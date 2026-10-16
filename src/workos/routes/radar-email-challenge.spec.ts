import { describe, it, expect, beforeEach } from 'bun:test';
import { createServer, type ApiKeyMap, type Store } from '../../core/index.js';
import { workosPlugin } from '../index.js';
import { getWorkOSStore } from '../store.js';
import { hashPassword } from '../helpers.js';

const apiKeys: ApiKeyMap = { sk_test_auth: { environment: 'test' } };
const headers = { Authorization: 'Bearer sk_test_auth', 'Content-Type': 'application/json' };

function createTestApp() {
  return createServer(workosPlugin, { port: 0, baseUrl: 'http://localhost:0', apiKeys });
}

describe('radar email challenge', () => {
  let app: ReturnType<typeof createTestApp>['app'];
  let store: Store;

  beforeEach(() => {
    const server = createTestApp();
    app = server.app;
    store = server.store;
  });

  const req = (path: string, init?: RequestInit) => app.request(path, { headers, ...init });
  const json = (res: Response) => res.json() as Promise<Record<string, any>>;

  const authenticate = (body: unknown) =>
    app.request('/user_management/authenticate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

  function insertUser(email: string, metadata: Record<string, string>, emailVerified = true) {
    return getWorkOSStore(store).users.insert({
      object: 'user',
      name: null,
      email,
      first_name: null,
      last_name: null,
      email_verified: emailVerified,
      profile_picture_url: null,
      last_sign_in_at: null,
      external_id: null,
      metadata,
      locale: null,
      password_hash: hashPassword('secret'),
      impersonator: null,
    });
  }

  function joinOrg(userId: string) {
    const ws = getWorkOSStore(store);
    const org = ws.organizations.insert({
      object: 'organization',
      name: 'Account 1981',
      external_id: '1981',
      metadata: { account_id: '1981' },
      stripe_customer_id: null,
      allow_profiles_outside_organization: false,
      entitlements: [],
    });
    ws.organizationMemberships.insert({
      object: 'organization_membership',
      organization_id: org.id,
      user_id: userId,
      role: { slug: 'admin' },
      status: 'active',
      external_id: null,
      metadata: {},
    });
    return org;
  }

  it('challenges a flagged user and finishes sign-in with the code', async () => {
    const user = insertUser('radar@test.com', { radar_email_challenge: 'true' });
    const org = joinOrg(user.id);

    const challenged = await authenticate({
      grant_type: 'password',
      email: 'radar@test.com',
      password: 'secret',
    });
    expect(challenged.status).toBe(403);
    const body = await json(challenged);
    expect(body.code).toBe('radar_email_challenge');
    expect(body.pending_authentication_token).toBeString();
    expect(body.radar_challenge_id).toBeString();
    expect(body.user).toEqual({ email: 'radar@test.com' });
    expect(body).not.toHaveProperty('access_token');

    const events = getWorkOSStore(store)
      .events.all()
      .filter((event) => event.event === 'radar.challenge_created');
    expect(events).toHaveLength(1);
    expect(events[0].data).toEqual({
      type: 'email',
      radar_challenge_id: body.radar_challenge_id,
      user_id: user.id,
      email: 'radar@test.com',
    });

    const fetched = await json(await req(`/user_management/radar_challenges/${body.radar_challenge_id}`));
    expect(fetched).toMatchObject({
      object: 'radar_challenge',
      type: 'email',
      user_id: user.id,
      email: 'radar@test.com',
    });
    expect(fetched.code).toMatch(/^\d{6}$/);
    expect(body.code).not.toBe(fetched.code);
    expect(body.message).not.toContain(fetched.code);
    expect(events[0].data).not.toHaveProperty('code');

    const wrong = fetched.code === '000000' ? '000001' : '000000';
    const rejected = await authenticate({
      grant_type: 'urn:workos:oauth:grant-type:radar-email-challenge:code',
      code: wrong,
      radar_challenge_id: body.radar_challenge_id,
      pending_authentication_token: body.pending_authentication_token,
    });
    expect(rejected.status).toBe(400);
    expect(await json(rejected)).not.toHaveProperty('access_token');

    const stillThere = await json(await req(`/user_management/radar_challenges/${body.radar_challenge_id}`));
    expect(stillThere.code).toBe(fetched.code);

    const done = await authenticate({
      grant_type: 'urn:workos:oauth:grant-type:radar-email-challenge:code',
      code: fetched.code,
      radar_challenge_id: body.radar_challenge_id,
      pending_authentication_token: body.pending_authentication_token,
    });
    expect(done.status).toBe(200);
    const session = await json(done);
    expect(session.access_token).toBeString();
    expect(session.user.email).toBe('radar@test.com');
    expect(session.organization_id).toBe(org.id);
    expect(session.authentication_method).toBe('Password');

    expect((await req(`/user_management/radar_challenges/${body.radar_challenge_id}`)).status).toBe(404);
  });

  it('rejects a wrong password before issuing a challenge', async () => {
    insertUser('radar@test.com', { radar_email_challenge: 'true' });

    const res = await authenticate({
      grant_type: 'password',
      email: 'radar@test.com',
      password: 'wrong',
    });
    expect(res.status).toBe(400);
    expect((await json(res)).code).toBe('invalid_credentials');
    expect(
      getWorkOSStore(store)
        .events.all()
        .some((event) => event.event === 'radar.challenge_created'),
    ).toBe(false);
  });

  it('leaves an unflagged user on the password path', async () => {
    insertUser('plain@test.com', {});

    const res = await authenticate({
      grant_type: 'password',
      email: 'plain@test.com',
      password: 'secret',
    });
    expect(res.status).toBe(200);
    expect((await json(res)).authentication_method).toBe('Password');
    expect(
      getWorkOSStore(store)
        .events.all()
        .some((event) => event.event === 'radar.challenge_created'),
    ).toBe(false);
  });

  it('does not let organization selection spend the radar token', async () => {
    const user = insertUser('radar@test.com', { radar_email_challenge: 'true' });
    const org = joinOrg(user.id);
    const challenged = await json(
      await authenticate({ grant_type: 'password', email: 'radar@test.com', password: 'secret' }),
    );
    const skipped = await authenticate({
      grant_type: 'urn:workos:oauth:grant-type:organization-selection',
      pending_authentication_token: challenged.pending_authentication_token,
      organization_id: org.id,
    });
    expect(skipped.status).toBe(400);
    expect((await json(skipped)).code).toBe('invalid_pending_authentication_token');

    const fetched = await json(await req(`/user_management/radar_challenges/${challenged.radar_challenge_id}`));
    const done = await authenticate({
      grant_type: 'urn:workos:oauth:grant-type:radar-email-challenge:code',
      code: fetched.code,
      radar_challenge_id: challenged.radar_challenge_id,
      pending_authentication_token: challenged.pending_authentication_token,
    });
    expect(done.status).toBe(200);
  });

  it('asks for the authenticator after the radar code', async () => {
    const user = insertUser('radar@test.com', { radar_email_challenge: 'true' });
    joinOrg(user.id);
    getWorkOSStore(store).authFactors.insert({
      object: 'authentication_factor',
      user_id: user.id,
      type: 'totp',
      totp: { issuer: 'WorkOS', user: 'radar@test.com', secret: 'secret', uri: 'otpauth://totp' },
    });
    const challenged = await json(
      await authenticate({ grant_type: 'password', email: 'radar@test.com', password: 'secret' }),
    );
    const fetched = await json(await req(`/user_management/radar_challenges/${challenged.radar_challenge_id}`));
    const done = await authenticate({
      grant_type: 'urn:workos:oauth:grant-type:radar-email-challenge:code',
      code: fetched.code,
      radar_challenge_id: challenged.radar_challenge_id,
      pending_authentication_token: challenged.pending_authentication_token,
    });
    expect(done.status).toBe(403);
    const body = await json(done);
    expect(body.code).toBe('mfa_challenge');
    expect(body).not.toHaveProperty('access_token');
  });

  it('challenges radar after an unverified user proves the mailbox', async () => {
    const user = insertUser('radar@test.com', { radar_email_challenge: 'true' }, false);
    joinOrg(user.id);
    const gated = await json(
      await authenticate({ grant_type: 'password', email: 'radar@test.com', password: 'secret' }),
    );
    expect(gated.code).toBe('email_verification_required');
    const verification = getWorkOSStore(store).emailVerifications.findBy('user_id', user.id)[0];
    const verified = await authenticate({
      grant_type: 'urn:workos:oauth:grant-type:email-verification:code',
      code: verification.code,
      pending_authentication_token: gated.pending_authentication_token,
    });
    expect(verified.status).toBe(403);
    expect((await json(verified)).code).toBe('radar_email_challenge');
  });

  it('returns 404 for an unknown challenge', async () => {
    const res = await req('/user_management/radar_challenges/radar_challenge_missing');
    expect(res.status).toBe(404);
  });
});
