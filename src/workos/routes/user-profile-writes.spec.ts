import { describe, it, expect, beforeEach } from 'bun:test';
import { createServer, type ApiKeyMap, type InsertInput } from '../../core/index.js';
import { workosPlugin } from '../index.js';
import { getWorkOSStore, type WorkOSStore } from '../store.js';
import type { WorkOSUser } from '../entities.js';
import { hashPassword, verifyPassword } from '../helpers.js';

const apiKeys: ApiKeyMap = { sk_test_widgets: { environment: 'test' } };
const headers = { Authorization: 'Bearer sk_test_widgets', 'Content-Type': 'application/json' };

function createTestApp() {
  return createServer(workosPlugin, { port: 0, baseUrl: 'http://localhost:0', apiKeys: { ...apiKeys } });
}

const userFields = (overrides: Partial<WorkOSUser> = {}): InsertInput<WorkOSUser> => ({
  object: 'user',
  id: 'user_profile',
  email: 'notrial@test.com',
  name: 'Notrial Test',
  first_name: 'Notrial',
  last_name: 'Test',
  email_verified: true,
  profile_picture_url: null,
  last_sign_in_at: '2026-10-14T00:00:00.000Z',
  external_id: null,
  metadata: {},
  locale: 'en-AU',
  password_hash: hashPassword('current-password'),
  impersonator: null,
  ...overrides,
});

describe('UserProfile widget writes', () => {
  let server: ReturnType<typeof createTestApp>;
  let app: ReturnType<typeof createTestApp>['app'];
  let ws: WorkOSStore;

  beforeEach(() => {
    server = createTestApp();
    app = server.app;
    ws = getWorkOSStore(server.store);
  });

  const json = (res: Response) => res.json() as Promise<any>;

  const mintUserToken = async (userId = 'user_profile') => {
    const res = await app.request('/widgets/token', {
      method: 'POST',
      headers,
      body: JSON.stringify({ user_id: userId }),
    });
    expect(res.status).toBe(200);
    return (await json(res)).token as string;
  };

  const widget = (token: string, elevated?: string) => ({
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json',
    ...(elevated ? { 'x-elevated-access-token': elevated } : {}),
  });

  const post = (path: string, token: string, body?: unknown, elevated?: string) =>
    app.request(path, {
      method: 'POST',
      headers: widget(token, elevated),
      body: body === undefined ? undefined : JSON.stringify(body),
    });

  const elevate = async (token: string) => {
    const sent = await post('/_widgets/UserProfile/send-verification', token);
    expect(sent.status).toBe(200);
    const challenge = (await json(sent)).authenticationChallenge as string;
    const verified = await post('/_widgets/UserProfile/verify', token, {
      code: '000000',
      authenticationChallengeId: challenge,
    });
    expect(verified.status).toBe(200);
    return (await json(verified)).elevatedAccessToken as string;
  };

  it('updates the display name', async () => {
    ws.users.insert(userFields());
    const token = await mintUserToken();
    const res = await post('/_widgets/UserProfile/me', token, { firstName: 'Ada', lastName: 'Lovelace' });
    expect(res.status).toBe(200);
    expect(await json(res)).toMatchObject({ firstName: 'Ada', lastName: 'Lovelace', email: 'notrial@test.com' });
    expect(ws.users.get('user_profile')?.name).toBe('Ada Lovelace');
  });

  it('rejects a password change with the wrong current password', async () => {
    ws.users.insert(userFields());
    const token = await mintUserToken();
    const res = await post('/_widgets/UserProfile/update-password', token, {
      currentPassword: 'nope',
      newPassword: 'replacement-password',
    });
    expect(res.status).toBe(400);
    const body = await json(res);
    expect(body.code).toBe('invalid_credentials');
    expect(body.message).toBe('Invalid credentials');
    expect(verifyPassword('current-password', ws.users.get('user_profile')!.password_hash!)).toBe(true);
  });

  it('changes the password without an elevated token', async () => {
    ws.users.insert(userFields());
    const token = await mintUserToken();
    const res = await post('/_widgets/UserProfile/update-password', token, {
      currentPassword: 'current-password',
      newPassword: 'replacement-password',
    });
    expect(res.status).toBe(201);
    expect(verifyPassword('replacement-password', ws.users.get('user_profile')!.password_hash!)).toBe(true);
  });

  it('rejects a new password shorter than 8 characters', async () => {
    ws.users.insert(userFields());
    const token = await mintUserToken();
    const res = await post('/_widgets/UserProfile/update-password', token, {
      currentPassword: 'current-password',
      newPassword: 'short',
    });
    expect(res.status).toBe(400);
    const body = await json(res);
    expect(body.code).toBe('password_strength_error');
    expect(body.errors).toEqual([
      {
        code: 'password_too_short',
        message: 'Password must be at least 8 characters',
        minimum_length: 8,
      },
    ]);
  });

  it('sets a password only after the verification step', async () => {
    ws.users.insert(userFields({ password_hash: null }));
    const token = await mintUserToken();
    const blocked = await post('/_widgets/UserProfile/create-password', token, { password: 'replacement-password' });
    expect(blocked.status).toBe(403);
    expect(ws.users.get('user_profile')?.password_hash).toBeNull();

    const elevated = await elevate(token);
    const res = await post(
      '/_widgets/UserProfile/create-password',
      token,
      { password: 'replacement-password' },
      elevated,
    );
    expect(res.status).toBe(201);
    expect(verifyPassword('replacement-password', ws.users.get('user_profile')!.password_hash!)).toBe(true);
  });

  it('rejects creating a password when one is already set', async () => {
    ws.users.insert(userFields());
    const token = await mintUserToken();
    const elevated = await elevate(token);
    const res = await post(
      '/_widgets/UserProfile/create-password',
      token,
      { password: 'replacement-password' },
      elevated,
    );
    expect(res.status).toBe(400);
    expect((await json(res)).code).toBe('password_already_set');
  });

  it('changes the email only after the second code', async () => {
    ws.users.insert(userFields());
    const token = await mintUserToken();
    const elevated = await elevate(token);
    const blocked = await post('/_widgets/UserProfile/verify-email-change', token, { code: '111111' }, elevated);
    expect(blocked.status).toBe(400);
    expect(ws.users.get('user_profile')?.email).toBe('notrial@test.com');

    const sent = await post('/_widgets/UserProfile/send-email-change', token, { newEmail: 'ada@test.com' }, elevated);
    expect(sent.status).toBe(200);
    const res = await post('/_widgets/UserProfile/verify-email-change', token, { code: '222222' }, elevated);
    expect(res.status).toBe(200);
    expect((await json(res)).user.email).toBe('ada@test.com');
    expect(ws.users.get('user_profile')?.email).toBe('ada@test.com');
  });

  it('rejects an email change without the elevated token and a duplicate address', async () => {
    ws.users.insert(userFields());
    ws.users.insert(userFields({ id: 'user_other', email: 'ada@test.com' }));
    const token = await mintUserToken();
    const missing = await post('/_widgets/UserProfile/send-email-change', token, { newEmail: 'fresh@test.com' });
    expect(missing.status).toBe(403);

    const elevated = await elevate(token);
    const duplicate = await post(
      '/_widgets/UserProfile/send-email-change',
      token,
      { newEmail: 'ada@test.com' },
      elevated,
    );
    expect(duplicate.status).toBe(409);
  });

  it('enrolls an authenticator only after verify, and any code is accepted', async () => {
    ws.users.insert(userFields());
    const token = await mintUserToken();
    const elevated = await elevate(token);
    const created = await post('/_widgets/UserProfile/create-totp-factor', token, undefined, elevated);
    expect(created.status).toBe(201);
    const infoBefore = await app.request('/_widgets/UserProfile/authentication-information', {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect((await json(infoBefore)).data.verificationMethods.Mfa.isSetUp).toBe(false);

    const challenge = (await json(created)).authenticationChallenge.id as string;
    const verified = await post(
      '/_widgets/UserProfile/verify-totp-factor',
      token,
      { code: '999999', authenticationChallengeId: challenge },
      elevated,
    );
    expect(verified.status).toBe(200);
    const infoAfter = await app.request('/_widgets/UserProfile/authentication-information', {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect((await json(infoAfter)).data.verificationMethods.Mfa.isSetUp).toBe(true);
  });

  it('removes authenticator factors only with an elevated token', async () => {
    ws.users.insert(userFields());
    ws.authFactors.insert({
      object: 'authentication_factor',
      user_id: 'user_profile',
      type: 'totp',
      totp: { issuer: 'WorkOS', user: 'notrial@test.com', secret: 'secret', uri: 'otpauth://totp' },
    });
    const token = await mintUserToken();
    const blocked = await app.request('/_widgets/UserProfile/totp-factors', {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(blocked.status).toBe(403);
    expect(ws.authFactors.findBy('user_id', 'user_profile')).toHaveLength(1);

    const elevated = await elevate(token);
    const res = await app.request('/_widgets/UserProfile/totp-factors', {
      method: 'DELETE',
      headers: widget(token, elevated),
    });
    expect(res.status).toBe(200);
    expect(ws.authFactors.findBy('user_id', 'user_profile')).toHaveLength(0);
  });
});
