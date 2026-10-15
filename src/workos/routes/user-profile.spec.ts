import { describe, it, expect, beforeEach } from 'bun:test';
import { createServer, type ApiKeyMap, type InsertInput } from '../../core/index.js';
import { workosPlugin } from '../index.js';
import { getWorkOSStore, type WorkOSStore } from '../store.js';
import type { WorkOSUser } from '../entities.js';

const apiKeys: ApiKeyMap = { sk_test_widgets: { environment: 'test' } };
const headers = { Authorization: 'Bearer sk_test_widgets', 'Content-Type': 'application/json' };

function createTestApp() {
  return createServer(workosPlugin, { port: 0, baseUrl: 'http://localhost:0', apiKeys: { ...apiKeys } });
}

const claims = (token: string) =>
  JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString()) as Record<string, unknown>;

const userFields = (overrides: Partial<WorkOSUser> = {}): InsertInput<WorkOSUser> => ({
  object: 'user',
  id: 'user_profile',
  email: 'notrial@test.com',
  name: null,
  first_name: 'Notrial',
  last_name: 'Test',
  email_verified: true,
  profile_picture_url: null,
  last_sign_in_at: '2026-10-14T00:00:00.000Z',
  external_id: null,
  metadata: {},
  locale: 'en-AU',
  password_hash: 'hashed',
  impersonator: null,
  ...overrides,
});

describe('UserProfile widget routes', () => {
  let server: ReturnType<typeof createTestApp>;
  let app: ReturnType<typeof createTestApp>['app'];
  let ws: WorkOSStore;

  beforeEach(() => {
    server = createTestApp();
    app = server.app;
    ws = getWorkOSStore(server.store);
  });

  const req = (path: string, init?: RequestInit) => app.request(path, { headers, ...init });
  const json = (res: Response) => res.json() as Promise<any>;

  const mintUserToken = async (userId = 'user_profile') => {
    const res = await req('/widgets/token', {
      method: 'POST',
      body: JSON.stringify({ user_id: userId }),
    });
    expect(res.status).toBe(200);
    return (await json(res)).token as string;
  };

  it('mints a user-only widget token with no organization', async () => {
    const token = await mintUserToken();
    const payload = claims(token);
    expect(payload.aud).toBe('widgets');
    expect(payload.sub).toBe('user_profile');
    expect(payload.org_id).toBeUndefined();
    expect(payload.permissions).toEqual([]);
    const now = Math.floor(Date.now() / 1000);
    expect(payload.exp).toBeGreaterThan(now);
  });

  it('still requires an organization when scopes are sent', async () => {
    const res = await req('/widgets/token', {
      method: 'POST',
      body: JSON.stringify({ user_id: 'user_profile', scopes: ['widgets:api-keys:manage'] }),
    });
    expect(res.status).toBe(422);
  });

  it('returns the signed-in user from GET /_widgets/UserProfile/me', async () => {
    ws.users.insert(userFields());
    const token = await mintUserToken();
    const res = await app.request('/_widgets/UserProfile/me', { headers: { Authorization: `Bearer ${token}` } });
    expect(res.status).toBe(200);
    expect(await json(res)).toEqual({
      id: 'user_profile',
      email: 'notrial@test.com',
      firstName: 'Notrial',
      lastName: 'Test',
      locale: 'en-AU',
      profilePictureUrl: null,
    });
  });

  it('answers 404 when the token names a user the store does not have', async () => {
    const token = await mintUserToken('user_missing');
    const res = await app.request('/_widgets/UserProfile/me', { headers: { Authorization: `Bearer ${token}` } });
    expect(res.status).toBe(404);
  });

  it('answers 403 when the widget token is missing', async () => {
    const res = await app.request('/_widgets/UserProfile/me');
    expect(res.status).toBe(403);
  });

  it('reports password and TOTP setup on authentication-information', async () => {
    ws.users.insert(userFields());
    ws.authFactors.insert({
      object: 'authentication_factor',
      user_id: 'user_profile',
      type: 'totp',
      totp: { issuer: 'WorkOS', user: 'notrial@test.com', secret: 'secret', uri: 'otpauth://totp' },
    });
    const token = await mintUserToken();
    const res = await app.request('/_widgets/UserProfile/authentication-information', {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
    const body = await json(res);
    expect(body.data.verificationMethods.Password).toEqual({
      provider: 'Password',
      isSetUp: true,
      lastUsed: '2026-10-14T00:00:00.000Z',
      isCurrentSession: true,
    });
    expect(body.data.verificationMethods.Mfa).toEqual({
      provider: 'MFA',
      isSetUp: true,
      lastUsed: null,
    });
    expect(body.data.passwordSettings.passwordMinimumLength).toBe(8);
  });

  it('reports password and TOTP as not set up when the user has neither', async () => {
    ws.users.insert(userFields({ password_hash: null, last_sign_in_at: null }));
    const token = await mintUserToken();
    const res = await app.request('/_widgets/UserProfile/authentication-information', {
      headers: { Authorization: `Bearer ${token}` },
    });
    const body = await json(res);
    expect(body.data.verificationMethods.Password.isSetUp).toBe(false);
    expect(body.data.verificationMethods.Password.isCurrentSession).toBe(false);
    expect(body.data.verificationMethods.Mfa.isSetUp).toBe(false);
  });
});
