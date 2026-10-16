import type { Context } from 'hono';
import { generateId } from '../../core/id.js';
import {
  type RouteContext,
  type WidgetAuthContext,
  type WorkOSAppEnv,
  WorkOSApiError,
  notFound,
  parseJsonBody,
  widgetForbidden,
} from '../../core/index.js';
import type { WorkOSAuthenticationFactor, WorkOSUser } from '../entities.js';
import {
  TOTP_QR_CODE,
  emailsMatch,
  expiresIn,
  findUserByEmail,
  hashPassword,
  isEmailShaped,
  isExpired,
  newTotp,
  verifyPassword,
} from '../helpers.js';
import { getWorkOSStore } from '../store.js';

const PASSWORD_MINIMUM_LENGTH = 8;
/** Separate from the widget audience, so this token cannot authorize `/_widgets/*` on its own. */
const ELEVATED_AUDIENCE = 'widget_elevated';
const ELEVATED_TTL_SECONDS = 10 * 60;

interface PendingVerify {
  userId: string;
  expiresAt: string;
}

interface PendingEmailChange {
  email: string;
  expiresAt: string;
}

interface PendingTotp {
  userId: string;
  factorId: string;
  totp: WorkOSAuthenticationFactor['totp'];
  expiresAt: string;
}

/** UserProfile routes the profile widgets call. Passkeys and sessions stay unimplemented. */
export function userProfileRoutes(ctx: RouteContext): void {
  const { app, store, jwt } = ctx;
  const ws = getWorkOSStore(store);

  const verifyKey = (id: string) => `widget_profile:verify:${id}`;
  const emailKey = (userId: string) => `widget_profile:email:${userId}`;
  const totpKey = (id: string) => `widget_profile:totp:${id}`;

  const widgetAuth = (c: Context<WorkOSAppEnv>): WidgetAuthContext => {
    const auth = c.get('widgetAuth');
    if (!auth) throw widgetForbidden('Widget token is required');
    return auth;
  };

  const userFor = (c: Context<WorkOSAppEnv>): WorkOSUser => {
    const { userId } = widgetAuth(c);
    if (!userId) throw widgetForbidden('Widget token does not carry a user');
    const user = ws.users.get(userId);
    if (!user) throw notFound('User');
    return user;
  };

  const requireElevated = (c: Context<WorkOSAppEnv>, userId: string): void => {
    const header = c.req.header('x-elevated-access-token');
    if (!header) throw widgetForbidden('Elevated access token is required');
    let payload: { sub?: unknown; aud?: unknown };
    try {
      payload = jwt.verify(header);
    } catch {
      throw widgetForbidden('Elevated access token is invalid');
    }
    if (payload.aud !== ELEVATED_AUDIENCE || payload.sub !== userId) {
      throw widgetForbidden('Elevated access token is invalid');
    }
  };

  const issueElevated = (userId: string) => {
    const elevatedAccessToken = jwt.sign({ sub: userId, aud: ELEVATED_AUDIENCE }, { expiresIn: ELEVATED_TTL_SECONDS });
    return {
      elevatedAccessToken,
      expiresAt: new Date(Date.now() + ELEVATED_TTL_SECONDS * 1000).toISOString(),
    };
  };

  const profile = (user: WorkOSUser) => ({
    id: user.id,
    email: user.email,
    firstName: user.first_name,
    lastName: user.last_name,
    locale: user.locale,
    profilePictureUrl: user.profile_picture_url,
  });

  const requirePassword = (password: unknown): string => {
    if (typeof password !== 'string' || password.length < PASSWORD_MINIMUM_LENGTH) {
      // Held in a variable so the widget's minimum_length field survives structural typing.
      const tooShort = {
        code: 'password_too_short',
        message: `Password must be at least ${PASSWORD_MINIMUM_LENGTH} characters`,
        minimum_length: PASSWORD_MINIMUM_LENGTH,
      };
      throw new WorkOSApiError(
        400,
        `Password must be at least ${PASSWORD_MINIMUM_LENGTH} characters`,
        'password_strength_error',
        [tooShort],
      );
    }
    return password;
  };

  // Any non-empty code completes the step. The emulator does not check the value.
  const requireCode = (code: unknown): void => {
    if (typeof code !== 'string' || code.trim() === '') {
      throw new WorkOSApiError(400, 'Code is required', 'invalid_request');
    }
  };

  const takePending = <T extends { expiresAt: string; userId?: string }>(
    key: string,
    invalidMessage: string,
    userId?: string,
  ): T => {
    const pending = store.getData<T>(key);
    if (!pending || (userId !== undefined && pending.userId !== userId)) {
      throw new WorkOSApiError(400, invalidMessage, 'invalid_one_time_code');
    }
    if (isExpired(pending.expiresAt)) {
      store.deleteData(key);
      throw new WorkOSApiError(400, 'Verification code has expired', 'expired_code');
    }
    store.deleteData(key);
    return pending;
  };

  app.get('/_widgets/UserProfile/me', (c) => c.json(profile(userFor(c))));

  app.post('/_widgets/UserProfile/me', async (c) => {
    const user = userFor(c);
    const body = await parseJsonBody(c);
    const firstName = optionalString(body, 'firstName');
    const lastName = optionalString(body, 'lastName');
    const locale = optionalString(body, 'locale');
    const nextFirst = firstName === undefined ? user.first_name : firstName || null;
    const nextLast = lastName === undefined ? user.last_name : lastName || null;
    const name = [nextFirst, nextLast].filter(Boolean).join(' ') || null;
    const updated = ws.users.update(user.id, {
      first_name: nextFirst,
      last_name: nextLast,
      name,
      locale: locale === undefined ? user.locale : locale || null,
    });
    return c.json(profile(updated ?? user));
  });

  app.post('/_widgets/UserProfile/update-password', async (c) => {
    const user = userFor(c);
    const body = await parseJsonBody(c);
    if (!user.password_hash || !verifyPassword(String(body.currentPassword ?? ''), user.password_hash)) {
      throw new WorkOSApiError(400, 'Invalid credentials', 'invalid_credentials');
    }
    const next = requirePassword(body.newPassword);
    ws.users.update(user.id, { password_hash: hashPassword(next) });
    return c.json({ success: true }, 201);
  });

  app.post('/_widgets/UserProfile/send-verification', (c) => {
    const user = userFor(c);
    const id = generateId('authentication_challenge');
    store.setData(verifyKey(id), { userId: user.id, expiresAt: expiresIn(10) } satisfies PendingVerify);
    return c.json({ authenticationChallenge: id, type: 'EmailVerification' });
  });

  app.post('/_widgets/UserProfile/verify', async (c) => {
    const user = userFor(c);
    const body = await parseJsonBody(c);
    requireCode(body.code);
    const challengeId = body.authenticationChallengeId;
    if (typeof challengeId !== 'string' || !challengeId) {
      throw new WorkOSApiError(400, 'Verification code is invalid', 'invalid_one_time_code');
    }
    takePending<PendingVerify>(verifyKey(challengeId), 'Verification code is invalid', user.id);
    return c.json(issueElevated(user.id));
  });

  app.post('/_widgets/UserProfile/create-password', async (c) => {
    const user = userFor(c);
    requireElevated(c, user.id);
    if (user.password_hash) throw new WorkOSApiError(400, 'Password is already set', 'password_already_set');
    const body = await parseJsonBody(c);
    ws.users.update(user.id, { password_hash: hashPassword(requirePassword(body.password)) });
    return c.json({ success: true }, 201);
  });

  app.post('/_widgets/UserProfile/send-email-change', async (c) => {
    const user = userFor(c);
    requireElevated(c, user.id);
    const body = await parseJsonBody(c);
    const email = typeof body.newEmail === 'string' ? body.newEmail.trim() : '';
    if (!isEmailShaped(email)) throw new WorkOSApiError(400, 'Email address is invalid', 'invalid_request');
    if (emailsMatch(email, user.email)) {
      throw new WorkOSApiError(400, 'That is already the email on this user', 'invalid_request');
    }
    const taken = findUserByEmail(ws, email);
    if (taken && taken.id !== user.id) {
      throw new WorkOSApiError(409, 'A user with this email already exists', 'email_already_exists');
    }
    const expiresAt = expiresIn(10);
    store.setData(emailKey(user.id), { email, expiresAt } satisfies PendingEmailChange);
    return c.json({ expiresAt });
  });

  app.post('/_widgets/UserProfile/verify-email-change', async (c) => {
    const user = userFor(c);
    requireElevated(c, user.id);
    const body = await parseJsonBody(c);
    requireCode(body.code);
    const pending = takePending<PendingEmailChange>(emailKey(user.id), 'Email change is not pending');
    const taken = findUserByEmail(ws, pending.email);
    if (taken && taken.id !== user.id) {
      throw new WorkOSApiError(409, 'A user with this email already exists', 'email_already_exists');
    }
    const updated = ws.users.update(user.id, { email: pending.email, email_verified: true });
    return c.json({ user: profile(updated ?? user), ...issueElevated(user.id) });
  });

  app.post('/_widgets/UserProfile/create-totp-factor', (c) => {
    const user = userFor(c);
    requireElevated(c, user.id);
    const now = new Date().toISOString();
    const factorId = generateId('auth_factor');
    const challengeId = generateId('auth_challenge');
    const totp = newTotp('WorkOS Emulator', user.email);
    const expiresAt = expiresIn(10);
    // Held aside until verify, so authentication-information stays "not set up".
    store.setData(totpKey(challengeId), { userId: user.id, factorId, totp, expiresAt } satisfies PendingTotp);
    return c.json(
      {
        authenticationFactor: {
          object: 'authentication_factor',
          id: factorId,
          type: 'totp',
          user_id: user.id,
          totp: { ...totp, qr_code: TOTP_QR_CODE },
          created_at: now,
          updated_at: now,
        },
        authenticationChallenge: {
          object: 'authentication_challenge',
          id: challengeId,
          expires_at: expiresAt,
          authentication_factor_id: factorId,
          created_at: now,
          updated_at: now,
        },
      },
      201,
    );
  });

  app.post('/_widgets/UserProfile/verify-totp-factor', async (c) => {
    const user = userFor(c);
    requireElevated(c, user.id);
    const body = await parseJsonBody(c);
    requireCode(body.code);
    const challengeId = body.authenticationChallengeId;
    if (typeof challengeId !== 'string' || !challengeId) {
      throw new WorkOSApiError(400, 'Authenticator code is invalid', 'invalid_one_time_code');
    }
    const pending = takePending<PendingTotp>(totpKey(challengeId), 'Authenticator code is invalid', user.id);
    ws.authFactors.insert({
      object: 'authentication_factor',
      id: pending.factorId,
      user_id: user.id,
      type: 'totp',
      totp: pending.totp,
    });
    return c.json({ success: true });
  });

  app.delete('/_widgets/UserProfile/totp-factors', (c) => {
    const user = userFor(c);
    requireElevated(c, user.id);
    for (const factor of ws.authFactors.findBy('user_id', user.id)) {
      if (factor.type === 'totp') ws.authFactors.delete(factor.id);
    }
    store.deleteDataByPrefix('widget_profile:totp:', (value) => (value as PendingTotp).userId === user.id);
    return c.json({ success: true });
  });

  app.get('/_widgets/UserProfile/authentication-information', (c) => {
    const user = userFor(c);
    const totp = ws.authFactors.findBy('user_id', user.id).some((factor) => factor.type === 'totp');
    return c.json({
      data: {
        verificationMethods: {
          Password: {
            provider: 'Password',
            isSetUp: user.password_hash !== null,
            lastUsed: user.last_sign_in_at,
            isCurrentSession: user.password_hash !== null,
          },
          Mfa: {
            provider: 'MFA',
            isSetUp: totp,
            lastUsed: null,
          },
        },
        passwordSettings: {
          isPasswordNumberRequired: false,
          isPasswordPwnedRequired: false,
          isPasswordSymbolRequired: false,
          isPasswordUppercaseRequired: false,
          passwordMinimumLength: PASSWORD_MINIMUM_LENGTH,
          passwordMinimumStrength: 0,
        },
      },
    });
  });
}

function optionalString(body: Record<string, unknown>, key: string): string | undefined {
  if (!(key in body)) return undefined;
  const value = body[key];
  if (typeof value !== 'string') throw new WorkOSApiError(400, `${key} must be a string`, 'invalid_request');
  return value;
}
