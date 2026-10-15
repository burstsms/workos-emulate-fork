import type { Context } from 'hono';
import {
  type RouteContext,
  type WidgetAuthContext,
  type WorkOSAppEnv,
  notFound,
  widgetForbidden,
} from '../../core/index.js';
import type { WorkOSUser } from '../entities.js';
import { getWorkOSStore } from '../store.js';

/** Read-only UserProfile and UserSecurity routes. Mutations stay unimplemented. */
export function userProfileRoutes(ctx: RouteContext): void {
  const { app, store } = ctx;
  const ws = getWorkOSStore(store);

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

  app.get('/_widgets/UserProfile/me', (c) => {
    const user = userFor(c);
    return c.json({
      id: user.id,
      email: user.email,
      firstName: user.first_name,
      lastName: user.last_name,
      locale: user.locale,
      profilePictureUrl: user.profile_picture_url,
    });
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
          passwordMinimumLength: 8,
          passwordMinimumStrength: 0,
        },
      },
    });
  });
}
