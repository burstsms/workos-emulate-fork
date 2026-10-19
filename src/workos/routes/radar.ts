import { type RouteContext, notFound, parseJsonBody, parseListParams } from '../../core/index.js';
import { getWorkOSStore } from '../store.js';
import { formatRadarAttempt, formatListResponse } from '../helpers.js';
import { STORE_KEY_PREFIXES } from '../constants.js';

/** Stored for the email-challenge fixture. The webhook payload does not include `code`. */
export interface RadarEmailChallengeRecord {
  id: string;
  user_id: string;
  email: string;
  code: string;
  type: 'email';
  expires_at: string;
  created_at: string;
  updated_at: string;
}

export function radarChallengeKey(id: string): string {
  return `${STORE_KEY_PREFIXES.radarChallenge}${id}`;
}

export function radarRoutes(ctx: RouteContext): void {
  const { app, store } = ctx;
  const ws = getWorkOSStore(store);

  // List attempts
  app.get('/radar/attempts', (c) => {
    const url = new URL(c.req.url);
    const params = parseListParams(url);
    const result = ws.radarAttempts.list({ ...params });
    return c.json(formatListResponse(result, formatRadarAttempt));
  });

  // Get attempt
  app.get('/radar/attempts/:id', (c) => {
    const attempt = ws.radarAttempts.get(c.req.param('id'));
    if (!attempt) throw notFound('RadarAttempt');
    return c.json(formatRadarAttempt(attempt));
  });

  // The fixture's code lives here. The challenge-created event does not carry it.
  app.get('/user_management/radar_challenges/:id', (c) => {
    const challenge = store.getData<RadarEmailChallengeRecord>(radarChallengeKey(c.req.param('id')));
    if (!challenge) throw notFound('Radar challenge');
    return c.json({
      object: 'radar_challenge',
      id: challenge.id,
      type: challenge.type,
      user_id: challenge.user_id,
      email: challenge.email,
      expires_at: challenge.expires_at,
      created_at: challenge.created_at,
      updated_at: challenge.updated_at,
      code: challenge.code,
    });
  });

  // Manage allow/deny lists
  app.post('/radar/lists/:type/:action', async (c) => {
    const listType = c.req.param('type');
    const action = c.req.param('action');
    const body = await parseJsonBody(c);
    const entries = (body.entries as string[]) ?? [];

    const key = `radar_${listType}_list`;
    const existing = store.getData<Set<string>>(key) ?? new Set<string>();

    if (action === 'add') {
      for (const entry of entries) existing.add(entry);
    } else if (action === 'remove') {
      for (const entry of entries) existing.delete(entry);
    }

    store.setData(key, existing);
    return c.json({ success: true });
  });
}
