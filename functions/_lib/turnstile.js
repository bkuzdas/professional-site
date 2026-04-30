import { HttpError, assert, getClientIp } from './auth.js';

export async function verifyTurnstileToken(env, request, token) {
  assert(env.TURNSTILE_SECRET_KEY, 503, 'Turnstile is not configured');

  if (!String(token || '').trim()) {
    throw new HttpError(400, 'Please complete the security check');
  }

  const body = new URLSearchParams({
    secret: env.TURNSTILE_SECRET_KEY,
    response: String(token),
    remoteip: getClientIp(request),
  });

  const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body,
  });

  if (!response.ok) {
    throw new HttpError(502, 'Security verification failed');
  }

  const result = await response.json();
  if (!result.success) {
    throw new HttpError(400, 'Please complete the security check');
  }
}
