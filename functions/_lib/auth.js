export class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
  }
}

export const SESSION_COOKIE = '__portfolio_session';
export const SESSION_TTL_SECONDS = 60 * 60 * 24;

export function assert(condition, status, message) {
  if (!condition) {
    throw new HttpError(status, message);
  }
}

export function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

export function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export function ensureMaxLength(value, maxLength, fieldName) {
  if (String(value || '').length > maxLength) {
    throw new HttpError(400, `${fieldName} is too long`);
  }
}

export function requireEmptyHoneypot(value) {
  if (String(value || '').trim()) {
    throw new HttpError(400, 'Invalid submission');
  }
}

export function parseCookie(header, name) {
  const match = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match ? match[1] : null;
}

export function getClientIp(request) {
  const forwarded = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || '';
  return forwarded.split(',')[0].trim() || 'unknown';
}

export function getSessionSecret(env) {
  const secret = String(env.SESSION_SECRET || '');
  assert(secret.length >= 32, 503, 'Server security configuration is incomplete');
  return secret;
}

export async function hmacSign(data, secret) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const buf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return toBase64Url(buf);
}

export async function sha256Base64Url(data) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(data));
  return toBase64Url(buf);
}

export async function signMagicLink(email, exp, nonce, env) {
  return hmacSign(`${email}|${exp}|${nonce}`, getSessionSecret(env));
}

export async function verifyMagicLink(email, exp, nonce, sig, env) {
  const expected = await signMagicLink(email, exp, nonce, env);
  return expected === sig;
}

export async function buildSessionCookie(email, env) {
  const exp = Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS;
  const sig = await hmacSign(`${email}|${exp}`, getSessionSecret(env));
  return `${encodeURIComponent(email)}|${exp}|${sig}`;
}

export async function isValidSessionCookie(cookieVal, env) {
  try {
    const parts = String(cookieVal || '').split('|');
    if (parts.length !== 3) return false;

    const [encodedEmail, exp, sig] = parts;
    if (Date.now() / 1000 > Number.parseInt(exp, 10)) return false;

    const email = decodeURIComponent(encodedEmail);
    const expected = await hmacSign(`${email}|${exp}`, getSessionSecret(env));
    return expected === sig;
  } catch {
    return false;
  }
}

function toBase64Url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}
