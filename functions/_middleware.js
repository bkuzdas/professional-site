/**
 * Global middleware for Cloudflare Pages Functions.
 * Protects /experience, /projects, /achievements, /resumes, /resume/*
 * by verifying a signed session cookie set by /api/verify.
 */

const SESSION_COOKIE  = '__portfolio_session';
const PROTECTED_PATHS = ['/experience', '/projects', '/achievements', '/resumes', '/resume'];

export async function onRequest(context) {
  const { request, env, next } = context;
  const url  = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '') || '/'; // strip trailing slash

  // Check if this path needs protection
  const isProtected = PROTECTED_PATHS.some(p => path === p || path.startsWith(p + '/'));
  if (!isProtected) return next(); // public — pass through

  // Parse session cookie
  const cookieHeader = request.headers.get('Cookie') || '';
  const cookieVal    = parseCookie(cookieHeader, SESSION_COOKIE);

  if (cookieVal && await isValidSession(cookieVal, env.SESSION_SECRET)) {
    return next(); // valid session — allow through
  }

  // No valid session → redirect to front door
  return Response.redirect(new URL('/', request.url).toString(), 302);
}

function parseCookie(header, name) {
  const match = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match ? match[1] : null;
}

async function isValidSession(cookieVal, secret) {
  try {
    const parts = cookieVal.split('|');
    if (parts.length !== 3) return false;
    const [encodedEmail, exp, sig] = parts;
    if (Date.now() / 1000 > parseInt(exp)) return false;
    const email   = decodeURIComponent(encodedEmail);
    const payload = `${email}|${exp}`;
    const expected = await hmacSign(payload, secret);
    return expected === sig;
  } catch {
    return false;
  }
}

async function hmacSign(data, secret) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const buf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
