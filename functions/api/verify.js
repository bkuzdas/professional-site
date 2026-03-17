/**
 * GET /api/verify?email=...&exp=...&sig=...
 * Verifies a magic link token, sets a 24hr session cookie, redirects to portfolio.
 */

const SESSION_COOKIE = '__portfolio_session';
const SESSION_TTL    = 60 * 60 * 24; // 24 hours in seconds

export async function onRequestGet(context) {
  const { request, env } = context;
  const url    = new URL(request.url);
  const email  = url.searchParams.get('email') || '';
  const exp    = url.searchParams.get('exp')   || '';
  const sig    = url.searchParams.get('sig')   || '';
  const origin = url.origin;

  // Check expiry
  if (!email || !exp || !sig || Date.now() / 1000 > parseInt(exp)) {
    return Response.redirect(`${origin}/verify-error?reason=expired`, 303);
  }

  // Verify HMAC signature
  const payload  = `${email}|${exp}`;
  const expected = await hmacSign(payload, env.SESSION_SECRET);
  if (expected !== sig) {
    return Response.redirect(`${origin}/verify-error?reason=invalid`, 303);
  }

  // Issue 24hr session cookie
  const sessionExp  = Math.floor(Date.now() / 1000) + SESSION_TTL;
  const sessionData = `${email}|${sessionExp}`;
  const sessionSig  = await hmacSign(sessionData, env.SESSION_SECRET);
  const cookieVal   = `${encodeURIComponent(email)}|${sessionExp}|${sessionSig}`;

  return new Response(null, {
    status: 303,
    headers: {
      'Location': '/experience',
      'Set-Cookie': `${SESSION_COOKIE}=${cookieVal}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL}`,
    },
  });
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
