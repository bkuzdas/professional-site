/**
 * GET /api/verify?email=...&exp=...&sig=...
 * Verifies a magic link token, sets a 24hr session cookie, redirects to portfolio.
 */

import { SESSION_COOKIE, SESSION_TTL_SECONDS, buildSessionCookie, verifyMagicLink, HttpError, isValidEmail, normalizeEmail } from '../_lib/auth.js';
import { assertMagicLinkUnused, markMagicLinkUsed } from '../_lib/security-events.js';

export async function onRequestGet(context) {
  const { request, env } = context;
  const url    = new URL(request.url);
  const email  = normalizeEmail(url.searchParams.get('email'));
  const exp    = url.searchParams.get('exp')   || '';
  const nonce  = url.searchParams.get('nonce') || '';
  const sig    = url.searchParams.get('sig')   || '';
  const origin = url.origin;

  try {
    if (!isValidEmail(email) || !exp || !nonce || !sig) {
      return Response.redirect(`${origin}/verify-error?reason=invalid`, 303);
    }

    if (Date.now() / 1000 > Number.parseInt(exp, 10)) {
      return Response.redirect(`${origin}/verify-error?reason=expired`, 303);
    }

    const isValid = await verifyMagicLink(email, exp, nonce, sig, env);
    if (!isValid) {
      return Response.redirect(`${origin}/verify-error?reason=invalid`, 303);
    }

    await assertMagicLinkUnused(env, nonce);
    await markMagicLinkUsed(env, request, email, nonce);

    const cookieVal = await buildSessionCookie(email, env);

    return new Response(null, {
      status: 303,
      headers: {
        Location: '/experience',
        'Set-Cookie': `${SESSION_COOKIE}=${cookieVal}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL_SECONDS}`,
      },
    });
  } catch (error) {
    if (error instanceof HttpError && error.status === 409) {
      return Response.redirect(`${origin}/verify-error?reason=invalid`, 303);
    }

    if (error instanceof HttpError) {
      return new Response(error.message, { status: error.status });
    }

    console.error('verify error:', error);
    return new Response('Unable to verify access link', { status: 500 });
  }
}
