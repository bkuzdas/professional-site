/**
 * Global middleware for Cloudflare Pages Functions.
 * Protects /experience, /projects, /achievements, /resumes, /resume/*
 * by verifying a signed session cookie set by /api/verify.
 */

import { SESSION_COOKIE, HttpError, isValidSessionCookie, parseCookie } from './_lib/auth.js';

const PROTECTED_PATHS = ['/experience', '/projects', '/achievements', '/resumes', '/resume', '/references', '/vcto'];

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

  try {
    if (cookieVal && await isValidSessionCookie(cookieVal, env)) {
      return next(); // valid session — allow through
    }
  } catch (error) {
    if (error instanceof HttpError) {
      return new Response(error.message, { status: error.status });
    }
    return new Response('Portfolio security configuration error', { status: 503 });
  }

  // No valid session → redirect to front door
  return Response.redirect(new URL('/', request.url).toString(), 302);
}
