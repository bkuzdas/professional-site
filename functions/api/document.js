import { HttpError, SESSION_COOKIE, isValidSessionCookie, parseCookie } from '../_lib/auth.js';
import { PROTECTED_DOCUMENTS } from '../_lib/protected-documents.generated.js';

export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const name = url.searchParams.get('name') || '';

  try {
    const cookieHeader = request.headers.get('Cookie') || '';
    const sessionCookie = parseCookie(cookieHeader, SESSION_COOKIE);
    const validSession = sessionCookie && await isValidSessionCookie(sessionCookie, env);

    if (!validSession) {
      return Response.redirect(new URL('/', request.url).toString(), 302);
    }

    const document = PROTECTED_DOCUMENTS[name];
    if (!document) {
      return new Response('Not found', { status: 404 });
    }

    return new Response(Uint8Array.from(atob(document.base64), char => char.charCodeAt(0)), {
      status: 200,
      headers: {
        'Content-Type': document.contentType,
        'Content-Disposition': `attachment; filename="${document.fileName}"`,
        'Cache-Control': 'private, no-store',
      },
    });
  } catch (error) {
    if (error instanceof HttpError) {
      return new Response(error.message, { status: error.status });
    }

    console.error('document download error:', error);
    return new Response('Unable to serve document', { status: 500 });
  }
}
