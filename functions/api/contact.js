import {
  HttpError,
  ensureMaxLength,
  isValidEmail,
  normalizeEmail,
  requireEmptyHoneypot,
} from '../_lib/auth.js';
import { sendZeptoEmail } from '../_lib/mail.js';

const ALLOWED_SOURCES = new Set([
  'professional-site',
  'technical-risk-architect-site',
  'brianboruma-com',
  'irish-heritage-planners',
]);

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    assertValidProxyToken(request, env);
    const payload = await readPayload(request);
    const source = String(payload.source || '').trim();
    const name = String(payload.name || '').trim();
    const email = normalizeEmail(payload.email);
    const organization = String(payload.organization || '').trim();
    const phone = String(payload.phone || '').trim();
    const subject = String(payload.subject || '').trim();
    const interest = String(payload.interest || '').trim();
    const message = String(payload.message || '').trim();
    const website = String(payload.website || '');

    requireEmptyHoneypot(website);
    ensureMaxLength(source, 80, 'Source');
    ensureMaxLength(name, 120, 'Name');
    ensureMaxLength(email, 254, 'Email');
    ensureMaxLength(organization, 120, 'Organization');
    ensureMaxLength(phone, 40, 'Phone');
    ensureMaxLength(subject, 160, 'Subject');
    ensureMaxLength(interest, 120, 'Interest');
    ensureMaxLength(message, 4000, 'Message');

    if (!ALLOWED_SOURCES.has(source) || !name || !isValidEmail(email) || !message) {
      throw new HttpError(400, 'Missing or invalid fields');
    }

    const submittedAt = new Date().toLocaleString('en-US', { timeZone: 'America/Chicago' });
    const sourceLabel = sourceName(source);

    await sendZeptoEmail(env, {
      to: [{ address: 'contact@technicalriskarchitect.com', name: 'Technical Risk Architect' }],
      subject: `${sourceLabel} contact form — ${name}`,
      htmlbody: `
        <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;padding:32px 24px;color:#1a1e2e;">
          <h2 style="margin:0 0 16px;color:#0d2b5e;">New website contact submission</h2>
          <table style="width:100%;border-collapse:collapse;">
            <tr><td style="padding:6px 0;color:#6b7494;width:160px;">Site</td><td style="padding:6px 0;font-weight:600;">${escapeHtml(sourceLabel)}</td></tr>
            <tr><td style="padding:6px 0;color:#6b7494;">Name</td><td style="padding:6px 0;">${escapeHtml(name)}</td></tr>
            <tr><td style="padding:6px 0;color:#6b7494;">Email</td><td style="padding:6px 0;">${escapeHtml(email)}</td></tr>
            <tr><td style="padding:6px 0;color:#6b7494;">Organization</td><td style="padding:6px 0;">${escapeHtml(organization || '—')}</td></tr>
            <tr><td style="padding:6px 0;color:#6b7494;">Phone</td><td style="padding:6px 0;">${escapeHtml(phone || '—')}</td></tr>
            <tr><td style="padding:6px 0;color:#6b7494;">Topic</td><td style="padding:6px 0;">${escapeHtml(subject || interest || 'General enquiry')}</td></tr>
            <tr><td style="padding:6px 0;color:#6b7494;">Submitted</td><td style="padding:6px 0;">${escapeHtml(submittedAt)} CT</td></tr>
          </table>
          <div style="margin-top:18px;padding:16px 18px;border:1px solid #dde3ec;border-radius:10px;background:#f9fbfd;line-height:1.6;white-space:pre-wrap;">
            ${escapeHtml(message)}
          </div>
        </div>
      `,
    });

    return jsonResponse({ success: true, message: successMessage(source) }, 200);
  } catch (error) {
    if (error instanceof HttpError) {
      return jsonResponse({ success: false, error: error.message }, error.status);
    }

    console.error('contact endpoint error:', error);
    return jsonResponse({ success: false, error: 'Unable to send message right now.' }, 500);
  }
}

async function readPayload(request) {
  const contentType = request.headers.get('content-type') || '';

  if (contentType.includes('application/json')) {
    return request.json();
  }

  if (contentType.includes('form-urlencoded') || contentType.includes('multipart/form-data')) {
    const formData = await request.formData();
    return Object.fromEntries(formData.entries());
  }

  throw new HttpError(415, 'Unsupported submission type');
}

function successMessage(source) {
  switch (source) {
    case 'technical-risk-architect-site':
      return "Message sent. We'll be in touch within one business day.";
    case 'irish-heritage-planners':
      return "Enquiry sent. You'll hear back shortly with next-step options.";
    default:
      return "Message sent. You'll hear back soon.";
  }
}

function sourceName(source) {
  switch (source) {
    case 'technical-risk-architect-site':
      return 'technicalriskarchitect.com';
    case 'brianboruma-com':
      return 'brianboruma.com';
    case 'irish-heritage-planners':
      return 'irishheritageplanners.com';
    default:
      return 'professional.brianboruma.com';
  }
}

function jsonResponse(body, status) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
    },
  });
}

function assertValidProxyToken(request, env) {
  const configured = String(env.CONTACT_PROXY_TOKEN || '');
  const provided = request.headers.get('X-Contact-Proxy-Token') || '';

  if (configured.length < 32 || provided !== configured) {
    throw new HttpError(403, 'Forbidden');
  }
}

function escapeHtml(value) {
  return String(value || '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}
