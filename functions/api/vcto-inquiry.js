/**
 * POST /api/vcto-inquiry
 * 1. Validates inquiry fields
 * 2. Applies rate limiting and hashed security-event logging
 * 3. Sends a confirmation email to the submitter from contact@technicalriskarchitect.com
 * 4. Notifies contact@technicalriskarchitect.com of the new inquiry
 * 5. Redirects to the vCTO inquiry success page
 *
 * Env vars:
 *   ZEPTOMAIL_API_KEY   — ZeptoMail send token
 *   ZEPTOMAIL_API_HOST  — ZeptoMail API host, e.g. api.zeptomail.com
 *   SECURITY_EVENTS  — Cloudflare KV namespace used for rate limiting and hashed event logging
 */

import {
  HttpError,
  ensureMaxLength,
  isValidEmail,
  normalizeEmail,
  requireEmptyHoneypot,
} from '../_lib/auth.js';
import { sendZeptoEmail as sendTransactionalEmail } from '../_lib/mail.js';
import { assertNotRateLimited, recordSubmission } from '../_lib/security-events.js';
import { verifyTurnstileToken } from '../_lib/turnstile.js';

const VCTO_RATE_LIMIT = {
  perIp: { limit: 5, windowMs: 60 * 60 * 1000 },
  perEmail: { limit: 4, windowMs: 24 * 60 * 60 * 1000 },
};

export async function onRequestPost(context) {
  const { request, env } = context;
  try {
    const formData = await request.formData();
    const firstName = String(formData.get('first_name') || '').trim();
    const lastName = String(formData.get('last_name') || '').trim();
    const company = String(formData.get('company') || '').trim();
    const email = normalizeEmail(formData.get('email'));
    const phone = String(formData.get('phone') || '').trim();
    const engagementType = String(formData.get('engagement_type') || '').trim();
    const serviceFocus = String(formData.get('service_focus') || '').trim();
    const message = String(formData.get('message') || '').trim();
    const website = String(formData.get('company_website') || '');
    const turnstileToken = String(formData.get('cf-turnstile-response') || '');

    requireEmptyHoneypot(website);
    ensureMaxLength(firstName, 80, 'First name');
    ensureMaxLength(lastName, 80, 'Last name');
    ensureMaxLength(company, 120, 'Company');
    ensureMaxLength(email, 254, 'Email');
    ensureMaxLength(phone, 40, 'Phone');
    ensureMaxLength(message, 4000, 'Message');

    if (!firstName || !lastName || !company || !isValidEmail(email) || !isValidEngagementType(engagementType) || !isValidServiceFocus(serviceFocus) || !message) {
      throw new HttpError(400, 'Missing or invalid fields');
    }

    await verifyTurnstileToken(env, request, turnstileToken);
    await assertNotRateLimited(env, request, 'vcto_inquiry', email, VCTO_RATE_LIMIT);

    const entry = {
      firstName,
      lastName,
      company,
      email,
      phone,
      engagementType,
      serviceFocus,
      message,
      requestedAt: new Date().toISOString(),
    };

    await sendConfirmation(env, entry);
    await notifyContact(env, entry);
    await recordSubmission(env, request, 'vcto_inquiry', email);

    const origin = new URL(request.url).origin;
    return Response.redirect(`${origin}/vcto-inquiry-success`, 303);
  } catch (error) {
    if (error instanceof HttpError) {
      return new Response(error.message, { status: error.status });
    }

    console.error('vCTO inquiry error:', error);
    return new Response('Unable to submit inquiry', { status: 500 });
  }
}

async function sendConfirmation(env, entry) {
  const focusLabel = serviceFocusLabel(entry.serviceFocus);
  const engagementLabel = engagementTypeLabel(entry.engagementType);

  await sendTransactionalEmail(env, {
    to: [{ address: entry.email, name: `${entry.firstName} ${entry.lastName}`.trim() }],
    subject: 'vCTO inquiry received — Technical Risk Architect',
    htmlbody: `
      <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;padding:32px 24px;color:#1a1e2e;">
        <h2 style="margin:0 0 12px;color:#0d2b5e;">Thanks, ${escapeHtml(entry.firstName)}.</h2>
        <p style="margin:0 0 18px;line-height:1.6;color:#3d4460;">
          Your vCTO inquiry has been received through the secure portfolio engagement form.
        </p>
        <div style="border:1px solid #dde3ec;border-radius:10px;padding:18px 20px;background:#f9fbfd;">
          <p style="margin:0 0 8px;"><strong>Company:</strong> ${escapeHtml(entry.company)}</p>
          <p style="margin:0 0 8px;"><strong>Engagement:</strong> ${escapeHtml(engagementLabel)}</p>
          <p style="margin:0 0 8px;"><strong>Primary focus:</strong> ${escapeHtml(focusLabel)}</p>
          <p style="margin:0;"><strong>Submitted:</strong> ${escapeHtml(new Date(entry.requestedAt).toLocaleString('en-US', { timeZone: 'America/Chicago' }))} CT</p>
        </div>
        <p style="margin:18px 0 0;line-height:1.6;color:#3d4460;">
          A follow-up will come through contact@technicalriskarchitect.com rather than a personal email address.
        </p>
      </div>
    `,
  });
}

async function notifyContact(env, entry) {
  const focusLabel = serviceFocusLabel(entry.serviceFocus);
  const engagementLabel = engagementTypeLabel(entry.engagementType);
  const submitted = new Date(entry.requestedAt).toLocaleString('en-US', { timeZone: 'America/Chicago' });

  await sendTransactionalEmail(env, {
    to: [{ address: 'contact@technicalriskarchitect.com', name: 'Technical Risk Architect' }],
    subject: `New vCTO inquiry — ${entry.firstName} ${entry.lastName}`,
    htmlbody: `
      <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;padding:32px 24px;color:#1a1e2e;">
        <h2 style="margin:0 0 16px;color:#0d2b5e;">New vCTO inquiry received</h2>
        <table style="width:100%;border-collapse:collapse;">
          <tr><td style="padding:6px 0;color:#6b7494;width:160px;">Name</td><td style="padding:6px 0;font-weight:600;">${escapeHtml(entry.firstName)} ${escapeHtml(entry.lastName)}</td></tr>
          <tr><td style="padding:6px 0;color:#6b7494;">Company</td><td style="padding:6px 0;">${escapeHtml(entry.company)}</td></tr>
          <tr><td style="padding:6px 0;color:#6b7494;">Email</td><td style="padding:6px 0;">${escapeHtml(entry.email)}</td></tr>
          <tr><td style="padding:6px 0;color:#6b7494;">Phone</td><td style="padding:6px 0;">${escapeHtml(entry.phone || '—')}</td></tr>
          <tr><td style="padding:6px 0;color:#6b7494;">Engagement</td><td style="padding:6px 0;">${escapeHtml(engagementLabel)}</td></tr>
          <tr><td style="padding:6px 0;color:#6b7494;">Primary focus</td><td style="padding:6px 0;">${escapeHtml(focusLabel)}</td></tr>
          <tr><td style="padding:6px 0;color:#6b7494;">Submitted</td><td style="padding:6px 0;">${escapeHtml(submitted)} CT</td></tr>
        </table>
        <div style="margin-top:18px;padding:16px 18px;border:1px solid #dde3ec;border-radius:10px;background:#f9fbfd;line-height:1.6;">
          ${escapeHtml(entry.message)}
        </div>
      </div>
    `,
  });
}

function engagementTypeLabel(value) {
  switch (value) {
    case 'advisory':
      return 'Advisory retainer';
    case 'standard':
      return 'Standard retainer';
    case 'premium':
      return 'Premium retainer';
    case 'project':
      return 'Project-based engagement';
    case 'hourly':
      return 'Hourly advisory';
    default:
      return value;
  }
}

function serviceFocusLabel(value) {
  switch (value) {
    case 'compliance':
      return 'Regulatory compliance';
    case 'security':
      return 'Security architecture';
    case 'ai':
      return 'Sovereign AI';
    case 'hardware':
      return 'Specialized hardware';
    case 'transformation':
      return 'Transformation program';
    default:
      return value;
  }
}

function isValidEngagementType(value) {
  return ['advisory', 'standard', 'premium', 'project', 'hourly'].includes(value);
}

function isValidServiceFocus(value) {
  return ['compliance', 'security', 'ai', 'hardware', 'transformation'].includes(value);
}

function escapeHtml(value) {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}
