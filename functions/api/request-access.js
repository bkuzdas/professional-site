import {
  HttpError,
  ensureMaxLength,
  isValidEmail,
  normalizeEmail,
  requireEmptyHoneypot,
  signMagicLink,
} from '../_lib/auth.js';
import { sendZeptoEmail } from '../_lib/mail.js';
import { assertNotRateLimited, recordMagicLinkIssued, recordSubmission } from '../_lib/security-events.js';
import { verifyTurnstileToken } from '../_lib/turnstile.js';

const TOKEN_TTL_SECONDS  = 900; // 15 minutes to click the link
const REQUEST_ACCESS_RATE_LIMIT = {
  perIp: { limit: 5, windowMs: 60 * 60 * 1000 },
  perEmail: { limit: 3, windowMs: 24 * 60 * 60 * 1000 },
};

export async function onRequestPost(context) {
  const { request, env } = context;
  try {
    const formData  = await request.formData();
    const firstName = String(formData.get('first_name') || '').trim();
    const lastName  = String(formData.get('last_name')  || '').trim();
    const phone     = String(formData.get('phone')      || '').trim();
    const email     = normalizeEmail(formData.get('email'));
    const website   = String(formData.get('website')    || '');
    const turnstileToken = String(formData.get('cf-turnstile-response') || '');

    requireEmptyHoneypot(website);
    ensureMaxLength(firstName, 80, 'First name');
    ensureMaxLength(lastName, 80, 'Last name');
    ensureMaxLength(phone, 40, 'Phone');
    ensureMaxLength(email, 254, 'Email');

    if (!firstName || !lastName || !isValidEmail(email)) {
      throw new HttpError(400, 'Missing or invalid fields');
    }

    await verifyTurnstileToken(env, request, turnstileToken);
    await assertNotRateLimited(env, request, 'request_access', email, REQUEST_ACCESS_RATE_LIMIT);

    const timestamp  = new Date().toISOString();
    const entry      = { firstName, lastName, phone, email, requestedAt: timestamp };
    const origin     = new URL(request.url).origin;
    const exp        = Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS;
    const nonce      = crypto.randomUUID();
    const sig        = await signMagicLink(email, String(exp), nonce, env);
    const magicLink  = `${origin}/api/verify?email=${encodeURIComponent(email)}&exp=${exp}&nonce=${encodeURIComponent(nonce)}&sig=${encodeURIComponent(sig)}`;

    await sendMagicLink(env, entry, magicLink);
    await recordSubmission(env, request, 'request_access', email);
    await recordMagicLinkIssued(env, request, email, nonce);

    notifyContact(env, entry).catch(err => console.error('Access request notify error:', err));

    return Response.redirect(`${origin}/request-access-success`, 303);
  } catch (error) {
    if (error instanceof HttpError) {
      return new Response(error.message, { status: error.status });
    }

    console.error('request-access error:', error);
    return new Response('Unable to process request access', { status: 500 });
  }
}

async function sendMagicLink(env, entry, magicLink) {
  await sendZeptoEmail(env, {
    to: [{ address: entry.email, name: `${entry.firstName} ${entry.lastName}`.trim() }],
    subject: 'Your verified guest access link — Brian Kuzdas',
    htmlbody: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:2rem;">
        <h2 style="color:#0a0f1e;margin:0 0 0.5rem;">Hi ${escapeHtml(entry.firstName)},</h2>
        <p style="color:#444;line-height:1.6;">
          Click the button below to access Brian's professional portfolio. This link expires in
          <strong>15 minutes</strong> and can only be used once.
        </p>
        <a href="${magicLink}"
           style="display:inline-block;margin:1.5rem 0;background:#d4af37;color:#0a0f1e;
                  padding:0.85rem 2rem;border-radius:6px;font-weight:700;text-decoration:none;
                  font-size:1rem;">
          Enter Portfolio →
        </a>
        <p style="color:#888;font-size:0.82rem;line-height:1.5;">
          If you didn't request this, you can safely ignore this email.
        </p>
      </div>
    `,
  });
}

async function notifyContact(env, entry) {
  const { firstName, lastName, phone, email, requestedAt } = entry;
  const date = new Date(requestedAt).toLocaleString('en-US', { timeZone: 'America/Chicago' });

  await sendZeptoEmail(env, {
    to: [{ address: 'contact@technicalriskarchitect.com', name: 'Technical Risk Architect' }],
    subject: `Portfolio Access Request — ${firstName} ${lastName}`,
    htmlbody: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:2rem;">
        <h2 style="margin:0 0 1rem;color:#0a0f1e;">New Portfolio Access Request</h2>
        <table style="width:100%;border-collapse:collapse;">
          <tr><td style="padding:0.5rem 0;color:#666;width:130px;">Name</td>
              <td style="padding:0.5rem 0;font-weight:600;">${escapeHtml(firstName)} ${escapeHtml(lastName)}</td></tr>
          <tr><td style="padding:0.5rem 0;color:#666;">Email</td>
              <td style="padding:0.5rem 0;font-weight:600;">${escapeHtml(email)}</td></tr>
          <tr><td style="padding:0.5rem 0;color:#666;">Phone</td>
              <td style="padding:0.5rem 0;">${escapeHtml(phone || '—')}</td></tr>
          <tr><td style="padding:0.5rem 0;color:#666;">Submitted</td>
              <td style="padding:0.5rem 0;">${escapeHtml(date)} CT</td></tr>
        </table>
        <p style="margin-top:1.5rem;color:#666;font-size:0.85rem;">
          A one-time guest access link was sent automatically.
        </p>
      </div>
    `,
  });
}

function escapeHtml(value) {
  return String(value || '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}
