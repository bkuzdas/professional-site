/**
 * POST /api/request-access
 * 1. Validates form fields
 * 2. Generates a time-limited HMAC-signed magic link
 * 3. Sends magic link to user via Resend
 * 4. Logs submission to GitHub Gist
 * 5. Emails Brian a notification
 * 6. Redirects to "check your email" page
 *
 * Env vars:
 *   SESSION_SECRET  — HMAC secret for signing tokens
 *   RESEND_API_KEY  — Resend.com API key
 *   GITHUB_TOKEN    — GitHub PAT with gist scope
 *   GITHUB_GIST_ID  — Private gist ID (auto-created if blank)
 */

const PROTECTED_REDIRECT = '/experience';
const TOKEN_TTL_SECONDS  = 900; // 15 minutes to click the link

export async function onRequestPost(context) {
  const { request, env } = context;

  const formData  = await request.formData();
  const firstName = (formData.get('first_name') || '').trim();
  const lastName  = (formData.get('last_name')  || '').trim();
  const phone     = (formData.get('phone')      || '').trim();
  const email     = (formData.get('email')      || '').trim().toLowerCase();

  if (!firstName || !lastName || !email || !email.includes('@')) {
    return new Response('Missing or invalid fields', { status: 400 });
  }

  const timestamp  = new Date().toISOString();
  const entry      = { firstName, lastName, phone, email, requestedAt: timestamp };
  const origin     = new URL(request.url).origin;

  // Build magic link
  const exp   = Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS;
  const payload = `${email}|${exp}`;
  const sig   = await hmacSign(payload, env.SESSION_SECRET);
  const magicLink = `${origin}/api/verify?email=${encodeURIComponent(email)}&exp=${exp}&sig=${encodeURIComponent(sig)}`;

  // 1 — Send magic link to user
  await sendMagicLink(env, entry, magicLink);

  // 2 — Log to GitHub Gist (non-blocking)
  logToGist(env, entry).catch(err => console.error('Gist log error:', err));

  // 3 — Notify Brian (non-blocking)
  notifyBrian(env, entry).catch(err => console.error('Email notify error:', err));

  // 4 — Redirect to "check your email" page
  return Response.redirect(`${origin}/request-access-success`, 303);
}

// ── Crypto helpers ──────────────────────────────────────────────────────────

async function hmacSign(data, secret) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const buf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// ── Email: magic link to user ────────────────────────────────────────────────

async function sendMagicLink(env, entry, magicLink) {
  const { RESEND_API_KEY } = env;
  if (!RESEND_API_KEY) throw new Error('RESEND_API_KEY not set');

  await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: 'Brian Kuzdas Portfolio <portfolio@brianboruma.com>',
      to: [entry.email],
      subject: 'Your access link — Brian Kuzdas Portfolio',
      html: `
        <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:2rem;">
          <h2 style="color:#0a0f1e;margin:0 0 0.5rem;">Hi ${entry.firstName},</h2>
          <p style="color:#444;line-height:1.6;">
            Click the button below to access Brian's private professional portfolio.
            This link expires in <strong>15 minutes</strong>.
          </p>
          <a href="${magicLink}"
             style="display:inline-block;margin:1.5rem 0;background:#d4af37;color:#0a0f1e;
                    padding:0.85rem 2rem;border-radius:6px;font-weight:700;text-decoration:none;
                    font-size:1rem;">
            Enter Portfolio →
          </a>
          <p style="color:#888;font-size:0.82rem;line-height:1.5;">
            If you didn't request this, you can safely ignore this email.<br>
            This link can only be used once and expires in 15 minutes.
          </p>
        </div>
      `,
    }),
  });
}

// ── Email: notify Brian ──────────────────────────────────────────────────────

async function notifyBrian(env, entry) {
  const { RESEND_API_KEY } = env;
  if (!RESEND_API_KEY) return;

  const { firstName, lastName, phone, email, requestedAt } = entry;
  const date = new Date(requestedAt).toLocaleString('en-US', { timeZone: 'America/Chicago' });

  await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: 'Portfolio Access <portfolio@brianboruma.com>',
      to: ['brian.kuzdas@gmail.com'],
      subject: `Portfolio Access Request — ${firstName} ${lastName}`,
      html: `
        <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:2rem;">
          <h2 style="margin:0 0 1rem;color:#0a0f1e;">New Portfolio Access Request</h2>
          <table style="width:100%;border-collapse:collapse;">
            <tr><td style="padding:0.5rem 0;color:#666;width:130px;">Name</td>
                <td style="padding:0.5rem 0;font-weight:600;">${firstName} ${lastName}</td></tr>
            <tr><td style="padding:0.5rem 0;color:#666;">Email</td>
                <td style="padding:0.5rem 0;font-weight:600;">${email}</td></tr>
            <tr><td style="padding:0.5rem 0;color:#666;">Phone</td>
                <td style="padding:0.5rem 0;">${phone || '—'}</td></tr>
            <tr><td style="padding:0.5rem 0;color:#666;">Submitted</td>
                <td style="padding:0.5rem 0;">${date} CT</td></tr>
          </table>
          <p style="margin-top:1.5rem;color:#666;font-size:0.85rem;">
            A magic link was sent to their email automatically.
          </p>
        </div>
      `,
    }),
  });
}

// ── Log to GitHub Gist ───────────────────────────────────────────────────────

async function logToGist(env, entry) {
  const { GITHUB_TOKEN, GITHUB_GIST_ID } = env;
  if (!GITHUB_TOKEN) return;

  const line = JSON.stringify(entry);

  if (GITHUB_GIST_ID) {
    const getRes  = await fetch(`https://api.github.com/gists/${GITHUB_GIST_ID}`, {
      headers: { 'Authorization': `Bearer ${GITHUB_TOKEN}`, 'Accept': 'application/vnd.github+json', 'User-Agent': 'professional-portfolio' }
    });
    const gistData = await getRes.json();
    const existing = gistData.files?.['access_requests.jsonl']?.content || '';
    await fetch(`https://api.github.com/gists/${GITHUB_GIST_ID}`, {
      method: 'PATCH',
      headers: { 'Authorization': `Bearer ${GITHUB_TOKEN}`, 'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json', 'User-Agent': 'professional-portfolio' },
      body: JSON.stringify({ files: { 'access_requests.jsonl': { content: existing + line + '\n' } } })
    });
  } else {
    await fetch('https://api.github.com/gists', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${GITHUB_TOKEN}`, 'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json', 'User-Agent': 'professional-portfolio' },
      body: JSON.stringify({ description: 'Portfolio Access Requests', public: false, files: { 'access_requests.jsonl': { content: line + '\n' } } })
    });
  }
}
