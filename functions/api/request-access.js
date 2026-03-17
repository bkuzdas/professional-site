/**
 * POST /api/request-access
 * Handles portfolio access requests:
 *  1. Validates form fields
 *  2. Adds requester email to Cloudflare Access policy
 *  3. Logs submission to a private GitHub Gist
 *  4. Emails Brian via Resend
 *  5. Redirects to success page
 *
 * Required env vars (set in Cloudflare Pages → Settings → Environment variables):
 *   CF_ACCESS_TOKEN   — Cloudflare API token with Access: Apps and Policies: Edit
 *   CF_ACCOUNT_ID     — Cloudflare account ID
 *   CF_APP_ID         — Cloudflare Access app ID
 *   CF_POLICY_ID      — Cloudflare Access policy ID
 *   GITHUB_TOKEN      — GitHub personal access token with gist scope
 *   GITHUB_GIST_ID    — ID of the private gist (auto-created on first run if blank)
 *   RESEND_API_KEY    — Resend.com API key for email notifications to Brian
 */
export async function onRequestPost(context) {
  const { request, env } = context;

  const formData = await request.formData();
  const firstName   = (formData.get('first_name')   || '').trim();
  const lastName    = (formData.get('last_name')    || '').trim();
  const phone       = (formData.get('phone')        || '').trim();
  const email       = (formData.get('email')        || '').trim().toLowerCase();

  // Basic validation
  if (!firstName || !lastName || !email) {
    return new Response('Missing required fields', { status: 400 });
  }
  if (!email.includes('@')) {
    return new Response('Invalid email address', { status: 400 });
  }

  const timestamp = new Date().toISOString();
  const entry = { firstName, lastName, phone, email, requestedAt: timestamp };

  // 1 — Add email to ALL Cloudflare Access policies (one per protected path)
  try {
    await addEmailToAllPolicies(env, email);
  } catch (err) {
    console.error('CF Access error:', err);
  }

  // 2 — Log to GitHub Gist
  try {
    await logToGist(env, entry);
  } catch (err) {
    console.error('Gist log error:', err);
  }

  // 3 — Email Brian a notification
  try {
    await notifyBrian(env, entry);
  } catch (err) {
    console.error('Email notify error:', err);
  }

  // 4 — Redirect straight to the Cloudflare Access login screen
  //     CF Access will challenge them for OTP, then land them on /experience
  const loginUrl = `https://brianboru.cloudflareaccess.com/cdn-cgi/access/login/professional.brianboruma.com?redirect_url=/experience`;
  return Response.redirect(loginUrl, 303);
}

async function addEmailToAllPolicies(env, newEmail) {
  const {
    CF_ACCESS_TOKEN, CF_ACCOUNT_ID,
    CF_APP_ID_EXPERIENCE,    CF_POLICY_ID_EXPERIENCE,
    CF_APP_ID_PROJECTS,      CF_POLICY_ID_PROJECTS,
    CF_APP_ID_ACHIEVEMENTS,  CF_POLICY_ID_ACHIEVEMENTS,
    CF_APP_ID_RESUMES,       CF_POLICY_ID_RESUMES,
    CF_APP_ID_RESUME,        CF_POLICY_ID_RESUME,
  } = env;

  const apps = [
    { appId: CF_APP_ID_EXPERIENCE,   policyId: CF_POLICY_ID_EXPERIENCE },
    { appId: CF_APP_ID_PROJECTS,     policyId: CF_POLICY_ID_PROJECTS },
    { appId: CF_APP_ID_ACHIEVEMENTS, policyId: CF_POLICY_ID_ACHIEVEMENTS },
    { appId: CF_APP_ID_RESUMES,      policyId: CF_POLICY_ID_RESUMES },
    { appId: CF_APP_ID_RESUME,       policyId: CF_POLICY_ID_RESUME },
  ];

  await Promise.all(apps.map(({ appId, policyId }) =>
    addEmailToPolicy(CF_ACCESS_TOKEN, CF_ACCOUNT_ID, appId, policyId, newEmail)
  ));
}

async function addEmailToPolicy(token, accountId, appId, policyId, newEmail) {
  // Fetch current policy
  const getRes = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${accountId}/access/apps/${appId}/policies/${policyId}`,
    { headers: { 'Authorization': `Bearer ${token}` } }
  );
  const getData = await getRes.json();
  if (!getData.success) throw new Error(JSON.stringify(getData.errors));

  const policy = getData.result;
  const include = policy.include || [];

  // Don't add duplicates
  const alreadyExists = include.some(r => r.email?.email === newEmail);
  if (alreadyExists) return;

  include.push({ email: { email: newEmail } });

  const putRes = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${accountId}/access/apps/${appId}/policies/${policyId}`,
    {
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ ...policy, include }),
    }
  );
  const putData = await putRes.json();
  if (!putData.success) throw new Error(JSON.stringify(putData.errors));
}

async function logToGist(env, entry) {
  const { GITHUB_TOKEN, GITHUB_GIST_ID } = env;
  const line = JSON.stringify(entry);

  if (GITHUB_GIST_ID) {
    // Fetch current gist content
    const getRes = await fetch(`https://api.github.com/gists/${GITHUB_GIST_ID}`, {
      headers: {
        'Authorization': `Bearer ${GITHUB_TOKEN}`,
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'professional-portfolio',
      }
    });
    const gistData = await getRes.json();
    const existing = gistData.files?.['access_requests.jsonl']?.content || '';
    const updated = existing + line + '\n';

    await fetch(`https://api.github.com/gists/${GITHUB_GIST_ID}`, {
      method: 'PATCH',
      headers: {
        'Authorization': `Bearer ${GITHUB_TOKEN}`,
        'Accept': 'application/vnd.github+json',
        'Content-Type': 'application/json',
        'User-Agent': 'professional-portfolio',
      },
      body: JSON.stringify({
        files: { 'access_requests.jsonl': { content: updated } }
      })
    });
  } else {
    // Create a new private gist on first run
    await fetch('https://api.github.com/gists', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${GITHUB_TOKEN}`,
        'Accept': 'application/vnd.github+json',
        'Content-Type': 'application/json',
        'User-Agent': 'professional-portfolio',
      },
      body: JSON.stringify({
        description: 'Portfolio Access Requests',
        public: false,
        files: { 'access_requests.jsonl': { content: line + '\n' } }
      })
    });
  }
}

async function notifyBrian(env, entry) {
  const { RESEND_API_KEY } = env;
  if (!RESEND_API_KEY) return;

  const { firstName, lastName, phone, email, requestedAt } = entry;
  const date = new Date(requestedAt).toLocaleString('en-US', { timeZone: 'America/Chicago' });

  await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: 'Portfolio Access <onboarding@resend.dev>',
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
            Their email has been automatically added to the portfolio access policy.
          </p>
        </div>
      `,
    }),
  });
}
