import { HttpError, assert } from './auth.js';

export function hasZeptoMailConfig(env) {
  return Boolean(env.ZEPTOMAIL_API_KEY && env.ZEPTOMAIL_API_HOST);
}

export async function sendZeptoEmail(env, { fromName = 'Technical Risk Architect', to, subject, htmlbody }) {
  assert(hasZeptoMailConfig(env), 503, 'Mail delivery is not configured');

  const response = await fetch(`https://${env.ZEPTOMAIL_API_HOST}/v1.1/email`, {
    method: 'POST',
    headers: {
      Authorization: `Zoho-enczapikey ${env.ZEPTOMAIL_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: {
        address: 'contact@technicalriskarchitect.com',
        name: fromName,
      },
      to: to.map(recipient => ({
        email_address: {
          address: recipient.address,
          name: recipient.name,
        },
      })),
      subject,
      htmlbody,
    }),
  });

  if (!response.ok) {
    throw new HttpError(502, `Mail delivery failed: ${response.status}`);
  }
}
