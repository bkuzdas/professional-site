import { HttpError, assert, getClientIp, getSessionSecret, normalizeEmail, sha256Base64Url } from './auth.js';

const RATE_LIMIT_RETENTION_MS = 31 * 24 * 60 * 60 * 1000;
const RATE_LIMIT_RETENTION_SECONDS = Math.ceil(RATE_LIMIT_RETENTION_MS / 1000);
const AUDIT_RETENTION_SECONDS = 31 * 24 * 60 * 60;
const MAGIC_LINK_RETENTION_SECONDS = 2 * 24 * 60 * 60;

export async function assertNotRateLimited(env, request, kind, email, policy) {
  const now = Date.now();
  const ipHash = await hashSecurityValue(env, getClientIp(request));
  const emailHash = email ? await hashSecurityValue(env, normalizeEmail(email)) : null;
  const namespace = getSecurityNamespace(env);

  if (policy.perIp) {
    const ipCount = await countRecentTimestamps(namespace, buildRateLimitKey(kind, 'ip', ipHash), policy.perIp.windowMs, now);
    if (ipCount >= policy.perIp.limit) {
      throw new HttpError(429, 'Too many requests. Please try again later.');
    }
  }

  if (policy.perEmail && emailHash) {
    const emailCount = await countRecentTimestamps(namespace, buildRateLimitKey(kind, 'email', emailHash), policy.perEmail.windowMs, now);
    if (emailCount >= policy.perEmail.limit) {
      throw new HttpError(429, 'Too many requests for this email. Please try again later.');
    }
  }

  return { ipHash, emailHash };
}

export async function recordSubmission(env, request, kind, email) {
  const namespace = getSecurityNamespace(env);
  const ts = Date.now();
  const ipHash = await hashSecurityValue(env, getClientIp(request));
  const emailHash = email ? await hashSecurityValue(env, normalizeEmail(email)) : null;

  await appendTimestamp(namespace, buildRateLimitKey(kind, 'ip', ipHash), ts);
  if (emailHash) {
    await appendTimestamp(namespace, buildRateLimitKey(kind, 'email', emailHash), ts);
  }

  await putAuditEvent(namespace, {
    kind,
    type: 'submit',
    ipHash,
    emailHash,
    ts,
  });
}

export async function recordMagicLinkIssued(env, request, email, nonce) {
  const namespace = getSecurityNamespace(env);
  const ipHash = await hashSecurityValue(env, getClientIp(request));
  const emailHash = await hashSecurityValue(env, normalizeEmail(email));
  const nonceHash = await hashSecurityValue(env, nonce);
  const ts = Date.now();

  await namespace.put(buildMagicLinkKey('issued', nonceHash), JSON.stringify({ ts, ipHash, emailHash }), {
    expirationTtl: MAGIC_LINK_RETENTION_SECONDS,
  });

  await putAuditEvent(namespace, {
    kind: 'request_access',
    type: 'magic_link_issued',
    ipHash,
    emailHash,
    nonceHash,
    ts,
  });
}

export async function assertMagicLinkUnused(env, nonce) {
  const nonceHash = await hashSecurityValue(env, nonce);
  const namespace = getSecurityNamespace(env);
  const alreadyUsed = await namespace.get(buildMagicLinkKey('used', nonceHash));

  if (alreadyUsed) {
    throw new HttpError(409, 'Magic link has already been used');
  }
}

export async function markMagicLinkUsed(env, request, email, nonce) {
  const namespace = getSecurityNamespace(env);
  const ipHash = await hashSecurityValue(env, getClientIp(request));
  const emailHash = await hashSecurityValue(env, normalizeEmail(email));
  const nonceHash = await hashSecurityValue(env, nonce);
  const ts = Date.now();

  await namespace.put(buildMagicLinkKey('used', nonceHash), JSON.stringify({ ts, ipHash, emailHash }), {
    expirationTtl: MAGIC_LINK_RETENTION_SECONDS,
  });

  await putAuditEvent(namespace, {
    kind: 'request_access',
    type: 'magic_link_used',
    ipHash,
    emailHash,
    nonceHash,
    ts,
  });
}

async function appendTimestamp(namespace, key, timestamp) {
  const values = await readTimestampList(namespace, key);
  const filtered = values.filter(value => timestamp - value <= RATE_LIMIT_RETENTION_MS);
  filtered.push(timestamp);

  await namespace.put(key, JSON.stringify(filtered), {
    expirationTtl: RATE_LIMIT_RETENTION_SECONDS,
  });
}

async function countRecentTimestamps(namespace, key, windowMs, now) {
  const values = await readTimestampList(namespace, key);
  return values.filter(value => now - value <= windowMs).length;
}

async function readTimestampList(namespace, key) {
  const raw = await namespace.get(key);
  if (!raw) return [];

  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed)
      ? parsed.map(value => Number(value)).filter(Number.isFinite)
      : [];
  } catch {
    return [];
  }
}

async function putAuditEvent(namespace, event) {
  await namespace.put(`audit:${event.type}:${event.ts}:${crypto.randomUUID()}`, JSON.stringify(event), {
    expirationTtl: AUDIT_RETENTION_SECONDS,
  });
}

async function hashSecurityValue(env, value) {
  return sha256Base64Url(`${getSessionSecret(env)}:${value}`);
}

function getSecurityNamespace(env) {
  assert(env.SECURITY_EVENTS && typeof env.SECURITY_EVENTS.get === 'function', 503, 'Security event store is not configured');
  return env.SECURITY_EVENTS;
}

function buildRateLimitKey(kind, dimension, hash) {
  return `rate:${kind}:submit:${dimension}:${hash}`;
}

function buildMagicLinkKey(type, nonceHash) {
  return `magic-link:${type}:${nonceHash}`;
}
