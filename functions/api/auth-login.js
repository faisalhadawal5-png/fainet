// functions/api/auth-login.js — Cloudflare Pages Function

function json(status, obj) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
}
function toHex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}
async function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [saltHex, hashHex] = stored.split(':');
  const salt = fromHex(saltHex);
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  return toHex(bits) === hashHex;
}
function base64url(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
async function signToken(payload, expiresInSeconds, secret) {
  const body = { ...payload, exp: Date.now() + expiresInSeconds * 1000 };
  const bodyB64 = base64url(JSON.stringify(body));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(bodyB64));
  return `${bodyB64}.${toHex(sig)}`;
}

export async function onRequestPost({ request, env }) {
  try {
    if (!env.FAINET_KV) return json(500, { error: 'Server misconfigured: FAINET_KV namespace is not bound.' });
    if (!env.SESSION_SECRET) return json(500, { error: 'Server misconfigured: SESSION_SECRET is not set.' });

    let payload;
    try { payload = await request.json(); } catch { return json(400, { error: 'Invalid JSON body' }); }
    const { faisalId, password } = payload;
    if (!faisalId || !password) return json(400, { error: 'Missing Faisal ID or password' });

    const faisalIdKey = faisalId.trim().toLowerCase().replace(/^@/, '');
    const emailKey = await env.FAINET_KV.get(`faisalid:${faisalIdKey}`);
    if (!emailKey) return json(401, { error: 'Invalid Faisal ID or password' });

    const userRaw = await env.FAINET_KV.get(`user:${emailKey}`);
    if (!userRaw) return json(401, { error: 'Invalid Faisal ID or password' });
    const user = JSON.parse(userRaw);

    if (!user.passwordHash) return json(401, { error: 'This account has no password set — sign in with Google instead.' });
    const match = await verifyPassword(password, user.passwordHash);
    if (!match) return json(401, { error: 'Invalid Faisal ID or password' });

    const token = await signToken({ email: emailKey }, 60 * 60 * 24 * 30, env.SESSION_SECRET);
    const { passwordHash: _drop, ...publicUser } = user;
    return json(200, { token, user: publicUser });
  } catch (err) {
    return json(500, { error: 'Unexpected server error: ' + err.message });
  }
}
