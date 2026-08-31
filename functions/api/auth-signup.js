// functions/api/auth-signup.js — Cloudflare Pages Function
// Requires a KV namespace bound as FAINET_KV, and a SESSION_SECRET env var
// (Pages → Settings → Functions → KV namespace bindings / Environment variables).

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

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  return `${toHex(salt)}:${toHex(bits)}`;
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
    const { fullName, faisalId, email, phone, password, country, province, district } = payload;
    if (!fullName || !faisalId || !email || !password) {
      return json(400, { error: 'Missing required fields' });
    }
    if (password.length < 6) return json(400, { error: 'Password must be at least 6 characters.' });

    const emailKey = email.trim().toLowerCase();
    const faisalIdKey = faisalId.trim().toLowerCase().replace(/^@/, '');

    if (await env.FAINET_KV.get(`user:${emailKey}`)) {
      return json(409, { error: 'An account with that email already exists' });
    }
    if (await env.FAINET_KV.get(`faisalid:${faisalIdKey}`)) {
      return json(409, { error: 'That Faisal ID is already taken. Try another.' });
    }

    const passwordHash = await hashPassword(password);
    // Whoever signs up with this exact email becomes an admin automatically —
    // the one bootstrap path into Main Control. Change/remove once you have
    // your own admin account.
    const MASTER_ADMIN_EMAIL = 'thefaisal322@gmail.com';

    const user = {
      fullName, faisalId: faisalIdKey, email: emailKey,
      phone: phone || null, passwordHash,
      plan: 'Free', type: 'email',
      country: country || null, province: province || null, district: district || null,
      isAdmin: emailKey === MASTER_ADMIN_EMAIL,
      createdAt: new Date().toISOString()
    };

    await env.FAINET_KV.put(`user:${emailKey}`, JSON.stringify(user));
    await env.FAINET_KV.put(`faisalid:${faisalIdKey}`, emailKey);

    const token = await signToken({ email: emailKey }, 60 * 60 * 24 * 30, env.SESSION_SECRET);
    const { passwordHash: _drop, ...publicUser } = user;
    return json(200, { token, user: publicUser });
  } catch (err) {
    return json(500, { error: 'Unexpected server error: ' + err.message });
  }
}
