// functions/api/auth-google.js — Cloudflare Pages Function
// Requires GOOGLE_CLIENT_ID env var (must match the frontend's GOOGLE_CLIENT_ID).

function json(status, obj) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
}
function toHex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
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
    if (!env.FAINET_KV || !env.SESSION_SECRET) return json(500, { error: 'Server misconfigured.' });
    if (!env.GOOGLE_CLIENT_ID) return json(500, { error: 'Server misconfigured: GOOGLE_CLIENT_ID not set.' });

    let payload;
    try { payload = await request.json(); } catch { return json(400, { error: 'Invalid JSON body' }); }
    const { credential } = payload;
    if (!credential) return json(400, { error: 'Missing Google credential' });

    const verifyResp = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(credential)}`);
    if (!verifyResp.ok) return json(401, { error: 'Invalid or expired Google credential' });
    const claims = await verifyResp.json();
    if (claims.aud !== env.GOOGLE_CLIENT_ID) return json(401, { error: 'Google credential was not issued for this app' });

    const emailKey = (claims.email || '').trim().toLowerCase();
    if (!emailKey) return json(400, { error: 'Google account has no email' });
    const MASTER_ADMIN_EMAIL = 'thefaisal322@gmail.com';

    let userRaw = await env.FAINET_KV.get(`user:${emailKey}`);
    let user;
    if (!userRaw) {
      let faisalIdKey = emailKey.split('@')[0].replace(/[^a-z0-9_]/g, '').toLowerCase() || 'user';
      let candidate = faisalIdKey, suffix = 0;
      while (await env.FAINET_KV.get(`faisalid:${candidate}`)) { suffix += 1; candidate = `${faisalIdKey}${suffix}`; }
      faisalIdKey = candidate;

      user = {
        fullName: claims.name || 'faiNET User', faisalId: faisalIdKey, email: emailKey,
        phone: null, passwordHash: null, plan: 'Free', type: 'google',
        photo: claims.picture || null, country: null, province: null, district: null,
        isAdmin: emailKey === MASTER_ADMIN_EMAIL, createdAt: new Date().toISOString()
      };
      await env.FAINET_KV.put(`user:${emailKey}`, JSON.stringify(user));
      await env.FAINET_KV.put(`faisalid:${faisalIdKey}`, emailKey);
    } else {
      user = JSON.parse(userRaw);
      if (emailKey === MASTER_ADMIN_EMAIL && !user.isAdmin) {
        user.isAdmin = true;
        await env.FAINET_KV.put(`user:${emailKey}`, JSON.stringify(user));
      }
    }

    const token = await signToken({ email: emailKey }, 60 * 60 * 24 * 30, env.SESSION_SECRET);
    const { passwordHash: _drop, ...publicUser } = user;
    return json(200, { token, user: publicUser });
  } catch (err) {
    return json(500, { error: 'Unexpected server error: ' + err.message });
  }
}
