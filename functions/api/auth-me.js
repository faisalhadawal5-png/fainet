// functions/api/auth-me.js — Cloudflare Pages Function

function json(status, obj) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
}
function base64urlDecode(input) {
  input = input.replace(/-/g, '+').replace(/_/g, '/');
  while (input.length % 4) input += '=';
  return atob(input);
}
function toHex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
async function verifyToken(token, secret) {
  if (!token || !token.includes('.')) return null;
  const [bodyB64, sig] = token.split('.');
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const expectedSig = toHex(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(bodyB64)));
  if (sig !== expectedSig) return null;
  let body;
  try { body = JSON.parse(base64urlDecode(bodyB64)); } catch { return null; }
  if (!body.exp || Date.now() > body.exp) return null;
  return body;
}

export async function onRequestGet({ request, env }) {
  try {
    if (!env.FAINET_KV || !env.SESSION_SECRET) return json(500, { error: 'Server misconfigured.' });
    const auth = request.headers.get('Authorization') || '';
    if (!auth.startsWith('Bearer ')) return json(401, { error: 'Missing session token' });
    const claims = await verifyToken(auth.replace('Bearer ', ''), env.SESSION_SECRET);
    if (!claims) return json(401, { error: 'Invalid or expired session' });

    const userRaw = await env.FAINET_KV.get(`user:${claims.email}`);
    if (!userRaw) return json(401, { error: 'Invalid or expired session' });
    const user = JSON.parse(userRaw);
    const { passwordHash: _drop, ...publicUser } = user;
    return json(200, { user: publicUser });
  } catch (err) {
    return json(500, { error: 'Unexpected server error: ' + err.message });
  }
}
