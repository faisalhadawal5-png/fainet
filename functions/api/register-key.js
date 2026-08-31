// functions/api/register-key.js — Cloudflare Pages Function

function json(status, obj) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
}

export async function onRequestPost({ request, env }) {
  try {
    if (!env.FAINET_KV) return json(500, { error: 'Server misconfigured: FAINET_KV namespace is not bound.' });
    let payload;
    try { payload = await request.json(); } catch { return json(400, { error: 'Invalid JSON body' }); }
    const { key, name } = payload;
    if (!key) return json(400, { error: 'Missing key' });

    await env.FAINET_KV.put(`apikey:${key}`, JSON.stringify({ name: name || 'unnamed', created: Date.now() }));
    return json(200, { ok: true });
  } catch (err) {
    return json(500, { error: 'Unexpected server error: ' + err.message });
  }
}
