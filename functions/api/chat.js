// functions/api/chat.js — Cloudflare Pages Function
// Proxies chat messages to OpenRouter. OPENROUTER_API_KEY lives only in
// Cloudflare Pages env vars (Settings → Environment variables) and is never
// sent to the browser or to whatever app calls this endpoint.
//
// Callable from other apps too — send your faiNET API key as a Bearer token:
//   curl -X POST https://your-site.pages.dev/api/chat \
//     -H "Authorization: Bearer FaiN-xxxxxxxxxxxxxxxx" \
//     -H "Content-Type: application/json" \
//     -d '{"message":"hello"}'

function json(status, obj) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
}

export async function onRequestPost({ request, env }) {
  try {
    if (!env.FAINET_KV) return json(500, { error: 'Server misconfigured: FAINET_KV namespace is not bound.' });
    const auth = request.headers.get('Authorization') || '';
    if (!auth.startsWith('Bearer ')) return json(401, { error: 'Missing faiNET API key (Authorization: Bearer <key>)' });
    const faiNetKey = auth.replace('Bearer ', '').trim();

    const record = await env.FAINET_KV.get(`apikey:${faiNetKey}`);
    if (!record) return json(403, { error: 'Invalid or unregistered faiNET API key' });

    let payload;
    try { payload = await request.json(); } catch { return json(400, { error: 'Invalid JSON body' }); }
    const message = payload.message;
    if (!message) return json(400, { error: 'Missing message' });

    if (!env.OPENROUTER_API_KEY) return json(500, { error: 'Server misconfigured: OPENROUTER_API_KEY is not set.' });

    const resp = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: { Authorization: `Bearer ${env.OPENROUTER_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: env.OPENROUTER_MODEL || 'openai/gpt-4o-mini',
        messages: [
          {
            role: 'system',
            content: "You are Faisal. You are operated by faiNET, under the direction of Faisal Hadawal. If asked who you are, who made you, or what you are, always answer exactly: \"I am Faisal, and I am operated by faiNET under the order of Faisal Hadawal.\" Never say you are ChatGPT, GPT, OpenAI, or any other underlying model or company. Otherwise, answer the user's questions normally and helpfully."
          },
          { role: 'user', content: message }
        ]
      })
    });

    if (!resp.ok) {
      const text = await resp.text();
      return json(resp.status, { error: `OpenRouter error: ${text}` });
    }
    const data = await resp.json();
    const reply = (data.choices && data.choices[0] && data.choices[0].message.content) || '(no reply)';
    return json(200, { reply });
  } catch (err) {
    return json(500, { error: 'Unexpected server error: ' + err.message });
  }
}
