// functions/api/search.js — Cloudflare Pages Function
// Real web search via Tavily (1,000 free queries/month, no card required).
// POST { query }  or  GET ?q=...
// Response: { query, answer, results: [{ title, url, content }] }

function json(status, obj) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
}

async function handle(request, env) {
  if (!env.FAINET_KV) return json(500, { error: 'Server misconfigured: FAINET_KV namespace is not bound.' });
  const auth = request.headers.get('Authorization') || '';
  if (!auth.startsWith('Bearer ')) return json(401, { error: 'Missing faiNET API key (Authorization: Bearer <key>)' });
  const faiNetKey = auth.replace('Bearer ', '').trim();

  const record = await env.FAINET_KV.get(`apikey:${faiNetKey}`);
  if (!record) return json(403, { error: 'Invalid or unregistered faiNET API key' });

  let query = new URL(request.url).searchParams.get('q');
  if (!query && request.method === 'POST') {
    let payload;
    try { payload = await request.json(); } catch { return json(400, { error: 'Invalid JSON body' }); }
    query = payload.query;
  }
  if (!query) return json(400, { error: 'Missing search query (?q=... or JSON body { "query": "..." })' });

  if (!env.TAVILY_API_KEY) return json(500, { error: 'Server misconfigured: TAVILY_API_KEY is not set.' });

  const resp = await fetch('https://api.tavily.com/search', {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.TAVILY_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ query, max_results: 8, include_answer: true })
  });
  if (!resp.ok) {
    const text = await resp.text();
    return json(resp.status, { error: `Tavily error: ${text}` });
  }
  const data = await resp.json();
  const results = (data.results || []).map(r => ({ title: r.title, url: r.url, content: r.content }));
  return json(200, { query, answer: data.answer || null, results });
}

export async function onRequestPost({ request, env }) {
  try { return await handle(request, env); }
  catch (err) { return json(500, { error: 'Unexpected server error: ' + err.message }); }
}
export async function onRequestGet({ request, env }) {
  try { return await handle(request, env); }
  catch (err) { return json(500, { error: 'Unexpected server error: ' + err.message }); }
}
