// Cloudflare Pages Function: runs on Cloudflare's servers, NOT in the browser.
// Your website calls /api/chat, this file calls OpenRouter with the secret key.

export async function onRequestPost({ request, env }) {
  const json = (obj, status = 200) =>
    new Response(JSON.stringify(obj), {
      status,
      headers: { "Content-Type": "application/json" },
    });

  if (!env.OPENROUTER_API_KEY) {
    return json({ error: "OPENROUTER_API_KEY is not set in Cloudflare" }, 500);
  }

  // Only accept requests coming from your own site
  const origin = request.headers.get("Origin");
  if (origin && new URL(origin).host !== new URL(request.url).host) {
    return json({ error: "Forbidden" }, 403);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Bad request" }, 400);
  }

  // Keep only the last 20 messages, limit length, allow only user/assistant roles
  const messages = (Array.isArray(body.messages) ? body.messages : [])
    .filter(
      (m) =>
        m &&
        (m.role === "user" || m.role === "assistant") &&
        typeof m.content === "string"
    )
    .slice(-20)
    .map((m) => ({ role: m.role, content: m.content.slice(0, 4000) }));

  if (!messages.length) return json({ error: "No messages" }, 400);

  const r = await fetch("https://openrouter.ai/api/v1/chat/completions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.OPENROUTER_API_KEY}`,
      "Content-Type": "application/json",
      "HTTP-Referer": new URL(request.url).origin,
      "X-Title": "Lobby",
    },
    body: JSON.stringify({
      // "openrouter/free" picks a free model for you. Change it in Cloudflare
      // by adding a variable called OPENROUTER_MODEL (no code edit needed).
      model: env.OPENROUTER_MODEL || "openrouter/free",
      max_tokens: 800,
      messages: [
        {
          role: "system",
          content:
            "You are the AI assistant inside Lobby, a personal notes website. Be friendly and concise. Reply in the same language the user writes in.",
        },
        ...messages,
      ],
    }),
  });

  const data = await r.json().catch(() => null);
  const reply = data?.choices?.[0]?.message?.content;
  if (!r.ok || !reply) {
    return json({ error: data?.error?.message || "AI request failed" }, 502);
  }
  return json({ reply });
}
