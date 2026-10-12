// lobby-server.js
// Accounts + social login (Google, GitHub, Facebook, X) + live chat room.
// Wire it into worker.js with two lines (see SETUP.md).

import { DurableObject } from "cloudflare:workers";

const SESSION_MS = 30 * 24 * 3600 * 1000;
const enc = new TextEncoder();

/* ---------- small helpers ---------- */
const b64 = (buf) => { let s = ""; for (const b of new Uint8Array(buf)) s += String.fromCharCode(b); return btoa(s); };
const b64url = (buf) => b64(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const rand = (n = 32) => b64url(crypto.getRandomValues(new Uint8Array(n)));
const sha256 = async (s) => b64url(await crypto.subtle.digest("SHA-256", enc.encode(s)));
async function pbkdf2(pw, saltB64) {
  const salt = Uint8Array.from(atob(saltB64), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
  // Workers caps PBKDF2 at 100,000 iterations
  return b64(await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, key, 256));
}
function same(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
const cleanName = (s) => String(s || "").replace(/[\u0000-\u001f<>]/g, "").trim().slice(0, 30);
const cleanPic = (s) => (/^https:\/\/[^\s"'<>\\]{1,500}$/.test(String(s || "")) ? String(s) : "");
const isEmail = (e) => typeof e === "string" && e.length <= 254 && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e);

function reply(obj, status = 200, cookies = []) {
  const h = new Headers({ "Content-Type": "application/json", "Cache-Control": "no-store" });
  for (const c of cookies) h.append("Set-Cookie", c);
  return new Response(JSON.stringify(obj), { status, headers: h });
}
function redirect(to, cookies = []) {
  const h = new Headers({ Location: to, "Cache-Control": "no-store" });
  for (const c of cookies) h.append("Set-Cookie", c);
  return new Response(null, { status: 302, headers: h });
}
const getCookie = (req, name) => {
  const m = (req.headers.get("Cookie") || "").split(/;\s*/).find((c) => c.startsWith(name + "="));
  return m ? m.slice(name.length + 1) : "";
};
const cookie = (name, val, maxAge) => `${name}=${val}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
const sessionCookie = (tok) => cookie("lobby_sid", tok, SESSION_MS / 1000);

/* ---------- OAuth providers ---------- */
const jget = async (url, token) => (await fetch(url, { headers: { Authorization: "Bearer " + token, "User-Agent": "lobby", Accept: "application/json" } })).json();

const PROVIDERS = {
  google: {
    auth: "https://accounts.google.com/o/oauth2/v2/auth",
    token: "https://oauth2.googleapis.com/token",
    scope: "openid email profile",
    id: "GOOGLE_CLIENT_ID", secret: "GOOGLE_CLIENT_SECRET",
    async profile(t) {
      const r = await jget("https://openidconnect.googleapis.com/v1/userinfo", t);
      return { sub: r.sub, email: r.email, verified: r.email_verified === true, name: r.name, pic: r.picture };
    },
  },
  github: {
    auth: "https://github.com/login/oauth/authorize",
    token: "https://github.com/login/oauth/access_token",
    scope: "read:user user:email",
    id: "GITHUB_CLIENT_ID", secret: "GITHUB_CLIENT_SECRET",
    async profile(t) {
      const r = await jget("https://api.github.com/user", t);
      let email = "", verified = false;
      try {
        const list = await jget("https://api.github.com/user/emails", t);
        const e = Array.isArray(list) && list.find((x) => x.primary && x.verified);
        if (e) { email = e.email; verified = true; }
      } catch {}
      return { sub: String(r.id), email, verified, name: r.name || r.login, pic: r.avatar_url };
    },
  },
  facebook: {
    auth: "https://www.facebook.com/v19.0/dialog/oauth",
    token: "https://graph.facebook.com/v19.0/oauth/access_token",
    scope: "email,public_profile",
    id: "FACEBOOK_CLIENT_ID", secret: "FACEBOOK_CLIENT_SECRET",
    async profile(t) {
      const r = await jget("https://graph.facebook.com/me?fields=id,name,email,picture.width(96).height(96)", t);
      // Facebook doesn't flag emails as verified, so we never auto-merge on it.
      return { sub: String(r.id), email: r.email || "", verified: false, name: r.name, pic: r.picture && r.picture.data && r.picture.data.url };
    },
  },
  x: {
    auth: "https://twitter.com/i/oauth2/authorize",
    token: "https://api.twitter.com/2/oauth2/token",
    scope: "users.read tweet.read",
    id: "X_CLIENT_ID", secret: "X_CLIENT_SECRET",
    pkce: true, basic: true,
    async profile(t) {
      const r = await jget("https://api.twitter.com/2/users/me?user.fields=profile_image_url", t);
      const d = r.data || {};
      // X does not hand out email addresses.
      return { sub: String(d.id), email: "", verified: false, name: d.name || d.username, pic: d.profile_image_url };
    },
  },
};

async function exchange(p, env, code, redirectUri, verifier) {
  const id = env[p.id], secret = env[p.secret];
  const body = new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: id });
  const headers = { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json", "User-Agent": "lobby" };
  if (p.basic) headers.Authorization = "Basic " + btoa(id + ":" + secret);
  else body.set("client_secret", secret);
  if (p.pkce) body.set("code_verifier", verifier);
  const r = await fetch(p.token, { method: "POST", headers, body });
  const j = await r.json();
  return j.access_token || "";
}

/* ---------- accounts (one Durable Object, SQLite-backed storage) ---------- */
export class LobbyDB extends DurableObject {
  #pub(u) { return { id: u.id, email: u.email || "", name: u.name, pic: u.pic || "" }; }

  async #newSession(uid) {
    const tok = rand();
    await this.ctx.storage.put("s:" + (await sha256(tok)), { uid, exp: Date.now() + SESSION_MS });
    return tok;
  }

  async signup(email, pw, name) {
    const st = this.ctx.storage;
    email = String(email || "").trim().toLowerCase();
    if (!isEmail(email)) return { error: "email" };
    if (typeof pw !== "string" || pw.length < 8 || pw.length > 200) return { error: "password" };
    if (await st.get("e:" + email)) return { error: "exists" };
    const id = crypto.randomUUID();
    const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
    const u = { id, email, name: cleanName(name) || email.split("@")[0].slice(0, 30), pic: "", salt, hash: await pbkdf2(pw, salt), created: Date.now() };
    await st.put({ ["u:" + id]: u, ["e:" + email]: id });
    return { user: this.#pub(u), token: await this.#newSession(id) };
  }

  async login(email, pw) {
    const st = this.ctx.storage;
    email = String(email || "").trim().toLowerCase();
    const f = (await st.get("f:" + email)) || { n: 0, t: 0 };
    const recent = Date.now() - f.t < 15 * 60 * 1000;
    if (f.n >= 8 && recent) return { error: "locked" };
    const id = await st.get("e:" + email);
    const u = id && (await st.get("u:" + id));
    const ok = u && u.hash && typeof pw === "string" && same(await pbkdf2(pw, u.salt), u.hash);
    if (!u) await pbkdf2(String(pw || ""), b64(new Uint8Array(16))); // keep timing similar
    if (!ok) {
      await st.put("f:" + email, { n: (recent ? f.n : 0) + 1, t: Date.now() });
      return { error: "bad" };
    }
    await st.delete("f:" + email);
    return { user: this.#pub(u), token: await this.#newSession(u.id) };
  }

  async oauth(provider, sub, email, verified, name, pic) {
    const st = this.ctx.storage;
    email = verified ? String(email || "").toLowerCase() : "";
    pic = cleanPic(pic);
    let id = await st.get(`p:${provider}:${sub}`);
    if (!id && email) id = await st.get("e:" + email); // merge only on a provider-verified email
    let u = id && (await st.get("u:" + id));
    if (!u) {
      id = crypto.randomUUID();
      u = { id, email, name: cleanName(name) || provider + " user", pic, salt: "", hash: "", created: Date.now() };
      if (email) await st.put("e:" + email, id);
    } else {
      if (!u.pic && pic) u.pic = pic;
      if (!u.name) u.name = cleanName(name) || provider + " user";
      // Merging into a password account: drop the password so nobody who
      // pre-registered this email can keep a way in.
      if (u.hash) { u.hash = ""; u.salt = ""; }
    }
    await st.put({ ["u:" + id]: u, [`p:${provider}:${sub}`]: id });
    return { user: this.#pub(u), token: await this.#newSession(id) };
  }

  async session(tok) {
    const st = this.ctx.storage;
    const k = "s:" + (await sha256(tok));
    const s = await st.get(k);
    if (!s) return null;
    if (s.exp < Date.now()) { await st.delete(k); return null; }
    const u = await st.get("u:" + s.uid);
    return u ? this.#pub(u) : null;
  }

  async logout(tok) { await this.ctx.storage.delete("s:" + (await sha256(tok))); }

  async setName(uid, name) {
    const u = await this.ctx.storage.get("u:" + uid);
    name = cleanName(name);
    if (!u || !name) return null;
    u.name = name;
    await this.ctx.storage.put("u:" + uid, u);
    return this.#pub(u);
  }
}

/* ---------- chat room (hibernating WebSockets, history survives restarts) ---------- */
export class ChatRoom extends DurableObject {
  async fetch(req) {
    let user;
    try { user = JSON.parse(decodeURIComponent(req.headers.get("X-Lobby-User") || "")); } catch { return new Response("No user", { status: 401 }); }
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server);
    server.serializeAttachment({ id: user.id, name: user.name, pic: user.pic, last: 0 });
    const hist = (await this.ctx.storage.get("hist")) || [];
    server.send(JSON.stringify({ type: "history", messages: hist }));
    this.#count();
    return new Response(null, { status: 101, webSocket: client });
  }

  #count(exclude) {
    const all = this.ctx.getWebSockets().filter((w) => w !== exclude);
    const msg = JSON.stringify({ type: "count", n: all.length });
    for (const w of all) { try { w.send(msg); } catch {} }
  }

  async webSocketMessage(ws, raw) {
    if (typeof raw !== "string" || raw.length > 2000) return;
    let d;
    try { d = JSON.parse(raw); } catch { return; }
    const text = String(d.text || "").trim().slice(0, 500);
    if (!text) return;
    const a = ws.deserializeAttachment();
    const now = Date.now();
    if (now - (a.last || 0) < 700) { ws.send(JSON.stringify({ type: "error", code: "slow" })); return; }
    a.last = now;
    ws.serializeAttachment(a);
    const msg = { id: crypto.randomUUID(), uid: a.id, name: a.name, pic: a.pic, text, ts: now };
    const hist = (await this.ctx.storage.get("hist")) || [];
    hist.push(msg);
    await this.ctx.storage.put("hist", hist.slice(-100));
    const out = JSON.stringify({ type: "msg", message: msg });
    for (const w of this.ctx.getWebSockets()) { try { w.send(out); } catch {} }
  }

  async webSocketClose(ws) { try { ws.close(); } catch {} this.#count(ws); }
  async webSocketError(ws) { this.#count(ws); }
}

/* ---------- router: returns a Response, or null if the path isn't ours ---------- */
const db = (env) => env.LOBBY_DB.get(env.LOBBY_DB.idFromName("main"));
const sidOf = (req) => getCookie(req, "lobby_sid");
const sameOrigin = (req, url) => { const o = req.headers.get("Origin"); return !o || o === url.origin; };

export async function handleLobby(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  if (!path.startsWith("/api/auth/") && path !== "/api/room/ws") return null;
  if (!env.LOBBY_DB || !env.CHAT_ROOM) return reply({ error: "Durable Objects not configured" }, 500);

  /* chat socket */
  if (path === "/api/room/ws") {
    if (request.headers.get("Upgrade") !== "websocket") return new Response("Expected WebSocket", { status: 426 });
    if (!sameOrigin(request, url)) return new Response("Bad origin", { status: 403 });
    const tok = sidOf(request);
    const user = tok && (await db(env).session(tok));
    if (!user) return new Response("Log in first", { status: 401 });
    const h = new Headers({ Upgrade: "websocket", "X-Lobby-User": encodeURIComponent(JSON.stringify({ id: user.id, name: user.name, pic: user.pic })) });
    const room = env.CHAT_ROOM.get(env.CHAT_ROOM.idFromName("main"));
    return room.fetch(new Request("https://room/ws", { headers: h }));
  }

  /* which social buttons are configured */
  if (path === "/api/auth/providers") {
    return reply({ providers: Object.keys(PROVIDERS).filter((k) => env[PROVIDERS[k].id] && env[PROVIDERS[k].secret]) });
  }

  if (path === "/api/auth/me") {
    const tok = sidOf(request);
    return reply({ user: tok ? await db(env).session(tok) : null });
  }

  /* start OAuth */
  let m = path.match(/^\/api\/auth\/oauth\/(\w+)$/);
  if (m) {
    const p = PROVIDERS[m[1]];
    if (!p || !env[p.id] || !env[p.secret]) return redirect("/?login=err&why=notset");
    const state = rand(16), verifier = rand(32);
    const q = new URLSearchParams({
      client_id: env[p.id], redirect_uri: `${url.origin}/api/auth/callback/${m[1]}`,
      response_type: "code", scope: p.scope, state,
    });
    if (p.pkce) { q.set("code_challenge", await sha256(verifier)); q.set("code_challenge_method", "S256"); }
    return redirect(`${p.auth}?${q}`, [cookie("lobby_oauth", `${m[1]}.${state}.${verifier}`, 600)]);
  }

  /* OAuth callback */
  m = path.match(/^\/api\/auth\/callback\/(\w+)$/);
  if (m) {
    const name = m[1], p = PROVIDERS[name];
    const clear = cookie("lobby_oauth", "", 0);
    if (!p || !env[p.id] || !env[p.secret]) return redirect("/?login=err&why=notset", [clear]);
    if (url.searchParams.get("error")) return redirect("/?login=err&why=denied", [clear]);
    const [cp, state, verifier] = getCookie(request, "lobby_oauth").split(".");
    if (cp !== name || !state || state !== url.searchParams.get("state") || !url.searchParams.get("code")) return redirect("/?login=err&why=failed", [clear]);
    try {
      const token = await exchange(p, env, url.searchParams.get("code"), `${url.origin}/api/auth/callback/${name}`, verifier);
      if (!token) return redirect("/?login=err&why=failed", [clear]);
      const prof = await p.profile(token);
      if (!prof.sub || prof.sub === "undefined") return redirect("/?login=err&why=failed", [clear]);
      const r = await db(env).oauth(name, prof.sub, prof.email, prof.verified, prof.name, prof.pic);
      return redirect("/?login=ok", [sessionCookie(r.token), clear]);
    } catch {
      return redirect("/?login=err&why=failed", [clear]);
    }
  }

  /* everything below is a POST */
  if (request.method !== "POST") return reply({ error: "method" }, 405);
  if (!sameOrigin(request, url)) return reply({ error: "origin" }, 403);
  let body = {};
  try { body = await request.json(); } catch {}

  if (path === "/api/auth/signup") {
    const r = await db(env).signup(body.email, body.password, body.name);
    if (r.error) return reply({ error: r.error }, r.error === "exists" ? 409 : 400);
    return reply({ user: r.user }, 200, [sessionCookie(r.token)]);
  }
  if (path === "/api/auth/login") {
    const r = await db(env).login(body.email, body.password);
    if (r.error) return reply({ error: r.error }, r.error === "locked" ? 429 : 401);
    return reply({ user: r.user }, 200, [sessionCookie(r.token)]);
  }
  if (path === "/api/auth/logout") {
    const tok = sidOf(request);
    if (tok) await db(env).logout(tok);
    return reply({ ok: true }, 200, [cookie("lobby_sid", "", 0)]);
  }
  if (path === "/api/auth/profile") {
    const tok = sidOf(request);
    const me = tok && (await db(env).session(tok));
    if (!me) return reply({ error: "auth" }, 401);
    const u = await db(env).setName(me.id, body.name);
    return u ? reply({ user: u }) : reply({ error: "name" }, 400);
  }
  return reply({ error: "not found" }, 404);
}
