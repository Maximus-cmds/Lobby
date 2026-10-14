// lobby-server.js
// Accounts + social login (Google, GitHub, Facebook, X) + live chat room.
// Wire it into worker.js with two lines (see SETUP.md).

import { DurableObject } from "cloudflare:workers";
import { moderateImage } from "./moderation.js";
import { ChatRoom, GroupRoom, DmRoom, IMG_RE, MAX_AVATAR, imgResponse } from "./rooms.js";
export { ChatRoom, GroupRoom, DmRoom };

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
  #pub(u) { return { id: u.id, email: u.email || "", name: u.name, pic: u.av ? `/api/avatar/${u.id}?v=${u.av}` : u.pic || "" }; }

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

  /* ----- avatars ----- */
  async setAvatar(uid, data) {
    const st = this.ctx.storage;
    if (typeof data !== "string" || !IMG_RE.test(data) || data.length > MAX_AVATAR) return { error: "image" };
    const u = await st.get("u:" + uid);
    if (!u) return { error: "auth" };
    u.av = (u.av || 0) + 1;
    await st.put({ ["u:" + uid]: u, ["a:" + uid]: data });
    return { user: this.#pub(u) };
  }
  async getAvatar(uid) { return (await this.ctx.storage.get("a:" + uid)) || null; }

  /* ----- groups: which groups a person is in, and join codes ----- */
  async groups(uid) { return (await this.ctx.storage.get("g:" + uid)) || []; }
  async addGroup(uid, gid) {
    const l = await this.groups(uid);
    if (!l.includes(gid)) { l.push(gid); await this.ctx.storage.put("g:" + uid, l); }
  }
  async removeGroup(uid, gid) {
    const l = await this.groups(uid);
    if (l.includes(gid)) await this.ctx.storage.put("g:" + uid, l.filter((x) => x !== gid));
  }
  async claimCode(code, gid) {
    if (await this.ctx.storage.get("c:" + code)) return false;
    await this.ctx.storage.put("c:" + code, gid);
    return true;
  }
  async freeCode(code) { await this.ctx.storage.delete("c:" + code); }
  async lookup(code) { return (await this.ctx.storage.get("c:" + code)) || null; }
  async profiles(ids) {
    const m = await this.ctx.storage.get(ids.slice(0, 100).map((i) => "u:" + i));
    const out = {};
    for (const u of m.values()) { const p = this.#pub(u); out[u.id] = { name: p.name, pic: p.pic }; }
    return out;
  }
  /* ----- friends ----- */
  async friendCode(uid) {
    const st = this.ctx.storage;
    let c = await st.get("fc:" + uid);
    if (c) return c;
    const A = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    for (let i = 0; i < 6; i++) {
      c = Array.from(crypto.getRandomValues(new Uint8Array(10)), (x) => A[x % 32]).join("");
      if (!(await st.get("fcode:" + c))) { await st.put({ ["fc:" + uid]: c, ["fcode:" + c]: uid }); return c; }
    }
    throw new Error("code");
  }
  async friends(uid) { return (await this.ctx.storage.get("f:" + uid)) || []; }
  async areFriends(a, b) { return (await this.friends(a)).includes(b); }
  async #befriend(a, b) {
    const st = this.ctx.storage, fa = await this.friends(a), fb = await this.friends(b);
    await st.put({ ["f:" + a]: [...new Set([...fa, b])], ["f:" + b]: [...new Set([...fb, a])] });
  }
  async requests(uid) {
    const ids = (await this.ctx.storage.get("r:" + uid)) || [], m = await this.profiles(ids);
    return ids.filter((i) => m[i]).map((i) => ({ id: i, ...m[i] }));
  }
  // someone enters your code: that sends you a request. If you had already asked them, it is accepted at once.
  async addFriend(uid, code) {
    const st = this.ctx.storage;
    const other = await st.get("fcode:" + code);
    if (!other) return { error: "nocode" };
    if (other === uid) return { error: "self" };
    const mine = await this.friends(uid);
    if (mine.includes(other)) return { error: "already" };
    if (mine.length >= 100 || (await this.friends(other)).length >= 100) return { error: "limit" };
    const inMine = (await st.get("r:" + uid)) || [], inTheirs = (await st.get("r:" + other)) || [];
    const p = (await this.profiles([other]))[other] || {};
    if (inMine.includes(other)) {
      await st.put("r:" + uid, inMine.filter((x) => x !== other));
      await this.#befriend(uid, other);
      return { friend: { id: other, ...p } };
    }
    if (inTheirs.includes(uid)) return { error: "pending" };
    if (inTheirs.length >= 50) return { error: "limit" };
    await st.put("r:" + other, [...inTheirs, uid]);
    return { sent: true, name: p.name || "" };
  }
  async acceptFriend(uid, other) {
    const st = this.ctx.storage, inc = (await st.get("r:" + uid)) || [];
    if (!inc.includes(other)) return { error: "nocode" };
    await st.put("r:" + uid, inc.filter((x) => x !== other));
    await this.#befriend(uid, other);
    const p = (await this.profiles([other]))[other];
    return p ? { friend: { id: other, ...p } } : { error: "nocode" };
  }
  async declineFriend(uid, other) {
    const inc = (await this.ctx.storage.get("r:" + uid)) || [];
    await this.ctx.storage.put("r:" + uid, inc.filter((x) => x !== other));
  }
  async removeFriend(uid, other) {
    const st = this.ctx.storage;
    await st.put({ ["f:" + uid]: (await this.friends(uid)).filter((x) => x !== other), ["f:" + other]: (await this.friends(other)).filter((x) => x !== uid) });
  }
  async friendList(uid) {
    const ids = await this.friends(uid), m = await this.profiles(ids);
    return ids.filter((i) => m[i]).map((i) => ({ id: i, ...m[i] }));
  }

  // 10 code guesses per 10 minutes per person
  async joinAllowed(uid) {
    const k = "j:" + uid, now = Date.now();
    let j = (await this.ctx.storage.get(k)) || { n: 0, t: now };
    if (now - j.t > 600000) j = { n: 0, t: now };
    if (j.n >= 10) return false;
    j.n++;
    await this.ctx.storage.put(k, j);
    return true;
  }
}

/* ---------- router: returns a Response, or null if the path isn't ours ---------- */
const db = (env) => env.LOBBY_DB.get(env.LOBBY_DB.idFromName("main"));
const sidOf = (req) => getCookie(req, "lobby_sid");
const groupStub = (env, gid) => env.GROUP_ROOM.get(env.GROUP_ROOM.idFromString(gid));
const who = async (req, env) => { const tok = sidOf(req); return tok ? await db(env).session(tok) : null; };
const sameOrigin = (req, url) => { const o = req.headers.get("Origin"); return !o || o === url.origin; };

export async function handleLobby(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const ours = path.startsWith("/api/auth/") || path.startsWith("/api/avatar/") || path.startsWith("/api/group/") || path.startsWith("/api/groups") || path.startsWith("/api/friends") || path.startsWith("/api/dm/") || path === "/api/room/ws" || path === "/api/ice";
  if (!ours) return null;
  if (!env.LOBBY_DB || !env.CHAT_ROOM || !env.GROUP_ROOM || !env.DM_ROOM) return reply({ error: "Durable Objects not configured" }, 500);

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

  /* profile pictures (anyone can view; ids are unguessable) */
  let g = path.match(/^\/api\/avatar\/([0-9a-f-]{36})$/);
  if (g) {
    const data = await db(env).getAvatar(g[1]);
    if (!data) return new Response("Not found", { status: 404 });
    return imgResponse(data, url.searchParams.has("v") ? "public, max-age=31536000, immutable" : "public, max-age=300");
  }

  /* everything from here needs a logged-in user */
  const me = await who(request, env);

  /* group chat socket + group picture */
  g = path.match(/^\/api\/group\/([0-9a-f]{64})\/(ws|pic)$/);
  if (g) {
    if (!me) return new Response("Log in first", { status: 401 });
    const stub = groupStub(env, g[1]);
    if (g[2] === "pic") {
      if (!(await stub.isMember(me.id))) return new Response("Not found", { status: 404 });
      const data = await stub.getPic();
      if (!data) return new Response("Not found", { status: 404 });
      return imgResponse(data, "private, max-age=31536000, immutable");
    }
    if (request.headers.get("Upgrade") !== "websocket") return new Response("Expected WebSocket", { status: 426 });
    if (!sameOrigin(request, url)) return new Response("Bad origin", { status: 403 });
    const h = new Headers({ Upgrade: "websocket", "X-Lobby-User": encodeURIComponent(JSON.stringify({ id: me.id, name: me.name, pic: me.pic })) });
    return stub.fetch(new Request("https://room/ws", { headers: h }));
  }

  /* private chat with a friend */
  g = path.match(/^\/api\/dm\/([0-9a-f-]{36})\/ws$/);
  if (g) {
    if (!me) return new Response("Log in first", { status: 401 });
    if (request.headers.get("Upgrade") !== "websocket") return new Response("Expected WebSocket", { status: 426 });
    if (!sameOrigin(request, url)) return new Response("Bad origin", { status: 403 });
    if (!(await db(env).areFriends(me.id, g[1]))) return new Response("Not friends", { status: 403 });
    const h = new Headers({ Upgrade: "websocket", "X-Lobby-User": encodeURIComponent(JSON.stringify({ id: me.id, name: me.name, pic: me.pic })) });
    return env.DM_ROOM.get(env.DM_ROOM.idFromName("dm:" + [me.id, g[1]].sort().join(":"))).fetch(new Request("https://room/ws", { headers: h }));
  }

  /* friends */
  if (path === "/api/friends" && request.method === "GET") {
    if (!me) return reply({ error: "auth" }, 401);
    const friends = await db(env).friendList(me.id);
    await Promise.all(friends.map(async (f) => {
      try { f.last = await env.DM_ROOM.get(env.DM_ROOM.idFromName("dm:" + [me.id, f.id].sort().join(":"))).lastOf(); } catch {}
    }));
    return reply({ friends, requests: await db(env).requests(me.id) });
  }
  if (path === "/api/friends/code" && request.method === "GET") {
    if (!me) return reply({ error: "auth" }, 401);
    return reply({ code: await db(env).friendCode(me.id) });
  }

  /* my groups */
  if (path === "/api/groups" && request.method === "GET") {
    if (!me) return reply({ error: "auth" }, 401);
    const ids = await db(env).groups(me.id);
    const views = await Promise.all(ids.map(async (gid) => { try { return await groupStub(env, gid).view(me.id, false); } catch { return undefined; } }));
    const groups = [];
    views.forEach((v, i) => { if (v) groups.push(v); else if (v === null) db(env).removeGroup(me.id, ids[i]); });
    let global = null;
    try { global = await env.CHAT_ROOM.get(env.CHAT_ROOM.idFromName("main")).lastOf(); } catch {}
    return reply({ groups, global });
  }

  /* voice call servers (STUN always; TURN too if Cloudflare TURN keys are set) */
  if (path === "/api/ice") {
    if (!me) return reply({ error: "auth" }, 401);
    let iceServers = [{ urls: "stun:stun.cloudflare.com:3478" }, { urls: "stun:stun.l.google.com:19302" }];
    if (env.TURN_KEY_ID && env.TURN_KEY_API_TOKEN) {
      try {
        const r = await fetch(`https://rtc.live.cloudflare.com/v1/turn/keys/${env.TURN_KEY_ID}/credentials/generate-ice-servers`, {
          method: "POST",
          headers: { Authorization: `Bearer ${env.TURN_KEY_API_TOKEN}`, "Content-Type": "application/json" },
          body: JSON.stringify({ ttl: 3600 }),
        });
        const j = await r.json();
        if (Array.isArray(j.iceServers) && j.iceServers.length) iceServers = j.iceServers;
      } catch {}
    }
    return reply({ iceServers });
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
    if (!me) return reply({ error: "auth" }, 401);
    const u = await db(env).setName(me.id, body.name);
    return u ? reply({ user: u }) : reply({ error: "name" }, 400);
  }
  if (path === "/api/auth/avatar") {
    if (!me) return reply({ error: "auth" }, 401);
    if (typeof body.data !== "string" || !IMG_RE.test(body.data) || body.data.length > MAX_AVATAR) return reply({ error: "image" }, 400);
    if (!(await moderateImage(env, body.data)).ok) return reply({ error: "blocked" }, 400);
    const r = await db(env).setAvatar(me.id, body.data);
    return r.error ? reply({ error: r.error }, 400) : reply({ user: r.user });
  }

  if (path === "/api/friends/add") {
    if (!me) return reply({ error: "auth" }, 401);
    if (!(await db(env).joinAllowed(me.id))) return reply({ error: "rate" }, 429);
    const code = String(body.code || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
    const r = code.length === 10 ? await db(env).addFriend(me.id, code) : { error: "nocode" };
    return r.error ? reply({ error: r.error }, 400) : reply(r);
  }
  if (path === "/api/friends/accept" || path === "/api/friends/decline") {
    if (!me) return reply({ error: "auth" }, 401);
    const id = String(body.id || "").slice(0, 40);
    if (path.endsWith("decline")) { await db(env).declineFriend(me.id, id); return reply({ ok: true }); }
    const r = await db(env).acceptFriend(me.id, id);
    return r.error ? reply({ error: r.error }, 400) : reply(r);
  }
  if (path === "/api/friends/remove") {
    if (!me) return reply({ error: "auth" }, 401);
    await db(env).removeFriend(me.id, String(body.id || "").slice(0, 40));
    return reply({ ok: true });
  }

  /* groups */
  if (path.startsWith("/api/group")) {
    if (!me) return reply({ error: "auth" }, 401);
    const fail = (r) => reply({ error: r.error }, r.error === "perm" ? 403 : r.error === "nocode" ? 404 : 400);

    if (path === "/api/groups/create") {
      if ((await db(env).groups(me.id)).length >= 15) return reply({ error: "limit" }, 400);
      const stub = env.GROUP_ROOM.get(env.GROUP_ROOM.newUniqueId());
      const r = await stub.init(me.id, me.name, body.name);
      if (r.error) return fail(r);
      if (typeof body.pic === "string" && body.pic) {
        const p = await stub.setPic(me.id, body.pic);
        if (p.view) r.view = p.view; else r.picError = p.error;
      }
      return reply(r);
    }
    if (path === "/api/groups/join") {
      if (!(await db(env).joinAllowed(me.id))) return reply({ error: "rate" }, 429);
      const code = String(body.code || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
      const gid = code.length === 12 ? await db(env).lookup(code) : null;
      if (!gid) return reply({ error: "nocode" }, 404);
      if (!(await groupStub(env, gid).isMember(me.id)) && (await db(env).groups(me.id)).length >= 15) return reply({ error: "limit" }, 400);
      const r = await groupStub(env, gid).join(me.id, me.name);
      return r.error ? fail(r) : reply(r);
    }
    const g = path.match(/^\/api\/group\/([0-9a-f]{64})\/(rename|pic|role|kick|leave|regen|destroy)$/);
    if (g) {
      const stub = groupStub(env, g[1]);
      const id = (x) => String(x || "").slice(0, 64);
      let r;
      switch (g[2]) {
        case "rename": r = await stub.rename(me.id, body.name); break;
        case "pic": r = await stub.setPic(me.id, body.data); break;
        case "role": r = await stub.setRole(me.id, id(body.target), body.role); break;
        case "kick": r = await stub.kick(me.id, id(body.target)); break;
        case "leave": r = await stub.leave(me.id); break;
        case "regen": r = await stub.regen(me.id); break;
        case "destroy": r = await stub.destroy(me.id); break;
      }
      return r.error ? fail(r) : reply(r);
    }
  }
  return reply({ error: "not found" }, 404);
}
