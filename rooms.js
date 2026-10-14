/* ---------- rooms: global chat + group chats (history, moderation, voice-call signalling) ---------- */
import { DurableObject } from "cloudflare:workers";
import { moderate, moderateImage } from "./moderation.js";

const HIST = 120;
const MAX_PIC = 150000;
export const IMG_RE = /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/]+={0,2}$/;
export const MAX_AVATAR = MAX_PIC;
const CODE_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no 0/O/1/I
const genCode = () => Array.from(crypto.getRandomValues(new Uint8Array(12)), (x) => CODE_CHARS[x % 32]).join("");
const cleanText = (s, n) => String(s || "").replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, "").slice(0, n);
const cleanName = (s) => String(s || "").replace(/[\u0000-\u001f<>]/g, "").trim().slice(0, 30);
const pad = (n) => String(n).padStart(9, "0");

const REACTIONS = ["\u{1F44D}", "\u2764\uFE0F", "\u{1F602}", "\u{1F62E}", "\u{1F622}", "\u{1F525}"];
function cleanReply(x) {
  if (!x || typeof x !== "object") return null;
  const id = String(x.id || "").replace(/[^0-9a-f-]/gi, "").slice(0, 40);
  if (!id) return null;
  return { id, name: cleanText(x.name, 30).replace(/[<>\n]/g, ""), text: cleanText(x.text, 80).replace(/\n/g, " ") };
}
function cleanAtt(a) {
  if (a && typeof a === "object" && a.kind === "image") return { kind: "image", title: cleanText(a.title, 80).replace(/[<>\n]/g, "").trim(), sub: "", text: "" };
  if (!a || typeof a !== "object" || !["note", "lore", "video"].includes(a.kind)) return null;
  const out = { kind: a.kind, title: cleanText(a.title, 80).replace(/[<>\n]/g, "").trim(), sub: cleanText(a.sub, 80).replace(/[<>\n]/g, ""), text: cleanText(a.text, 4000) };
  if (a.kind === "video" && typeof a.thumb === "string" && a.thumb.length <= 30000 && IMG_RE.test(a.thumb)) out.thumb = a.thumb;
  return out;
}

export function imgResponse(dataUrl, cache) {
  const mime = dataUrl.slice(5, dataUrl.indexOf(";"));
  const bin = atob(dataUrl.slice(dataUrl.indexOf(",") + 1));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new Response(bytes, { headers: { "Content-Type": mime, "Cache-Control": cache, "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'none'" } });
}

class RoomBase extends DurableObject {
  calls = false; // voice calls allowed in this room?

  async allow() { return true; }
  async getImg(id) { return typeof id === "string" ? (await this.ctx.storage.get("i:" + id)) || null : null; }
  async shutdown() { for (const w of this.ctx.getWebSockets()) { try { w.close(1000, "gone"); } catch {} } }
  async lastOf() { return (await this.ctx.storage.get("last")) || null; }
  async initMsg() { return { type: "init", history: await this._hist() }; }

  async _hist() {
    const m = await this.ctx.storage.list({ prefix: "m:", reverse: true, limit: HIST });
    return [...m.values()].reverse();
  }
  async _push(msg) {
    const st = this.ctx.storage;
    const seq = ((await st.get("seq")) || 0) + 1;
    msg.seq = seq;
    const puts = { seq, ["m:" + pad(seq)]: msg };
    if (!msg.sys) puts.last = { uid: msg.uid, name: msg.name, text: String(msg.text || (msg.att ? "📎 " + msg.att.title : "")).slice(0, 60), ts: msg.ts };
    await st.put(puts);
    if (seq > HIST) {
      const k = "m:" + pad(seq - HIST), old = await st.get(k);
      await st.delete(k);
      if (old && old.att && old.att.img) await st.delete("i:" + old.id);
    }
  }
  _all(obj, exclude) {
    const s = JSON.stringify(obj);
    for (const w of this.ctx.getWebSockets()) if (w !== exclude) { try { w.send(s); } catch {} }
  }
  _att(w) { try { return w.deserializeAttachment() || {}; } catch { return {}; } }
  _count(exclude) {
    const ids = new Set(this.ctx.getWebSockets().filter((w) => w !== exclude).map((w) => this._att(w).id));
    this._all({ type: "count", n: ids.size }, exclude);
  }
  _callUsers(exclude) {
    const seen = new Map();
    for (const w of this.ctx.getWebSockets()) {
      if (w === exclude) continue;
      const a = this._att(w);
      if (a.call && !seen.has(a.id)) seen.set(a.id, { id: a.id, name: a.name, pic: a.pic });
    }
    return [...seen.values()];
  }
  _sendCall(exclude) { this._all({ type: "call", users: this._callUsers(exclude) }, exclude); }

  async fetch(req) {
    let user;
    try { user = JSON.parse(decodeURIComponent(req.headers.get("X-Lobby-User") || "")); } catch { return new Response("No user", { status: 401 }); }
    if (!user || !user.id || !(await this.allow(user))) return new Response("Forbidden", { status: 403 });
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server);
    server.serializeAttachment({ id: user.id, name: user.name, pic: user.pic, last: 0, call: false });
    server.send(JSON.stringify(await this.initMsg(user)));
    this._count();
    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws, raw) {
    if (typeof raw !== "string" || raw.length > 220000) return;
    let d;
    try { d = JSON.parse(raw); } catch { return; }
    if (!d || typeof d !== "object") return;
    const a = this._att(ws);
    if (d.type === "call-join" && this.calls) return this.#callJoin(ws, a);
    if (d.type === "call-leave") return this.#callLeave(ws, a);
    if (d.type === "rtc") return this.#rtc(ws, a, d);
    if (d.type === "typing") return this.#typing(ws, a);
    if (d.type === "react") return this.#react(a, d);
    return this.#say(ws, a, d);
  }

  #typing(ws, a) {
    const now = Date.now();
    if (now - (a.tt || 0) < 2000) return;
    a.tt = now;
    ws.serializeAttachment(a);
    this._all({ type: "typing", id: a.id, name: a.name }, ws);
  }
  async #react(a, d) {
    const seq = Number(d.seq);
    if (!Number.isInteger(seq) || seq < 1 || !REACTIONS.includes(d.e)) return;
    const key = "m:" + pad(seq), m = await this.ctx.storage.get(key);
    if (!m || m.sys) return;
    m.r = m.r || {};
    const l = m.r[d.e] || [], i = l.indexOf(a.id);
    if (i >= 0) l.splice(i, 1);
    else {
      if ((!m.r[d.e] && Object.keys(m.r).length >= 8) || l.length >= 60) return;
      l.push(a.id);
    }
    if (l.length) m.r[d.e] = l; else delete m.r[d.e];
    await this.ctx.storage.put(key, m);
    this._all({ type: "react", seq, r: m.r });
  }

  async #say(ws, a, d) {
    const text = cleanText(d.text, 500).trim();
    const att = cleanAtt(d.att);
    if (!text && !att) return;
    let imgData = null;
    if (att && att.kind === "image") {
      const dd = d.att.data;
      if (typeof dd !== "string" || dd.length > 150000 || !IMG_RE.test(dd)) { try { ws.send(JSON.stringify({ type: "error", code: "image", cid: typeof d.cid === "string" ? d.cid.slice(0, 24) : "" })); } catch {} return; }
      imgData = dd;
      att.img = true;
    }
    const re = cleanReply(d.reply);
    const cid = typeof d.cid === "string" ? d.cid.slice(0, 24) : "";
    const out = (o) => { try { ws.send(JSON.stringify({ ...o, cid })); } catch {} };
    const now = Date.now();
    if (now - (a.last || 0) < 700) return out({ type: "error", code: "slow" });
    a.last = now;
    ws.serializeAttachment(a);
    const key = "mod:" + a.id;
    const st = (await this.ctx.storage.get(key)) || { s: [], mute: 0 };
    if (st.mute > now) return out({ type: "error", code: "muted" });

    let v = await moderate(this.env, [text, att && att.title, att && att.text].filter(Boolean).join("\n"));
    if (v.ok && att && att.thumb) v = await moderateImage(this.env, att.thumb);
    if (v.ok && imgData) v = await moderateImage(this.env, imgData);
    if (!v.ok) {
      let muted = false;
      if (!v.failed) {
        st.s = st.s.filter((x) => now - x < 10 * 60 * 1000);
        st.s.push(now);
        if (st.s.length >= 3) { st.mute = now + 5 * 60 * 1000; st.s = []; muted = true; } // 3 strikes in 10 min = 5 min mute
        await this.ctx.storage.put(key, st);
      }
      return out({ type: "blocked", reason: v.reason, muted, failed: !!v.failed });
    }
    const msg = { id: crypto.randomUUID(), uid: a.id, name: a.name, pic: a.pic, text, ts: Date.now() };
    if (att) msg.att = att;
    if (re) msg.re = re;
    if (imgData) await this.ctx.storage.put("i:" + msg.id, imgData);
    await this._push(msg);
    this._all({ type: "msg", message: msg, cid });
  }

  #callJoin(ws, a) {
    if (a.call) return;
    const users = this._callUsers();
    if (users.length >= 6) return ws.send(JSON.stringify({ type: "error", code: "callfull" }));
    a.call = true;
    ws.serializeAttachment(a);
    ws.send(JSON.stringify({ type: "call-peers", peers: users.map((u) => u.id).filter((id) => id !== a.id) }));
    this._sendCall();
  }
  #callLeave(ws, a) {
    if (!a.call) return;
    a.call = false;
    ws.serializeAttachment(a);
    this._sendCall();
  }
  #rtc(ws, a, d) {
    if (!a.call || typeof d.to !== "string" || !d.data) return;
    if (JSON.stringify(d.data).length > 8000) return;
    const out = JSON.stringify({ type: "rtc", from: a.id, data: d.data });
    for (const w of this.ctx.getWebSockets()) {
      if (w === ws) continue;
      const b = this._att(w);
      if (b.id === d.to && b.call) { try { w.send(out); } catch {} }
    }
  }

  async webSocketClose(ws) { try { ws.close(); } catch {} this._count(ws); this._sendCall(ws); }
  async webSocketError(ws) { this._count(ws); this._sendCall(ws); }
}

/* private chat between two friends (the router checks they are friends) */
export class DmRoom extends RoomBase { calls = true; }

/* global chat: everybody who is logged in */
export class ChatRoom extends RoomBase {}

/* group chat: one Durable Object per group */
export class GroupRoom extends RoomBase {
  calls = true;
  #db() { return this.env.LOBBY_DB.get(this.env.LOBBY_DB.idFromName("main")); }
  #gid() { return this.ctx.id.toString(); }
  async #meta() { return (await this.ctx.storage.get("meta")) || null; }
  async #claim() {
    for (let i = 0; i < 6; i++) { const c = genCode(); if (await this.#db().claimCode(c, this.#gid())) return c; }
    throw new Error("code");
  }
  async #profiles(m) { try { return await this.#db().profiles(Object.keys(m.members)); } catch { return {}; } }
  #kill(uid, payload) {
    for (const w of this.ctx.getWebSockets()) {
      if (uid && this._att(w).id !== uid) continue;
      try { w.send(JSON.stringify(payload)); w.close(1000, "gone"); } catch {}
    }
  }
  async #sys(o) {
    const msg = { id: crypto.randomUUID(), ts: Date.now(), ...o };
    await this._push(msg);
    this._all({ type: "msg", message: msg });
  }
  #build(m, uid, full, prof, last) {
    const ids = Object.keys(m.members), role = m.members[uid].role;
    const out = { id: this.#gid(), name: m.name, picv: m.picv || 0, role, count: ids.length, created: m.created };
    if (last) out.last = last;
    if (full) {
      if (role !== "member") out.code = m.code;
      const rank = { owner: 0, admin: 1, member: 2 };
      out.members = ids
        .map((id) => ({ id, role: m.members[id].role, name: (prof[id] && prof[id].name) || m.members[id].name, pic: (prof[id] && prof[id].pic) || "" }))
        .sort((a, b) => rank[a.role] - rank[b.role] || String(a.name).localeCompare(String(b.name)));
    }
    return out;
  }
  async #refresh() {
    const m = await this.#meta();
    if (!m) return;
    const prof = await this.#profiles(m), last = await this.ctx.storage.get("last");
    for (const w of this.ctx.getWebSockets()) {
      const a = this._att(w);
      if (!a.id || !m.members[a.id]) continue;
      try { w.send(JSON.stringify({ type: "meta", meta: this.#build(m, a.id, true, prof, last) })); } catch {}
    }
  }

  async allow(user) {
    const m = await this.#meta();
    if (!m || !m.members[user.id]) return false;
    if (user.name && m.members[user.id].name !== user.name) { m.members[user.id].name = user.name; await this.ctx.storage.put("meta", m); }
    return true;
  }
  async initMsg(user) {
    return { type: "init", history: await this._hist(), meta: await this.view(user.id, true), call: { users: this._callUsers() } };
  }

  /* ----- RPC methods (called from the router, always with the logged-in user's id) ----- */
  async init(owner, ownerName, name) {
    name = cleanName(name);
    if (!name) return { error: "name" };
    if (!(await moderate(this.env, name)).ok) return { error: "blocked" };
    const code = await this.#claim();
    await this.ctx.storage.put("meta", { name, owner, code, created: Date.now(), picv: 0, kicked: [], members: { [owner]: { role: "owner", name: ownerName, joined: Date.now() } } });
    await this.#db().addGroup(owner, this.#gid());
    return { view: await this.view(owner, true) };
  }
  async view(uid, full) {
    const m = await this.#meta();
    if (!m || !m.members[uid]) return null;
    return this.#build(m, uid, !!full, full ? await this.#profiles(m) : null, await this.ctx.storage.get("last"));
  }
  async isMember(uid) { const m = await this.#meta(); return !!(m && m.members[uid]); }
  async getPic() { return (await this.ctx.storage.get("pic")) || null; }

  async join(uid, name) {
    const m = await this.#meta();
    if (!m) return { error: "nocode" };
    if (m.members[uid]) return { view: await this.view(uid, true) };
    if ((m.kicked || []).includes(uid)) return { error: "kicked" };
    if (Object.keys(m.members).length >= 50) return { error: "full" };
    m.members[uid] = { role: "member", name, joined: Date.now() };
    await this.ctx.storage.put("meta", m);
    await this.#db().addGroup(uid, this.#gid());
    await this.#sys({ sys: "join", a: name });
    await this.#refresh();
    return { view: await this.view(uid, true) };
  }
  async rename(uid, name) {
    let m = await this.#meta();
    if (!m || !m.members[uid] || m.members[uid].role !== "owner") return { error: "perm" };
    name = cleanName(name);
    if (!name) return { error: "name" };
    if (name !== m.name) {
      if (!(await moderate(this.env, name)).ok) return { error: "blocked" };
      m = await this.#meta();
      m.name = name;
      await this.ctx.storage.put("meta", m);
      await this.#sys({ sys: "rename", a: name });
      await this.#refresh();
    }
    return { view: await this.view(uid, true) };
  }
  async setPic(uid, data) {
    let m = await this.#meta();
    if (!m || !m.members[uid] || m.members[uid].role !== "owner") return { error: "perm" };
    if (typeof data !== "string" || !IMG_RE.test(data) || data.length > MAX_PIC) return { error: "image" };
    if (!(await moderateImage(this.env, data)).ok) return { error: "blocked" };
    await this.ctx.storage.put("pic", data);
    m = await this.#meta();
    m.picv = (m.picv || 0) + 1;
    await this.ctx.storage.put("meta", m);
    await this.#refresh();
    return { view: await this.view(uid, true) };
  }
  async setRole(uid, target, role) {
    const m = await this.#meta();
    if (!m || !m.members[uid] || m.members[uid].role !== "owner") return { error: "perm" };
    if (!["admin", "member"].includes(role) || !m.members[target] || m.members[target].role === "owner") return { error: "perm" };
    if (m.members[target].role !== role) {
      m.members[target].role = role;
      await this.ctx.storage.put("meta", m);
      await this.#sys({ sys: "role", a: m.members[target].name, b: role });
      await this.#refresh();
    }
    return { view: await this.view(uid, true) };
  }
  async kick(uid, target) {
    const m = await this.#meta();
    const me = m && m.members[uid], t = m && m.members[target];
    if (!me || !t || target === uid || t.role === "owner") return { error: "perm" };
    if (me.role === "member" || (me.role === "admin" && t.role !== "member")) return { error: "perm" };
    delete m.members[target];
    m.kicked = [...new Set([...(m.kicked || []), target])];
    await this.ctx.storage.put("meta", m);
    await this.#db().removeGroup(target, this.#gid());
    this.#kill(target, { type: "kicked" });
    await this.#sys({ sys: "kick", a: t.name });
    await this.#refresh();
    return { view: await this.view(uid, true) };
  }
  async leave(uid) {
    const m = await this.#meta();
    const me = m && m.members[uid];
    if (!me || me.role === "owner") return { error: "perm" };
    delete m.members[uid];
    await this.ctx.storage.put("meta", m);
    await this.#db().removeGroup(uid, this.#gid());
    this.#kill(uid, { type: "left" });
    await this.#sys({ sys: "leave", a: me.name });
    await this.#refresh();
    return { ok: true };
  }
  async regen(uid) {
    let m = await this.#meta();
    if (!m || !m.members[uid] || m.members[uid].role !== "owner") return { error: "perm" };
    const old = m.code, code = await this.#claim();
    m = await this.#meta();
    m.code = code;
    m.kicked = []; // a fresh code also lets removed people back in
    await this.ctx.storage.put("meta", m);
    await this.#db().freeCode(old);
    await this.#refresh();
    return { view: await this.view(uid, true) };
  }
  async destroy(uid) {
    const m = await this.#meta();
    if (!m || !m.members[uid] || m.members[uid].role !== "owner") return { error: "perm" };
    const db = this.#db(), gid = this.#gid();
    await Promise.all(Object.keys(m.members).map((id) => db.removeGroup(id, gid)));
    await db.freeCode(m.code);
    this.#kill(null, { type: "deleted" });
    await this.ctx.storage.deleteAll();
    return { ok: true };
  }
}
