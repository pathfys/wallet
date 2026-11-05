// Order chat: text + image evidence (JPEG/PNG only, metadata stripped),
// realtime push over WebSocket with single-use tickets.
import { WebSocketServer } from "ws";
import { mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { HttpError, bad, forbidden, notFound, tooMany, v, randomId, now } from "./util.js";
import { selfOrigin } from "./http.js";

// ---------------------------------------------------------------- images
export function sanitizeImage(buf) {
  if (buf.length < 64) throw bad("bad_image", "Файл повреждён");
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return { mime: "image/jpeg", data: stripJpeg(buf) };
  if (buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return { mime: "image/png", data: stripPng(buf) };
  throw bad("bad_image", "Поддерживаются только JPEG и PNG");
}
function stripJpeg(b) {
  const out = [b.subarray(0, 2)];
  let i = 2;
  while (i + 4 <= b.length) {
    if (b[i] !== 0xff) throw bad("bad_image", "Файл повреждён");
    const m = b[i + 1];
    if (m === 0xd9) { out.push(b.subarray(i, i + 2)); return Buffer.concat(out); }
    if (m === 0xda) { out.push(b.subarray(i)); return Buffer.concat(out); }       // start of scan: rest is image data
    if (m >= 0xd0 && m <= 0xd7 || m === 0x01) { out.push(b.subarray(i, i + 2)); i += 2; continue; }
    const len = b.readUInt16BE(i + 2);
    if (len < 2 || i + 2 + len > b.length) throw bad("bad_image", "Файл повреждён");
    const drop = m === 0xe1 || m === 0xed || m === 0xfe || (m >= 0xe3 && m <= 0xef && m !== 0xee); // EXIF/XMP, IPTC, comments, vendor APPn
    if (!drop) out.push(b.subarray(i, i + 2 + len));
    i += 2 + len;
  }
  throw bad("bad_image", "Файл повреждён");
}
function stripPng(b) {
  const out = [b.subarray(0, 8)];
  let i = 8, first = true;
  while (i + 12 <= b.length) {
    const len = b.readUInt32BE(i), type = b.toString("latin1", i + 4, i + 8);
    if (len > b.length || i + 12 + len > b.length) throw bad("bad_image", "Файл повреждён");
    if (first && type !== "IHDR") throw bad("bad_image", "Файл повреждён");
    first = false;
    if (!["tEXt", "zTXt", "iTXt", "eXIf", "tIME"].includes(type)) out.push(b.subarray(i, i + 12 + len));
    i += 12 + len;
    if (type === "IEND") return Buffer.concat(out);
  }
  throw bad("bad_image", "Файл повреждён");
}

// ---------------------------------------------------------------- realtime hub
export function makeHub() {
  const conns = new Map(); // userId -> Set<ws>
  const tickets = new Map(); // ticket -> { userId, exp }
  return {
    conns, tickets,
    issue(userId) {
      if (tickets.size > 50_000) for (const [k, t] of tickets) if (t.exp < now()) tickets.delete(k);
      const t = randomId(24);
      tickets.set(t, { userId, exp: now() + 30_000 });
      return t;
    },
    redeem(t) { const x = tickets.get(t); tickets.delete(t); return x && x.exp > now() ? x.userId : null; },
    add(userId, ws) { let s = conns.get(userId); if (!s) conns.set(userId, (s = new Set())); s.add(ws); },
    remove(userId, ws) { const s = conns.get(userId); if (s) { s.delete(ws); if (!s.size) conns.delete(userId); } },
    count: (userId) => conns.get(userId)?.size || 0,
    online: (userId) => (conns.get(userId)?.size || 0) > 0,
    toUsers(ids, ev) {
      const data = JSON.stringify(ev);
      for (const id of new Set(ids)) for (const ws of conns.get(id) || []) if (ws.readyState === 1 && ws.bufferedAmount < 1_000_000) ws.send(data);
    },
  };
}

export function attachWs(server, ctx) {
  const { cfg, hub, limiter, log } = ctx;
  const allowed = new Set(cfg.allowedOrigins);
  const wss = new WebSocketServer({ noServer: true, maxPayload: 1024, perMessageDeflate: false, clientTracking: true });
  server.on("upgrade", (req, socket, head) => {
    const reject = (code, text) => { socket.write(`HTTP/1.1 ${code} ${text}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`); socket.destroy(); };
    try {
      const url = new URL(req.url, "http://x");
      if (url.pathname !== "/api/ws") return reject(404, "Not Found");
      const ip = ctx.clientIp(req);
      if (!limiter.take("wsip:" + ip, 20, 60_000)) return reject(429, "Too Many Requests");
      const origin = req.headers.origin;
      if (origin && !allowed.has(origin) && origin !== selfOrigin(req, cfg.trustProxy)) return reject(403, "Forbidden");
      const userId = hub.redeem(String(url.searchParams.get("ticket") || ""));
      if (!userId) return reject(401, "Unauthorized");
      if (hub.count(userId) >= 3) return reject(429, "Too Many Connections");
      wss.handleUpgrade(req, socket, head, (ws) => {
        ws.isAlive = true;
        hub.add(userId, ws);
        ws.on("pong", () => { ws.isAlive = true; });
        ws.on("message", (data) => {                     // client only sends pings; anything else is dropped
          if (!limiter.take("wsmsg:" + userId, 10, 10_000)) return ws.terminate();
          if (String(data) === "ping") ws.send("pong");
        });
        ws.on("close", () => hub.remove(userId, ws));
        ws.on("error", () => hub.remove(userId, ws));
        ws.send(JSON.stringify({ t: "hello" }));
      });
    } catch (e) { log.warn("ws upgrade", { err: String(e) }); reject(400, "Bad Request"); }
  });
  const iv = setInterval(() => {
    for (const ws of wss.clients) { if (!ws.isAlive) { ws.terminate(); continue; } ws.isAlive = false; try { ws.ping(); } catch {} }
  }, 30_000);
  iv.unref();
  return wss;
}

// ---------------------------------------------------------------- routes
export function registerChat(router, ctx) {
  const { cfg, db, hub, bot, limiter } = ctx;
  const filesDir = join(cfg.dataDir, "files");
  mkdirSync(filesDir, { recursive: true });

  function canPost(o, user) {
    const closedAt = o.completed_at || o.cancelled_at;
    if (closedAt && now() - closedAt > ctx.CHAT_AFTER_CLOSE) throw forbidden("Чат закрыт");
    if (user.role !== "admin" && o.buyer_id !== user.id && o.seller_id !== user.id) throw forbidden();
  }
  function msgView(m, user, o) {
    let from = "system";
    if (m.sender_id) from = m.support ? "support" : m.sender_id === user.id ? "me" : "peer";
    if (user.role === "admin" && m.sender_id && !m.support) from = m.sender_id === o.buyer_id ? "buyer" : "seller";
    return { id: m.id, orderId: m.order_id, kind: m.kind, body: m.body, fileId: m.file_id || null, from, createdAt: m.created_at };
  }
  function deliver(o, row, senderId) {
    for (const uid of ctx.participants(o)) {
      const u = db.get("SELECT id, role FROM users WHERE id=?", uid);
      hub.toUsers([uid], { t: "msg", orderId: o.id, message: msgView(row, u, o) });
    }
    const admins = db.all("SELECT id, role FROM users WHERE role='admin'");
    if (db.get("SELECT 1 x FROM appeals WHERE order_id=? AND status='open'", o.id)) for (const a of admins) if (a.id !== senderId) hub.toUsers([a.id], { t: "msg", orderId: o.id, message: msgView(row, a, o) });
    // offline counterpart -> bot ping, at most every 2 minutes per order
    const peer = ctx.participants(o).filter((x) => x !== senderId);
    if (now() - o.last_notify_msg_at > 120_000 && peer.some((p) => !hub.online(p))) {
      db.run("UPDATE orders SET last_notify_msg_at=? WHERE id=?", now(), o.id);
      for (const p of peer) if (!hub.online(p)) bot.notify(p, `Новое сообщение в чате ордера #${o.id}`, cfg.tgAppLink ? `${cfg.tgAppLink}?startapp=order_${o.id}` : "");
    }
  }

  router.get("/api/orders/:id/messages", {}, ({ user, params, query }) => {
    const o = ctx.orderFor(user, params.id);
    const after = v.int(query.get("after") || 0, "after", { min: 0 });
    const rows = db.all("SELECT * FROM messages WHERE order_id=? AND id>? ORDER BY id LIMIT 300", o.id, after);
    return { items: rows.map((m) => msgView(m, user, o)) };
  });
  router.post("/api/orders/:id/messages", {}, ({ user, params, body }) => {
    const o = ctx.orderFor(user, params.id);
    canPost(o, user);
    if (!limiter.take(`chat:${user.id}`, 20, 60_000) || !limiter.take(`chat:${user.id}:${o.id}`, 5, 5_000)) throw tooMany("Слишком часто, подождите немного");
    const text = v.str(body.text, "Сообщение", { min: 1, max: 1000, multiline: true });
    const support = user.role === "admin" && o.buyer_id !== user.id && o.seller_id !== user.id ? 1 : 0;
    const r = db.run("INSERT INTO messages(order_id,sender_id,kind,body,support,created_at) VALUES(?,?,?,?,?,?)", o.id, user.id, "text", text, support, now());
    const row = db.get("SELECT * FROM messages WHERE id=?", Number(r.lastInsertRowid));
    deliver(o, row, user.id);
    return msgView(row, user, o);
  });
  router.post("/api/orders/:id/files", { raw: true, maxBody: 3 * 1024 * 1024 }, ({ user, params, rawBody, headers }) => {
    const o = ctx.orderFor(user, params.id);
    canPost(o, user);
    if (!limiter.take(`upload:${user.id}`, 10, 600_000)) throw tooMany("Слишком много файлов, подождите");
    if (!/^image\/(jpeg|png)$/.test(headers["content-type"] || "")) throw new HttpError(415, "bad_type", "Поддерживаются только JPEG и PNG");
    const img = sanitizeImage(rawBody);
    const id = randomId(18);
    writeFileSync(join(filesDir, id), img.data, { flag: "wx", mode: 0o600 });
    db.run("INSERT INTO files(id,order_id,uploader_id,mime,size,sha256,created_at) VALUES(?,?,?,?,?,?,?)", id, o.id, user.id, img.mime, img.data.length, createHash("sha256").update(img.data).digest("hex"), now());
    const support = user.role === "admin" && o.buyer_id !== user.id && o.seller_id !== user.id ? 1 : 0;
    const r = db.run("INSERT INTO messages(order_id,sender_id,kind,body,file_id,support,created_at) VALUES(?,?,?,?,?,?,?)", o.id, user.id, "image", "", id, support, now());
    const row = db.get("SELECT * FROM messages WHERE id=?", Number(r.lastInsertRowid));
    deliver(o, row, user.id);
    return msgView(row, user, o);
  });
  router.get("/api/files/:id", {}, ({ user, params }) => {
    const id = String(params.id);
    if (!/^[A-Za-z0-9_-]{24}$/.test(id)) throw notFound();
    const f = db.get("SELECT * FROM files WHERE id=?", id);
    if (!f) throw notFound();
    ctx.orderFor(user, f.order_id); // participant or admin only
    return { __file: true, mime: f.mime, data: readFileSync(join(filesDir, id)) };
  });
  router.post("/api/ws-ticket", { limit: { key: "wst", n: 30, ms: 60_000 } }, ({ user }) => ({ ticket: hub.issue(user.id) }));
}
