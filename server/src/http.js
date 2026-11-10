// Hardened HTTP layer: strict routing, bounded bodies, timeouts, CORS
// allowlist, security headers, per-IP/per-user rate limits, signed-session auth.
import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, join, normalize, sep } from "node:path";
import { createHash } from "node:crypto";
import { HttpError, tooMany } from "./util.js";
import { verifyRequestSig, SKEW_MS } from "./security.js";

const API_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Frame-Options": "DENY",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
  "Cross-Origin-Resource-Policy": "same-site",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
};

export function makeRouter() {
  const routes = [];
  const add = (method, path, opts, handler) => {
    const keys = [];
    const re = new RegExp("^" + path.replace(/:(\w+)/g, (_, k) => { keys.push(k); return "([^/]+)"; }) + "$");
    routes.push({ method, re, keys, handler, auth: opts.auth || "session", maxBody: opts.maxBody || 32 * 1024, raw: !!opts.raw, limit: opts.limit });
  };
  return {
    routes,
    get: (p, o, h) => add("GET", p, o, h),
    post: (p, o, h) => add("POST", p, o, h),
    del: (p, o, h) => add("DELETE", p, o, h),
    match(method, path) {
      for (const r of routes) {
        if (r.method !== method) continue;
        const m = r.re.exec(path);
        if (m) {
          const params = {};
          try { r.keys.forEach((k, i) => { params[k] = decodeURIComponent(m[i + 1]); }); }
          catch { throw new HttpError(400, "bad_path", "Некорректный адрес"); }
          return { r, params };
        }
      }
      return null;
    },
  };
}

function readBody(req, max) {
  return new Promise((resolve, reject) => {
    const len = Number(req.headers["content-length"] || 0);
    if (len > max) return reject(new HttpError(413, "too_large", "Слишком большой запрос"));
    const chunks = []; let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > max) { reject(new HttpError(413, "too_large", "Слишком большой запрос")); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

export function clientIp(req, trustProxy) {
  if (trustProxy) {
    const real = req.headers["x-real-ip"];
    if (typeof real === "string" && /^[0-9a-f.:]{3,45}$/i.test(real)) return real;
  }
  return req.socket.remoteAddress || "0.0.0.0";
}

// same-origin requests (frontend served by this server) also carry an Origin header
export function selfOrigin(req, trustProxy) {
  const host = req.headers.host;
  if (!host || !/^[a-z0-9.-]+(:\d+)?$/i.test(host)) return null;
  const xf = trustProxy ? String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim() : "";
  const proto = xf === "https" || xf === "http" ? xf : req.socket.encrypted ? "https" : "http";
  return `${proto}://${host}`;
}

const STATIC_TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".png": "image/png", ".svg": "image/svg+xml", ".json": "application/json", ".ico": "image/x-icon", ".webmanifest": "application/manifest+json" };
const STATIC_ALLOW = /^\/(index\.html|vendor\/[A-Za-z0-9._-]+\.js|icons\/[A-Za-z0-9 ._-]+\.png)?$/;

export function makeServer(ctx, router) {
  const { cfg, db, limiter, nonces, log } = ctx;
  const allowed = new Set(cfg.allowedOrigins);

  async function authSession(req, url, body, ip) {
    const auth = req.headers.authorization || "";
    const m = /^Bearer ([A-Za-z0-9_-]{30,80})$/.exec(auth);
    if (!m) throw new HttpError(401, "no_session", "Требуется вход");
    const hash = createHash("sha256").update(m[1]).digest("hex");
    const sess = db.get("SELECT * FROM sessions WHERE token_hash=?", hash);
    if (!sess || sess.expires_at < Date.now()) throw new HttpError(401, "session_expired", "Сессия истекла");
    const ts = Number(req.headers["x-pmr-ts"]), nonce = String(req.headers["x-pmr-nonce"] || ""), sig = String(req.headers["x-pmr-sig"] || "");
    if (!Number.isSafeInteger(ts) || Math.abs(Date.now() - ts) > SKEW_MS) throw new HttpError(401, "bad_timestamp", "Неверное время устройства — проверьте часы");
    if (!/^[A-Za-z0-9_-]{16,64}$/.test(nonce)) throw new HttpError(401, "bad_nonce", "Некорректный запрос");
    if (!verifyRequestSig(sess, { method: req.method, pathQuery: url.pathname + url.search, ts, nonce, sig, body })) throw new HttpError(401, "bad_signature", "Подпись запроса неверна");
    if (nonces.seen(hash + ":" + nonce, ts)) throw new HttpError(409, "replay", "Повторный запрос отклонён");
    const user = db.get("SELECT * FROM users WHERE id=?", sess.user_id);
    if (!user) throw new HttpError(401, "no_session", "Требуется вход");
    if (!limiter.take("u:" + user.id, 240, 60_000)) throw tooMany();
    ctx.touch(user.id);
    return { sess, user, tokenHash: hash };
  }

  async function serveStatic(req, res, url) {
    if (!cfg.staticDir || (req.method !== "GET" && req.method !== "HEAD")) return false;
    let p; try { p = decodeURIComponent(url.pathname); } catch { return false; }
    if (!STATIC_ALLOW.test(p)) return false;
    const file = normalize(join(cfg.staticDir, p === "/" ? "index.html" : p));
    if (!file.startsWith(cfg.staticDir + sep)) return false;
    try { if (!(await stat(file)).isFile()) return false; } catch { return false; }
    const data = await readFile(file);
    const headers = {
      "Content-Type": STATIC_TYPES[extname(file)] || "application/octet-stream",
      "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
      "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
      "Cache-Control": extname(file) === ".html" ? "no-cache" : "public, max-age=3600",
      "Permissions-Policy": "geolocation=(), microphone=(), payment=(), usb=()",
    };
    if (extname(file) === ".html") headers["Content-Security-Policy"] = "frame-ancestors 'self' https://web.telegram.org https://webk.telegram.org https://webz.telegram.org; object-src 'none'; base-uri 'none'";
    res.writeHead(200, headers);
    res.end(req.method === "HEAD" ? undefined : data);
    return true;
  }

  const server = createServer(async (req, res) => {
    const started = Date.now();
    const ip = clientIp(req, cfg.trustProxy);
    let status = 200, code = "";
    const origin = req.headers.origin;
    const self = origin && origin === selfOrigin(req, cfg.trustProxy);
    const corsOk = origin && !self && allowed.has(origin);
    const send = (st, obj, extra = {}) => {
      status = st;
      const h = { ...API_HEADERS, ...extra };
      if (corsOk) { h["Access-Control-Allow-Origin"] = origin; h["Vary"] = "Origin"; }
      res.writeHead(st, h);
      res.end(Buffer.isBuffer(obj) ? obj : JSON.stringify(obj));
    };
    try {
      // per-IP ceiling (mobile CGNAT shares IPs, so it is generous); per-user limits apply after auth
      if (!limiter.take("ip:" + ip, 600, 60_000)) throw tooMany();
      const url = new URL(req.url, "http://x");
      if (url.pathname.length > 256 || url.search.length > 1024) throw new HttpError(414, "uri_too_long", "Слишком длинный адрес");
      if (!url.pathname.startsWith("/api/")) {
        if (await serveStatic(req, res, url)) return;
        throw new HttpError(404, "not_found", "Не найдено");
      }
      if (origin && !corsOk && !self) throw new HttpError(403, "bad_origin", "Источник запроса не разрешён");
      if (req.method === "OPTIONS") {
        return send(204, Buffer.alloc(0), corsOk ? {
          "Access-Control-Allow-Methods": "GET, POST, DELETE",
          "Access-Control-Allow-Headers": "Content-Type, Authorization, X-PMR-Ts, X-PMR-Nonce, X-PMR-Sig",
          "Access-Control-Max-Age": "600",
        } : {});
      }
      const m = router.match(req.method, url.pathname);
      if (!m) throw new HttpError(404, "not_found", "Не найдено");
      const { r, params } = m;
      // public routes (login) are limited per IP; signed routes per account (many users share one mobile IP)
      if (r.limit && r.auth === "public" && !limiter.take(`${r.limit.key}:${ip}`, r.limit.n, r.limit.ms)) throw tooMany();
      const body = req.method === "GET" || req.method === "DELETE" ? Buffer.alloc(0) : await readBody(req, r.maxBody);
      let json = null;
      if (!r.raw && body.length) {
        if (!/^application\/json\b/.test(req.headers["content-type"] || "")) throw new HttpError(415, "bad_type", "Ожидается JSON");
        try { json = JSON.parse(body.toString("utf8")); } catch { throw new HttpError(400, "bad_json", "Некорректный JSON"); }
        if (!json || typeof json !== "object" || Array.isArray(json)) throw new HttpError(400, "bad_json", "Некорректный JSON");
      }
      let a = null;
      if (r.auth !== "public") {
        a = await authSession(req, url, body, ip);
        if (a.user.banned_at && r.auth !== "session-any") throw new HttpError(403, "banned", "Аккаунт заблокирован: " + (a.user.ban_reason || "нарушение правил"));
        if (r.auth === "admin" && a.user.role !== "admin") throw new HttpError(403, "forbidden", "Только для администраторов");
        if (r.limit && !limiter.take(`${r.limit.key}:u${a.user.id}`, r.limit.n, r.limit.ms)) throw tooMany();
      }
      const out = await r.handler({ req, res, ip, url, params, query: url.searchParams, body: json || {}, rawBody: body, user: a?.user, sess: a?.sess, tokenHash: a?.tokenHash, headers: req.headers });
      if (out && out.__file) {
        status = 200;
        const h = { ...API_HEADERS, "Content-Type": out.mime, "Content-Security-Policy": "default-src 'none'; sandbox", "Cache-Control": "private, max-age=600", "Content-Disposition": "inline" };
        if (corsOk) { h["Access-Control-Allow-Origin"] = origin; h["Vary"] = "Origin"; }
        res.writeHead(200, h); res.end(out.data); return;
      }
      send(200, out ?? { ok: true });
    } catch (e) {
      if (e instanceof HttpError) { code = e.code; send(e.status, { error: e.code, message: e.message, ...(e.extra || {}) }); }
      else { code = "internal"; log.error("unhandled", { err: String(e && e.stack || e) }); send(500, { error: "internal", message: "Внутренняя ошибка сервера" }); }
    } finally {
      if (!(status === 200 && req.method === "GET")) log.info("req", { m: req.method, p: (req.url || "").split("?")[0].slice(0, 120), s: status, c: code || undefined, ms: Date.now() - started, ip });
    }
  });
  // Slowloris / resource-exhaustion guards
  server.headersTimeout = 10_000;
  server.requestTimeout = 30_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 60;
  server.maxConnections = 4000;
  server.maxRequestsPerSocket = 1000;
  return server;
}
