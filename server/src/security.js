// Authentication & anti-abuse primitives:
//  * Telegram Mini App initData verification (HMAC-SHA256 over the bot token)
//  * sessions bound to a client-generated, non-extractable ECDSA P-256 key
//  * per-request signatures with timestamp + nonce  -> replay protection
//  * token-bucket rate limiting (bounded memory)    -> abuse / DoS protection
//  * AES-256-GCM encryption of personal payment details at rest
//  * nickname rules (profanity, reserved names, homoglyph impersonation)
import { createHmac, createHash, createPublicKey, verify as cverify, timingSafeEqual, randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import { Address, Cell, beginCell, contractAddress } from "@ton/core";
import { HttpError, bad } from "./util.js";

export const sha256hex = (b) => createHash("sha256").update(b).digest("hex");

// ------------------------------------------------------------ Telegram initData
export function verifyInitData(initData, botToken, maxAgeSec, nowSec = Math.floor(Date.now() / 1000)) {
  if (typeof initData !== "string" || initData.length < 20 || initData.length > 4096) throw new HttpError(401, "bad_init_data", "Некорректные данные Telegram");
  const params = new URLSearchParams(initData);
  const hash = params.get("hash") || "";
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new HttpError(401, "bad_init_data", "Некорректные данные Telegram");
  params.delete("hash");
  const check = [...params.entries()].map(([k, v]) => `${k}=${v}`).sort().join("\n");
  const secret = createHmac("sha256", "WebAppData").update(botToken).digest();
  const calc = createHmac("sha256", secret).update(check).digest();
  if (!timingSafeEqual(calc, Buffer.from(hash, "hex"))) throw new HttpError(401, "bad_init_data", "Подпись Telegram не прошла проверку");
  const authDate = Number(params.get("auth_date"));
  if (!Number.isInteger(authDate) || authDate > nowSec + 60 || nowSec - authDate > maxAgeSec)
    throw new HttpError(401, "init_data_expired", "Сессия Telegram устарела — перезапустите приложение");
  let user;
  try { user = JSON.parse(params.get("user") || "null"); } catch { user = null; }
  if (!user || !Number.isSafeInteger(user.id) || user.id <= 0 || user.is_bot) throw new HttpError(401, "bad_init_data", "Нет пользователя Telegram");
  return { user, authDate, hash, startParam: params.get("start_param") || "" };
}

// ------------------------------------------------------------ request signatures
const B64URL = /^[A-Za-z0-9_-]+$/;
export function parseP256(pub) {
  if (!pub || typeof pub !== "object" || pub.kty !== "EC" || pub.crv !== "P-256") throw bad("bad_key", "Некорректный ключ сессии");
  const { x, y } = pub;
  if (typeof x !== "string" || typeof y !== "string" || x.length !== 43 || y.length !== 43 || !B64URL.test(x) || !B64URL.test(y)) throw bad("bad_key", "Некорректный ключ сессии");
  try { createPublicKey({ key: { kty: "EC", crv: "P-256", x, y }, format: "jwk" }); } catch { throw bad("bad_key", "Некорректный ключ сессии"); }
  return { x, y };
}
const keyCache = new Map();
function p256Key(x, y) {
  const k = x + "." + y;
  let key = keyCache.get(k);
  if (!key) {
    key = createPublicKey({ key: { kty: "EC", crv: "P-256", x, y }, format: "jwk" });
    if (keyCache.size > 5000) keyCache.clear();
    keyCache.set(k, key);
  }
  return key;
}
export function canonical(method, pathQuery, ts, nonce, bodyHashHex) {
  return `${method.toUpperCase()}\n${pathQuery}\n${ts}\n${nonce}\n${bodyHashHex}`;
}
export function verifyRequestSig(sess, { method, pathQuery, ts, nonce, sig, body }) {
  const str = canonical(method, pathQuery, ts, nonce, sha256hex(body || Buffer.alloc(0)));
  let raw;
  try { raw = Buffer.from(sig, "base64url"); } catch { return false; }
  if (raw.length !== 64) return false;
  return cverify("sha256", Buffer.from(str), { key: p256Key(sess.pub_x, sess.pub_y), dsaEncoding: "ieee-p1363" }, raw);
}

// replay window: each (session, nonce) is accepted once within +-SKEW of server time
export const SKEW_MS = 60_000;
// Persistent variant: nonces live in SQLite, so a request captured before a
// server restart cannot be replayed after it (the in-memory cache would be empty).
export class DbNonceCache {
  constructor(db) { this.db = db; }
  seen(key, ts) {
    const exp = Math.max(Number(ts) || 0, Date.now()) + 2 * SKEW_MS;
    return this.db.run("INSERT OR IGNORE INTO nonces(k, exp) VALUES(?, ?)", key, exp).changes === 0;
  }
  sweep() { this.db.run("DELETE FROM nonces WHERE exp<?", Date.now()); }
}

export class NonceCache {
  constructor(max = 500_000) { this.max = max; this.map = new Map(); }
  seen(key, ts) {
    const t = Date.now();
    if (this.map.has(key)) return true;
    if (this.map.size >= this.max) this.sweep(true);
    this.map.set(key, ts + 2 * SKEW_MS);
    return false;
  }
  sweep(force = false) {
    const t = Date.now();
    for (const [k, exp] of this.map) if (exp < t || (force && this.map.size > this.max * 0.8)) this.map.delete(k);
  }
}

// ------------------------------------------------------------ rate limiting
export class RateLimiter {
  constructor(max = 200_000) { this.max = max; this.b = new Map(); }
  // capacity tokens, refilled at capacity/perMs; returns true if allowed
  take(key, capacity, perMs, cost = 1) {
    const t = Date.now();
    let s = this.b.get(key);
    if (!s) {
      if (this.b.size >= this.max) this.sweep(t, true);
      s = { tok: capacity, t };
      this.b.set(key, s);
    }
    s.tok = Math.min(capacity, s.tok + ((t - s.t) * capacity) / perMs);
    s.t = t;
    if (s.tok < cost) return false;
    s.tok -= cost;
    return true;
  }
  sweep(t = Date.now(), force = false) {
    for (const [k, s] of this.b) if (t - s.t > 3_600_000 || force) { this.b.delete(k); if (force && this.b.size < this.max * 0.5) break; }
  }
}

// ------------------------------------------------------------ PII at rest
export function encryptJson(key, obj, aad) {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, iv);
  c.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([c.update(JSON.stringify(obj), "utf8"), c.final()]);
  return "v1:" + Buffer.concat([iv, c.getAuthTag(), ct]).toString("base64");
}
export function decryptJson(key, s, aad) {
  if (typeof s !== "string" || !s.startsWith("v1:")) throw new Error("bad ciphertext");
  const raw = Buffer.from(s.slice(3), "base64");
  const d = createDecipheriv("aes-256-gcm", key, raw.subarray(0, 12));
  d.setAAD(Buffer.from(aad));
  d.setAuthTag(raw.subarray(12, 28));
  return JSON.parse(Buffer.concat([d.update(raw.subarray(28)), d.final()]).toString("utf8"));
}

// ------------------------------------------------------------ wallet ownership proof
// Standard wallet v4r2 (same code and initial data as @ton/ton WalletContractV4, workchain 0).
const WALLET_V4R2_CODE = Cell.fromBoc(Buffer.from("te6ccgECFAEAAtQAART/APSkE/S88sgLAQIBIAIDAgFIBAUE+PKDCNcYINMf0x/THwL4I7vyZO1E0NMf0x/T//QE0VFDuvKhUVG68qIF+QFUEGT5EPKj+AAkpMjLH1JAyx9SMMv/UhD0AMntVPgPAdMHIcAAn2xRkyDXSpbTB9QC+wDoMOAhwAHjACHAAuMAAcADkTDjDQOkyMsfEssfy/8QERITAubQAdDTAyFxsJJfBOAi10nBIJJfBOAC0x8hghBwbHVnvSKCEGRzdHK9sJJfBeAD+kAwIPpEAcjKB8v/ydDtRNCBAUDXIfQEMFyBAQj0Cm+hMbOSXwfgBdM/yCWCEHBsdWe6kjgw4w0DghBkc3RyupJfBuMNBgcCASAICQB4AfoA9AQw+CdvIjBQCqEhvvLgUIIQcGx1Z4MesXCAGFAEywUmzxZY+gIZ9ADLaRfLH1Jgyz8gyYBA+wAGAIpQBIEBCPRZMO1E0IEBQNcgyAHPFvQAye1UAXKwjiOCEGRzdHKDHrFwgBhQBcsFUAPPFiP6AhPLassfyz/JgED7AJJfA+ICASAKCwBZvSQrb2omhAgKBrkPoCGEcNQICEekk30pkQzmkD6f+YN4EoAbeBAUiYcVnzGEAgFYDA0AEbjJftRNDXCx+AA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYAIBIA4PABmtznaiaEAga5Drhf/AABmvHfaiaEAQa5DrhY/AAG7SB/oA1NQi+QAFyMoHFcv/ydB3dIAYyMsFywIizxZQBfoCFMtrEszMyXP7AMhAFIEBCPRR8qcCAHCBAQjXGPoA0z/IVCBHgQEI9FHyp4IQbm90ZXB0gBjIywXLAlAGzxZQBPoCFMtqEssfyz/Jc/sAAgBsgQEI1xj6ANM/MFIkgQEI9Fnyp4IQZHN0cnB0gBjIywXLAlAFzxZQA/oCE8tqyx8Syz/Jc/sAAAr0AMntVA==", "base64"))[0];
export function walletV4Address(publicKey) {
  const data = beginCell().storeUint(0, 32).storeUint(698983191, 32).storeBuffer(Buffer.from(publicKey), 32).storeBit(false).endCell();
  return contractAddress(0, { code: WALLET_V4R2_CODE, data });
}
export const bindMessage = (challenge, userId, rawAddress) => Buffer.from(`pmr-wallet-bind:v1:${challenge}:${userId}:${rawAddress}`);
export function verifyWalletProof({ address, publicKeyHex, signatureB64, challenge, userId }) {
  let addr;
  try { addr = Address.parse(String(address)); } catch { throw bad("bad_address", "Некорректный адрес"); }
  if (!/^[0-9a-f]{64}$/i.test(String(publicKeyHex))) throw bad("bad_key", "Некорректный публичный ключ");
  const pub = Buffer.from(publicKeyHex, "hex");
  const expected = walletV4Address(pub);
  if (!expected.equals(addr)) throw bad("wallet_mismatch", "Ключ не соответствует адресу кошелька (поддерживается WalletV4R2)");
  const sig = Buffer.from(String(signatureB64 || ""), "base64");
  if (sig.length !== 64) throw bad("bad_signature", "Некорректная подпись");
  const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), pub]);
  const ok = cverify(null, bindMessage(challenge, userId, addr.toRawString()), createPublicKey({ key: der, format: "der", type: "spki" }), sig);
  if (!ok) throw bad("bad_signature", "Подпись кошелька не прошла проверку");
  return addr;
}

// ------------------------------------------------------------ nicknames
const BAD_ROOTS = [
  "хуй","хуе","хуя","хуи","хуё","пизд","пизж","пезд","ебан","ебат","ебах","ебал","ебуч","ёбан","ёбну","заеб","наеб","проеб","выеб","отъеб",
  "долбоеб","долбоёб","далбаёб","долбаеб","блят","бляд","сука","суки","суку","сучар","сучка","мудак","мудил","мудач","пидор","пидар","пидр",
  "пидер","педик","педераст","гандон","гондон","залуп","дроч","мразь","говн","гавн","жопа","шлюх","гнида",
  "fuck","shit","bitch","cunt","asshole","bastard","whore","nigger","nigga","faggot","pizda","pidor","pidar","pidr","pedik","eblan","ebal",
  "ebat","yobn","ohuel","ahuel","xyi","xuy","huy","hui","huj","blyad","blyat","suka","suchka","mudak","mydak","mudila","gandon","gondon",
  "zalupa","droch","dolboeb","dolbaeb","govno","gavno","zhopa","shluha","mraz",
];
const LEET = { "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "6": "g", "7": "t", "8": "b", "9": "g", "@": "a", "$": "s", "!": "i", "|": "i" };
const C2L = { а: "a", б: "b", в: "v", г: "g", д: "d", е: "e", ё: "e", ж: "zh", з: "z", и: "i", й: "i", к: "k", л: "l", м: "m", н: "n", о: "o", п: "p", р: "r", с: "s", т: "t", у: "u", ф: "f", х: "h", ц: "c", ч: "ch", ш: "sh", щ: "sch", ъ: "", ы: "y", ь: "", э: "e", ю: "yu", я: "ya" };
const L2C = { a: "а", b: "б", c: "с", d: "д", e: "е", f: "ф", g: "г", h: "х", i: "и", j: "й", k: "к", l: "л", m: "м", n: "н", o: "о", p: "п", q: "к", r: "р", s: "с", t: "т", u: "у", v: "в", w: "в", x: "х", y: "у", z: "з" };
// visual look-alikes collapse to one skeleton, so "аdmin" (cyrillic а) == "admin"
const HOMO = { а: "a", в: "b", е: "e", ё: "e", к: "k", м: "m", н: "h", о: "o", р: "p", с: "c", т: "t", у: "y", х: "x", і: "i", ј: "j", ѕ: "s", ԁ: "d", "0": "o", "1": "l", "3": "e" };
const RESERVED = ["admin","administrator","админ","администратор","moderator","moder","модер","модератор","support","поддержка","pmr","pmrwallet",
  "pmrsupport","root","official","system","система","null","undefined","owner","staff","team","service","сервис","bot","бот","wallet","кошелек","кошелёк","arbiter","арбитр"];

const normBase = (s) => String(s || "").toLowerCase().replace(/[0-9@$!|]/g, (c) => LEET[c] || "").replace(/[^a-zа-яё]/g, "");
export const nickKey = (s) => String(s || "").trim().toLowerCase().replace(/./g, (c) => HOMO[c] ?? c).replace(/[._-]/g, "");
export function nickError(raw) {
  const nick = String(raw || "").trim();
  if (nick.length < 3) return "Минимум 3 символа";
  if (nick.length > 16) return "Максимум 16 символов";
  if (!/^[A-Za-zА-Яа-яЁё0-9_.\-]+$/.test(nick)) return "Разрешены буквы, цифры, _ . -";
  if (!/[A-Za-zА-Яа-яЁё]/.test(nick)) return "Нужна хотя бы одна буква";
  if (/^[._\-]|[._\-]$/.test(nick)) return "Не может начинаться/заканчиваться на . _ -";
  if (/[._\-]{2,}/.test(nick)) return "Без двух спецсимволов подряд";
  if (/[A-Za-z]/.test(nick) && /[А-Яа-яЁё]/.test(nick)) return "Используйте один алфавит: латиницу или кириллицу";
  const base = normBase(nick), key = nickKey(nick);
  if (RESERVED.some((r) => r === nick.toLowerCase() || r === base || nickKey(r) === key || key.includes(nickKey("admin")) || key.includes(nickKey("support")))) return "Этот ник зарезервирован";
  const variants = [base, base.replace(/[а-яё]/g, (c) => C2L[c] ?? c), base.replace(/[a-z]/g, (c) => L2C[c] || c)];
  if (BAD_ROOTS.some((r) => variants.some((x) => x.includes(r)))) return "Недопустимый ник. Нецензурные слова запрещены.";
  return null;
}
