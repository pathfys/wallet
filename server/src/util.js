// Errors, strict input validation and exact (BigInt) money arithmetic.
import { randomBytes } from "node:crypto";

export class HttpError extends Error {
  constructor(status, code, message, extra) { super(message || code); this.status = status; this.code = code; this.extra = extra; }
}
export const bad = (code, msg, extra) => new HttpError(400, code, msg, extra);
export const forbidden = (msg = "Доступ запрещён") => new HttpError(403, "forbidden", msg);
export const notFound = (msg = "Не найдено") => new HttpError(404, "not_found", msg);
export const conflict = (code, msg) => new HttpError(409, code, msg);
export const tooMany = (msg = "Слишком много запросов, попробуйте позже") => new HttpError(429, "rate_limited", msg);

export const now = () => Date.now();
export const nowSec = () => Math.floor(Date.now() / 1000);
export const randomId = (bytes = 16) => randomBytes(bytes).toString("base64url");
export const randomU64 = () => randomBytes(8).readBigUInt64BE() & 0x7fffffffffffffffn;

// ------------------------------------------------------------ validation
const CTRL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F​-‏‪-‮⁦-⁩]/g;
export function cleanText(s, { max, multiline = false } = {}) {
  if (typeof s !== "string") throw bad("bad_input", "Ожидалась строка");
  let t = s.replace(CTRL, "").normalize("NFC");
  t = multiline ? t.replace(/\r\n?/g, "\n").replace(/\n{3,}/g, "\n\n") : t.replace(/\s+/g, " ");
  t = t.trim();
  if (max && t.length > max) throw bad("too_long", `Слишком длинный текст (максимум ${max})`);
  return t;
}
export const v = {
  str(x, name, { min = 0, max = 200, re, multiline } = {}) {
    if (x == null) x = "";
    const t = cleanText(String(x), { max, multiline });
    if (t.length < min) throw bad("bad_input", `${name}: обязательное поле`);
    if (re && t && !re.test(t)) throw bad("bad_input", `${name}: неверный формат`);
    return t;
  },
  int(x, name, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
    const n = typeof x === "string" && /^-?\d{1,16}$/.test(x) ? Number(x) : x;
    if (!Number.isSafeInteger(n) || n < min || n > max) throw bad("bad_input", `${name}: неверное значение`);
    return n;
  },
  oneOf(x, name, list) { if (!list.includes(x)) throw bad("bad_input", `${name}: недопустимое значение`); return x; },
  bool(x) { return x === true || x === 1 || x === "1" || x === "true"; },
  arr(x, name, { max = 10 } = {}) { if (!Array.isArray(x) || x.length > max) throw bad("bad_input", `${name}: неверный список`); return x; },
  // decimal string -> BigInt scaled by 10^dec (no floats anywhere)
  dec(x, name, dec, { min, max } = {}) {
    const s = String(x ?? "").trim().replace(",", ".");
    if (!new RegExp(`^\\d{1,15}(\\.\\d{1,${dec}})?$`).test(s)) throw bad("bad_input", `${name}: неверное число`);
    const [i, f = ""] = s.split(".");
    const r = BigInt(i + (f + "0".repeat(dec)).slice(0, dec));
    if (min !== undefined && r < BigInt(min)) throw bad("bad_input", `${name}: слишком мало`);
    if (max !== undefined && r > BigInt(max)) throw bad("bad_input", `${name}: слишком много`);
    return r;
  },
};

// ------------------------------------------------------------ money
export const ASSETS = {
  USDT: { dec: 6, step: 10_000n, kind: 1, cg: "tether", maxUnits: 1_000_000n * 1_000_000n },
  GRAM: { dec: 9, step: 100_000n, kind: 0, cg: "the-open-network", maxUnits: 1_000_000n * 1_000_000_000n },
};
export const FIATS = ["RUB(ПМР)", "RUB(РФ)", "USD", "EUR", "UAH", "KZT"];
export const PAY_TYPES = ["АПБ", "ЭксимБанк", "Сбербанк", "Наличные", "Банковский перевод", "СБП"];
export const PAY_WINDOWS = [15, 30, 60];
export const PINS = [{ h: 3, usd: 1 }, { h: 6, usd: 3 }, { h: 12, usd: 5 }, { h: 24, usd: 10 }];

// P2P fee defaults: 2% from the buyer + 2% from the seller = 4% per order, no $-cap.
// Override with P2P_FEE_SIDE_BPS / P2P_FEE_MAX_SIDE_USD in .env.
export const P2P_FEE_BPS = 200n;
export const MAX_FEE_SIDE_USD_E6 = 0n;

export const pow10 = (n) => 10n ** BigInt(n);
export const floorTo = (x, step) => (x / step) * step;
export const toStr = (units, dec) => {
  const neg = units < 0n; let u = neg ? -units : units;
  const i = u / pow10(dec), f = (u % pow10(dec)).toString().padStart(dec, "0").replace(/0+$/, "");
  return (neg ? "-" : "") + i.toString() + (f ? "." + f : "");
};
// fiat cents for `units` of an asset at price_e6 (fiat per 1 asset, scaled 1e6); rounds half up
export function fiatCents(units, dec, priceE6) {
  const num = BigInt(units) * BigInt(priceE6) * 100n, den = pow10(dec) * 1_000_000n;
  return (num + den / 2n) / den;
}
// asset units purchasable for `cents` at price_e6, floored to the asset step
export function unitsForCents(cents, asset, priceE6) {
  const a = ASSETS[asset];
  const u = (BigInt(cents) * pow10(a.dec) * 1_000_000n) / (BigInt(priceE6) * 100n);
  return floorTo(u, a.step);
}
// per-side P2P fee in basis points, rounded up to the unit; optional cap in USD (usdE6 = asset price * 1e6)
export function sideFee(units, asset, usdE6, bps = P2P_FEE_BPS, capUsdE6 = MAX_FEE_SIDE_USD_E6) {
  let fee = (BigInt(units) * BigInt(bps) + 9_999n) / 10_000n;
  if (capUsdE6 > 0n && usdE6 && usdE6 > 0n) {
    const cap = (BigInt(capUsdE6) * pow10(ASSETS[asset].dec)) / BigInt(usdE6);
    if (fee > cap) fee = cap;
  }
  return fee;
}
