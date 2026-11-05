// Market index prices (CoinGecko) used for floating-price ads and the $-caps on
// fees. Values are cached; stale data is refused after MAX_AGE so orders never
// execute against a frozen price.
const VS = { "RUB(РФ)": "rub", USD: "usd", EUR: "eur", UAH: "uah", KZT: "kzt" };
const TTL = 60_000, MAX_AGE = 30 * 60_000;

export function makePrices(cfg, fetchImpl = fetch) {
  let cache = null, at = 0, inflight = null;
  async function refresh() {
    const url = `${cfg.coingecko}?ids=tether,the-open-network&vs_currencies=usd,eur,rub,uah,kzt`;
    const ctl = new AbortController(), t = setTimeout(() => ctl.abort(), 8000);
    try {
      const r = await fetchImpl(url, { signal: ctl.signal, headers: { accept: "application/json" } });
      if (!r.ok) throw new Error("coingecko " + r.status);
      const j = await r.json();
      if (!j.tether || !j["the-open-network"]) throw new Error("coingecko payload");
      cache = j; at = Date.now();
    } finally { clearTimeout(t); }
  }
  async function get() {
    if (!cache || Date.now() - at > TTL) {
      inflight = inflight || refresh().catch(() => {}).finally(() => { inflight = null; });
      if (!cache) await inflight;
    }
    return cache && Date.now() - at < MAX_AGE ? cache : null;
  }
  const toE6 = (x) => (Number.isFinite(x) && x > 0 ? BigInt(Math.round(x * 1e6)) : 0n);
  return {
    // asset price in fiat, scaled by 1e6; 0n when unavailable
    async index(asset, fiat) {
      const p = await get(); if (!p) return 0n;
      const row = p[asset === "USDT" ? "tether" : "the-open-network"];
      if (fiat === "RUB(ПМР)") return cfg.prbPerUsd ? toE6(row.usd * Number(cfg.prbPerUsd)) : 0n;
      return toE6(row[VS[fiat]]);
    },
    async usdE6(asset) {
      if (asset === "USDT") return 1_000_000n;
      const p = await get(); return p ? toE6(p["the-open-network"].usd) : 0n;
    },
    _set(j) { cache = j; at = Date.now(); },
  };
}
