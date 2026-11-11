// SQLite (node:sqlite) storage. Only prepared statements are used — no string
// concatenation of user input into SQL anywhere in the codebase.
import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY,                 -- Telegram user id
  nick TEXT, nick_key TEXT UNIQUE, nick_changes_left INTEGER NOT NULL DEFAULT 1,
  first_name TEXT, username TEXT, allows_pm INTEGER NOT NULL DEFAULT 0,
  role TEXT NOT NULL DEFAULT 'user',
  wallet_address TEXT UNIQUE, wallet_pubkey TEXT, wallet_bound_at INTEGER,
  banned_at INTEGER, ban_reason TEXT, banned_by INTEGER,
  created_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, pub_x TEXT NOT NULL, pub_y TEXT NOT NULL,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, ip TEXT
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS wallet_challenges(
  id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS payment_methods(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, type TEXT NOT NULL, details_enc TEXT NOT NULL,
  created_at INTEGER NOT NULL, deleted INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS pm_user ON payment_methods(user_id);
CREATE TABLE IF NOT EXISTS ads(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, side TEXT NOT NULL, asset TEXT NOT NULL, fiat TEXT NOT NULL,
  price_type TEXT NOT NULL, price_e6 INTEGER, float_e2 INTEGER,
  total_units INTEGER NOT NULL, remaining_units INTEGER NOT NULL,
  min_cents INTEGER NOT NULL, max_cents INTEGER NOT NULL, pay_window INTEGER NOT NULL,
  pay_types TEXT NOT NULL, pm_ids TEXT NOT NULL, remarks TEXT NOT NULL DEFAULT '',
  cond_min_orders INTEGER NOT NULL DEFAULT 0, cond_reg_days INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL, pinned_until INTEGER NOT NULL DEFAULT 0, removed_reason TEXT,
  idem TEXT UNIQUE, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ads_list ON ads(status, side, asset, fiat);
CREATE INDEX IF NOT EXISTS ads_user ON ads(user_id);
CREATE TABLE IF NOT EXISTS orders(
  id INTEGER PRIMARY KEY, ad_id INTEGER NOT NULL, maker_id INTEGER NOT NULL, taker_id INTEGER NOT NULL,
  buyer_id INTEGER NOT NULL, seller_id INTEGER NOT NULL, asset TEXT NOT NULL, fiat TEXT NOT NULL,
  price_e6 INTEGER NOT NULL, amount_units INTEGER NOT NULL, fiat_cents INTEGER NOT NULL,
  buyer_fee INTEGER NOT NULL, seller_fee INTEGER NOT NULL, usd_e6 INTEGER NOT NULL DEFAULT 0,
  pay_type TEXT NOT NULL, pay_details_enc TEXT NOT NULL, pay_window INTEGER NOT NULL, remarks TEXT NOT NULL DEFAULT '',
  status INTEGER NOT NULL,
  deal_id TEXT NOT NULL, escrow_address TEXT NOT NULL UNIQUE, seller_address TEXT NOT NULL, buyer_address TEXT NOT NULL,
  escrow_deadline INTEGER NOT NULL, jetton_wallet TEXT,
  lock_deadline INTEGER NOT NULL, pay_deadline INTEGER, funded_at INTEGER, paid_at INTEGER,
  completed_at INTEGER, cancelled_at INTEGER, cancel_reason TEXT, cancelled_by INTEGER, fault_user INTEGER,
  lock_sent_at INTEGER, release_sent_at INTEGER, decision TEXT, decision_valid_until INTEGER, refund_needed INTEGER NOT NULL DEFAULT 0,
  chain_checked_at INTEGER NOT NULL DEFAULT 0, last_notify_msg_at INTEGER NOT NULL DEFAULT 0,
  idem TEXT UNIQUE, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS orders_status ON orders(status);
CREATE INDEX IF NOT EXISTS orders_buyer ON orders(buyer_id, status);
CREATE INDEX IF NOT EXISTS orders_seller ON orders(seller_id, status);
CREATE INDEX IF NOT EXISTS orders_ad ON orders(ad_id, status);
CREATE TABLE IF NOT EXISTS messages(
  id INTEGER PRIMARY KEY, order_id INTEGER NOT NULL, sender_id INTEGER NOT NULL, -- 0 = system
  kind TEXT NOT NULL, body TEXT NOT NULL DEFAULT '', file_id TEXT, support INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_order ON messages(order_id, id);
CREATE TABLE IF NOT EXISTS files(
  id TEXT PRIMARY KEY, order_id INTEGER NOT NULL, uploader_id INTEGER NOT NULL, mime TEXT NOT NULL,
  size INTEGER NOT NULL, sha256 TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS appeals(
  id INTEGER PRIMARY KEY, order_id INTEGER NOT NULL, opened_by INTEGER NOT NULL, reason TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '', status TEXT NOT NULL, prev_status INTEGER NOT NULL,
  resolution TEXT, resolved_by INTEGER, created_at INTEGER NOT NULL, resolved_at INTEGER
);
CREATE INDEX IF NOT EXISTS appeals_status ON appeals(status);
CREATE TABLE IF NOT EXISTS reports(
  id INTEGER PRIMARY KEY, reporter_id INTEGER NOT NULL, against_id INTEGER NOT NULL, order_id INTEGER,
  reason TEXT NOT NULL, text TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'new',
  resolution TEXT, resolved_by INTEGER, created_at INTEGER NOT NULL, resolved_at INTEGER
);
CREATE TABLE IF NOT EXISTS feedback(
  id INTEGER PRIMARY KEY, order_id INTEGER NOT NULL, from_id INTEGER NOT NULL, to_id INTEGER NOT NULL,
  positive INTEGER NOT NULL, comment TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL,
  UNIQUE(order_id, from_id)
);
CREATE INDEX IF NOT EXISTS feedback_to ON feedback(to_id);
CREATE TABLE IF NOT EXISTS pin_invoices(
  id TEXT PRIMARY KEY, ad_id INTEGER NOT NULL, user_id INTEGER NOT NULL, hours INTEGER NOT NULL,
  asset TEXT NOT NULL, amount_units INTEGER NOT NULL, comment TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'pending', tx_hash TEXT UNIQUE, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, paid_at INTEGER
);
CREATE TABLE IF NOT EXISTS activity(user_id INTEGER NOT NULL, hour INTEGER NOT NULL, PRIMARY KEY(user_id, hour)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS activity_hour ON activity(hour);
CREATE INDEX IF NOT EXISTS orders_created ON orders(created_at);
CREATE INDEX IF NOT EXISTS orders_completed ON orders(completed_at);
CREATE INDEX IF NOT EXISTS users_created ON users(created_at);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, actor_id INTEGER, action TEXT NOT NULL, target TEXT, details TEXT, ip TEXT
);
CREATE TABLE IF NOT EXISTS broadcasts(
  id INTEGER PRIMARY KEY, admin_id INTEGER NOT NULL, text TEXT NOT NULL, total INTEGER NOT NULL DEFAULT 0,
  sent INTEGER NOT NULL DEFAULT 0, failed INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS nonces(k TEXT PRIMARY KEY, exp INTEGER NOT NULL) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS nonces_exp ON nonces(exp);
-- initData is bound to the first device key that used it: a copied initData
-- (logs, Telegram Web devtools, a malicious proxy) cannot open a second session.
CREATE TABLE IF NOT EXISTS init_data_uses(
  hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, pub_x TEXT NOT NULL, pub_y TEXT NOT NULL, expires_at INTEGER NOT NULL
) WITHOUT ROWID;
`;

export function openDb(file) {
  if (file !== ":memory:") mkdirSync(dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA secure_delete=ON;");
  db.exec(SCHEMA);
  const cache = new Map();
  const prep = (sql) => { let s = cache.get(sql); if (!s) { s = db.prepare(sql); cache.set(sql, s); } return s; };
  return {
    raw: db,
    get: (sql, ...a) => prep(sql).get(...a),
    all: (sql, ...a) => prep(sql).all(...a),
    run: (sql, ...a) => prep(sql).run(...a),
    tx(fn) {
      db.exec("BEGIN IMMEDIATE");
      try { const r = fn(); db.exec("COMMIT"); return r; }
      catch (e) { try { db.exec("ROLLBACK"); } catch {} throw e; }
    },
    audit(actor, action, target, details, ip) {
      prep("INSERT INTO audit(ts,actor_id,action,target,details,ip) VALUES(?,?,?,?,?,?)")
        .run(Date.now(), actor ?? null, action, target == null ? null : String(target), details ? JSON.stringify(details) : null, ip || null);
    },
    close: () => db.close(),
  };
}
