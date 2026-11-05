# PMR Wallet — бэкенд

Node.js ≥ 22.13 (встроенный SQLite), две рантайм‑зависимости: `@ton/core`, `ws`.
Подробности архитектуры и безопасности — в [`../REVIEW.md`](../REVIEW.md).

## Быстрый старт (локально, testnet)

```bash
cd server
npm ci
npm test
cp .env.example .env
npm run gen:keys      # вставьте ARBITER_SECRET и DATA_KEY в .env, публичный ключ — в index.html (CONFIG.ARBITER_PUBKEY)
npm start
```

## Продакшен

1. Сервер с доменом и TLS (Let's Encrypt). Пользователь: `sudo useradd -r -s /usr/sbin/nologin pmrwallet`.
2. Код в `/opt/pmr-wallet` (репозиторий целиком: фронтенд раздаётся этим же сервером), затем
   `cd /opt/pmr-wallet/server && npm ci --omit=dev`.
3. `.env` по образцу `.env.example`, `chmod 600 .env`, `mkdir data && chown pmrwallet data`.
4. `deploy/pmr-wallet.service` → `/etc/systemd/system/`, `systemctl enable --now pmr-wallet`.
5. `deploy/nginx.conf` → `/etc/nginx/sites-enabled/` (замените `wallet.example.com`), `nginx -t && systemctl reload nginx`.
6. В @BotFather укажите URL Mini App: `https://<ваш домен>/`.
7. Если фронтенд остаётся на GitHub Pages: в `index.html` задайте `CONFIG.API_BASE = "https://<api-домен>"`,
   добавьте этот домен в `connect-src` CSP в `index.html`, а на сервере `ALLOWED_ORIGINS=https://<pages-домен>`.

## Пересборка артефактов

Скомпилированный контракт (`contracts/build/pmr_escrow.json`) и бандл фронтенда (`../vendor/pmr-vendor.js`)
лежат в репозитории. Пересобирать нужно только после изменения контракта или библиотек:

```bash
npm run build:contract   # FunC -> contracts/build/pmr_escrow.json
npm run build:vendor     # ../vendor/pmr-vendor.js + обновляет SRI-хеш в ../index.html
```

Изменение кода контракта меняет адреса всех будущих эскроу; старые сделки продолжают работать со старым кодом.

## API (кратко)

Все маршруты, кроме `/api/config` и `/api/auth/login`, требуют `Authorization: Bearer <token>` и подписи
`X-PMR-Ts`, `X-PMR-Nonce`, `X-PMR-Sig` (ECDSA P‑256 над `METHOD\nPATH\nTS\nNONCE\nSHA256(body)`).

* Вход и профиль: `POST /api/auth/login`, `GET /api/me`, `POST /api/me/nick`, `GET /api/nick-check`, `POST /api/wallet/challenge`, `POST /api/wallet/bind`
* Реквизиты: `GET|POST /api/payment-methods`, `DELETE /api/payment-methods/:id`
* Объявления: `GET /api/ads`, `GET /api/ads/mine`, `POST /api/ads`, `POST /api/ads/:id`, `POST /api/ads/:id/status`, `DELETE /api/ads/:id`, `POST /api/ads/:id/pin`, `GET /api/pins/:id`, `GET /api/index-price`
* Ордеры: `POST /api/orders`, `GET /api/orders`, `GET /api/orders/:id`, `GET /api/orders/:id/escrow-tx`, `POST /api/orders/:id/{escrow-sent,paid,cancel,release-sent,appeal,appeal/cancel,feedback}`
* Чат: `GET|POST /api/orders/:id/messages`, `POST /api/orders/:id/files`, `GET /api/files/:id`, `POST /api/ws-ticket`, WebSocket `/api/ws?ticket=`
* Прочее: `POST /api/reports`, `GET /api/users/:nick`
* Админ: `/api/admin/{stats,appeals,appeals/:id/resolve,orders/:id,reports,reports/:id/status,reports/:id/block,bans,users,ads,ads/:id/remove,broadcast,broadcasts}`
