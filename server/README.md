# PMR Wallet — бэкенд

Node.js ≥ 22.13 (встроенный SQLite), две рантайм‑зависимости: `@ton/core`, `ws`.
Подробности архитектуры и безопасности — в [`../REVIEW.md`](../REVIEW.md).

## Быстрый старт (локально)

```bash
cd server
npm ci
npm test
cp .env.example .env
npm run gen:keys          # ARBITER_SECRET и DATA_KEY -> в .env
npm run setup:frontend    # пропишет ключ арбитра и кошелёк комиссий в ../index.html
npm start
```

Приложение открывается только внутри нативного Telegram — в обычном браузере будет пустая страница (так задумано).

## Продакшен на pmrwallet.com

Нужен VPS (Ubuntu 22.04/24.04, 1 vCPU / 1 ГБ хватит на старт) и DNS: записи `A` для `pmrwallet.com`
и `www.pmrwallet.com` на IP сервера.

```bash
# 1. Node.js 22 и nginx
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo bash -
sudo apt install -y nodejs nginx certbot python3-certbot-nginx unzip

# 2. Код
sudo useradd -r -s /usr/sbin/nologin pmrwallet
sudo mkdir -p /opt/pmr-wallet && sudo unzip pmrwallet.zip -d /opt/pmr-wallet
cd /opt/pmr-wallet/server && sudo npm ci --omit=dev

# 3. Настройки
sudo cp .env.example .env && sudo chmod 600 .env
sudo node scripts/gen-keys.mjs        # ARBITER_SECRET и DATA_KEY — вставить в .env, сохранить копию офлайн
sudo nano .env                        # BOT_TOKEN, ADMIN_IDS, TONCENTER_API_KEY, FEE_WALLET, BOT_WEBHOOK_SECRET, TG_APP_LINK
sudo npm run setup:frontend           # ключ арбитра + кошелёк комиссий -> index.html
sudo mkdir -p data && sudo chown -R pmrwallet /opt/pmr-wallet/server/data

# 4. Служба
sudo cp deploy/pmr-wallet.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now pmr-wallet

# 5. HTTPS + nginx
sudo certbot certonly --nginx -d pmrwallet.com -d www.pmrwallet.com
sudo cp deploy/nginx.conf /etc/nginx/sites-enabled/pmrwallet.conf
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx

# 6. Проверка
curl -s https://pmrwallet.com/api/config | head -c 200; echo
sudo journalctl -u pmr-wallet -n 30 --no-pager   # не должно быть ошибок про ARBITER_PUBKEY / FEE_WALLET
```

**@BotFather**
1. `/newapp` (или `/myapps` → ваш бот) → URL Mini App: `https://pmrwallet.com/`, короткое имя, например `app`.
   Ссылка вида `https://t.me/<бот>/app` — это `TG_APP_LINK` в `.env` (перезапустите службу).
2. Бот сам ставит вебхук `https://pmrwallet.com/api/tg/webhook`, команды `/start`, `/help` и кнопку меню «Кошелёк».

`BOT_WEBHOOK_SECRET` — `openssl rand -hex 32`. Сначала стоит проверить всё на testnet (`TON_NETWORK=testnet`).

После правки `index.html` руками (например, `CONFIG`) сервер сам пересчитывает CSP‑хеш при отдаче страницы;
для хостинга без этого сервера выполните `npm run setup:frontend`.

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
