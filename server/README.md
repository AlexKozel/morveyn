# Сервер «Морвейна» (Cloudflare Worker + D1)

Код сервера, который раньше жил только локально. Секретов здесь нет: токен бота и секрет вебхука
хранятся в Cloudflare (`npx wrangler secret put BOT_TOKEN`, `TG_WEBHOOK_SECRET`).

Выкладка (из этой папки):

```
npx wrangler d1 execute morveyn --remote --file=schema.sql   # новые таблицы; повторный запуск безопасен
npx wrangler deploy
```

Сначала выкладывается сервер, потом игра: без сервера окно мирового босса просто пишет «нет связи».
