-- Схема базы «Морвейна». Применять: npx wrangler d1 execute morveyn --remote --file=schema.sql
-- Повторный запуск безопасен (IF NOT EXISTS).

-- Игроки: анонимный код, без имён и id Telegram
CREATE TABLE IF NOT EXISTS players (
  pid        TEXT PRIMARY KEY,        -- tg_… (хеш от id Telegram) или dev_… (браузер вне Telegram)
  verified   INTEGER NOT NULL,        -- 1 = подпись Telegram проверена сервером
  first_seen INTEGER NOT NULL,        -- unix-время в мс
  last_seen  INTEGER NOT NULL,
  platform   TEXT,
  version    TEXT
);

-- События игры
CREATE TABLE IF NOT EXISTS events (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  t        INTEGER NOT NULL,          -- время события на устройстве, мс
  received INTEGER NOT NULL,          -- время приёма сервером, мс
  pid      TEXT NOT NULL,
  sid      TEXT,                      -- сессия
  v        TEXT,                      -- версия игры
  platform TEXT,
  e        TEXT NOT NULL,             -- имя события: session_start, battle, day, …
  day      INTEGER,
  cont     INTEGER,                   -- земля 0–4
  hero     TEXT,
  hard     INTEGER,
  lvl      INTEGER,
  d        TEXT                       -- дополнительные данные события (JSON)
);
CREATE INDEX IF NOT EXISTS idx_events_t   ON events(t);
CREATE INDEX IF NOT EXISTS idx_events_e   ON events(e, t);
CREATE INDEX IF NOT EXISTS idx_events_pid ON events(pid, t);

-- Заготовки для следующих этапов (пока не используются)
CREATE TABLE IF NOT EXISTS scores (       -- этап 2: испытание недели
  week     TEXT NOT NULL,                 -- например 2026-W40
  pid      TEXT NOT NULL,
  name     TEXT,                          -- только имя из Telegram
  hero     TEXT,
  days     INTEGER NOT NULL,
  active_ms INTEGER NOT NULL,
  v        TEXT,
  created  INTEGER NOT NULL,
  title    TEXT,                          -- звание из книги достижений
  PRIMARY KEY (week, pid)
);
CREATE TABLE IF NOT EXISTS purchases (    -- этап 3: покупки за звёзды
  charge_id TEXT PRIMARY KEY,             -- telegram_payment_charge_id
  pid       TEXT NOT NULL,
  product   TEXT NOT NULL,
  stars     INTEGER NOT NULL,
  created   INTEGER NOT NULL,
  refunded  INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS referrals (
  invitee      TEXT PRIMARY KEY,     -- код приглашённого игрока
  inviter      TEXT NOT NULL,        -- код пригласившего
  created      INTEGER NOT NULL,
  qualified    INTEGER NOT NULL DEFAULT 0,  -- 1 = друг выиграл первый бой (проверяется по статистике на сервере)
  qualified_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_ref_inviter ON referrals(inviter, qualified);

-- Посылки: всё, что игрок получает от сервера. Сейчас — награды за приглашения;
-- позже сюда же — покупки за звёзды, промокоды, подарки и компенсации от разработчика.
-- Игра забирает посылку через /inbox/claim, сервер помечает её полученной — дважды не забрать.
CREATE TABLE IF NOT EXISTS rewards (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  pid        TEXT NOT NULL,
  kind       TEXT NOT NULL,          -- ref_invitee | ref_inviter | gift | purchase | promo …
  payload    TEXT NOT NULL,          -- JSON: {"gold":300} | {"item":"…"} | {"unlock":"full"} …
  created    INTEGER NOT NULL,
  claimed    INTEGER NOT NULL DEFAULT 0,
  claimed_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_rewards_pid ON rewards(pid, claimed);

-- Мировой босс недели (0.41): один на всех, урон суммируется, одна попытка в день (UTC)
CREATE TABLE IF NOT EXISTS boss_weeks (
  week       TEXT PRIMARY KEY,          -- 2026-W48
  key        TEXT NOT NULL,             -- облик босса: dragon | giants | liches | demons | cyclopes | trolls
  hp         INTEGER NOT NULL,          -- запас здоровья на неделю
  killed     INTEGER NOT NULL DEFAULT 0,
  killed_at  INTEGER,
  created    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS boss_hits (
  week     TEXT NOT NULL,
  pid      TEXT NOT NULL,
  day      TEXT NOT NULL,               -- дата попытки по UTC, 2026-11-24
  name     TEXT,                        -- имя из Telegram для таблицы вклада
  dmg      INTEGER NOT NULL,
  pow      INTEGER,
  v        TEXT,
  created  INTEGER NOT NULL,
  PRIMARY KEY (week, pid, day)
);
CREATE INDEX IF NOT EXISTS idx_boss_hits_week ON boss_hits(week, pid);
