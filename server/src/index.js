/* Сервер «Морвейна» — Cloudflare Worker.
 *
 * Маршруты:
 *   GET  /health       — проверка, что сервер жив
 *   POST /events       — пачка событий статистики от игры
 *   POST /scores       — результат испытания недели (только из Telegram, одна попытка в неделю)
 *   POST /leaderboard  — таблицы испытания: топ-50 по дням и по времени, место игрока
 *   POST /achstats     — сколько игроков получили каждое достижение (для процентов в книге достижений)
 *   POST /ref/register — приглашённый друг впервые открыл игру по ссылке ref_<код> (подарок ему — сразу)
 *   POST /inbox        — посылки игрока + статистика приглашений (заодно засчитывает друзей, выигравших первый бой)
 *   POST /inbox/claim  — забрать посылки (каждую — только один раз)
 *   POST /boss         — мировой босс недели: запас здоровья, общий урон, вклад игрока, топ-10
 *   POST /boss/hit     — урон за попытку (только из Telegram, одна попытка в сутки по UTC)
 *   POST /tg-webhook   — сообщения боту от Telegram (команды /start /play /top /invite /channel /help);
 *                        проверяется секрет в заголовке X-Telegram-Bot-Api-Secret-Token (TG_WEBHOOK_SECRET)
 *
 * Безопасность:
 *   • запросы принимаются только с адресов из ALLOWED_ORIGINS (wrangler.toml);
 *   • если игра открыта в Telegram, к пачке прикладывается initData — сервер проверяет подпись
 *     (HMAC-SHA256 с токеном бота) и сам вычисляет код игрока, поэтому подделать чужой код нельзя;
 *   • поддельная подпись → 401; без initData (браузер вне Telegram) пачка принимается как непроверенная;
 *   • ограничены размер пачки, число событий и длина полей.
 *
 * Код игрока совпадает с тем, что считает игра: 'tg_' + первые 8 байт SHA-256('morveyn:' + id) в hex.
 * Имена, ники и сам id Telegram в базу не пишутся.
 */

const MAX_BODY = 64 * 1024;          // байт в одной пачке
const MAX_EVENTS = 60;               // событий в одной пачке
const MAX_DATA = 1000;               // символов в поле d одного события
const INITDATA_MAX_AGE = 7 * 86400;  // подпись Telegram действительна 7 дней (игра может быть открыта долго)

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';
    const cors = corsHeaders(origin, env);

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    if (url.pathname === '/health') return json({ ok: true }, 200, cors);
    // Telegram присылает сообщения боту сюда; это не браузер, поэтому проверяем не Origin, а секретный заголовок
    if (url.pathname === '/tg-webhook' && request.method === 'POST') {
      if (!env.TG_WEBHOOK_SECRET || request.headers.get('X-Telegram-Bot-Api-Secret-Token') !== env.TG_WEBHOOK_SECRET)
        return new Response('forbidden', { status: 403 });
      try { await handleTgUpdate(await request.json(), env); } catch (e) { /* Telegram всё равно получит 200, чтобы не слал повторно */ }
      return new Response('ok');
    }

    const routes = { '/events': handleEvents, '/scores': handleScores, '/leaderboard': handleLeaderboard, '/achstats': handleAchStats,
                     '/ref/register': handleRefRegister, '/inbox': handleInbox, '/inbox/claim': handleClaim,
                     '/boss': handleBoss, '/boss/hit': handleBossHit };
    if (routes[url.pathname] && request.method === 'POST') {
      if (!originAllowed(origin, env)) return json({ error: 'origin' }, 403, cors);
      try { return await routes[url.pathname](request, env, cors); }
      catch (e) { return json({ error: 'server' }, 500, cors); }
    }
    return json({ error: 'not_found' }, 404, cors);
  },
};

/* ---------- /events ---------- */
async function handleEvents(request, env, cors) {
  const text = await request.text();
  if (text.length > MAX_BODY) return json({ error: 'too_large' }, 413, cors);
  let body;
  try { body = JSON.parse(text); } catch { return json({ error: 'bad_json' }, 400, cors); }
  if (!body || !Array.isArray(body.events)) return json({ error: 'bad_shape' }, 400, cors);
  if (body.events.length === 0) return json({ ok: true, stored: 0 }, 200, cors);
  if (body.events.length > MAX_EVENTS) return json({ error: 'too_many' }, 413, cors);

  // кто прислал
  let pid, verified = 0;
  if (body.initData) {
    const user = await verifyInitData(String(body.initData), env.BOT_TOKEN);
    if (!user) return json({ error: 'bad_signature' }, 401, cors);
    pid = await playerIdFromTelegram(user.id);
    verified = 1;
  } else {
    pid = String(body.pid || '');
    if (!/^dev_[a-z0-9]{4,20}$/.test(pid)) return json({ error: 'bad_pid' }, 400, cors);
  }

  const now = Date.now();
  const sid = clip(body.sid, 32), v = clip(body.v, 16), platform = clip(body.platform, 32);

  const stmts = [
    env.DB.prepare(
      `INSERT INTO players (pid, verified, first_seen, last_seen, platform, version)
       VALUES (?1, ?2, ?3, ?3, ?4, ?5)
       ON CONFLICT(pid) DO UPDATE SET last_seen=?3, platform=?4, version=?5,
         verified=MAX(verified, ?2)`
    ).bind(pid, verified, now, platform, v),
  ];
  const ins = env.DB.prepare(
    `INSERT INTO events (t, received, pid, sid, v, platform, e, day, cont, hero, hard, lvl, d)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)`
  );
  for (const ev of body.events) {
    if (!ev || typeof ev.e !== 'string') continue;
    const t = Number.isFinite(ev.t) && Math.abs(ev.t - now) < 30 * 86400e3 ? Math.round(ev.t) : now;
    let d = '';
    try { d = JSON.stringify(ev.d ?? {}); } catch { d = '{}'; }
    if (d.length > MAX_DATA) d = d.slice(0, MAX_DATA);
    stmts.push(ins.bind(
      t, now, pid, sid, v, platform, clip(ev.e, 32),
      int(ev.day), int(ev.cont), clip(ev.hero, 16), ev.hard ? 1 : 0, int(ev.lvl), d
    ));
  }
  await env.DB.batch(stmts);
  return json({ ok: true, stored: stmts.length - 1, verified: !!verified }, 200, cors);
}

/* ---------- испытание недели ----------
 * Те же правила недели и героя, что в игре: ISO-неделя (понедельник–воскресенье, UTC), герой по очереди. */
const CHAL_HEROES = ['knight', 'sorceress', 'ranger'];
export function isoWeekId(ts) {
  const d = new Date(ts), t = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const dn = (t.getUTCDay() + 6) % 7; t.setUTCDate(t.getUTCDate() - dn + 3);
  const fy = t.getUTCFullYear(), ft = new Date(Date.UTC(fy, 0, 4));
  const w = 1 + Math.round(((t - ft) / 864e5 - 3 + ((ft.getUTCDay() + 6) % 7)) / 7);
  return fy + '-W' + String(w).padStart(2, '0');
}
export function heroForWeek(id) { const y = +id.slice(0, 4), w = +id.slice(6); return CHAL_HEROES[(y * 53 + w) % 3]; }
const MIN_DAYS = 5, MAX_DAYS = 500, MIN_ACTIVE_MS = 5 * 60e3, MAX_ACTIVE_MS = 200 * 3600e3, GRACE_MS = 12 * 3600e3;

async function readBody(request) {
  const text = await request.text();
  if (text.length > 16 * 1024) return null;
  try { return JSON.parse(text); } catch { return null; }
}
function cleanName(user) {
  const n = String(user.first_name || 'Игрок').replace(/[\u0000-\u001f<>]/g, '').trim().slice(0, 24);
  return n || 'Игрок';
}

async function handleScores(request, env, cors, nowMs = Date.now()) {
  const body = await readBody(request);
  if (!body) return json({ error: 'bad_json' }, 400, cors);
  const user = await verifyInitData(String(body.initData || ''), env.BOT_TOKEN);
  if (!user) return json({ error: 'bad_signature' }, 401, cors);

  // правдоподобие: неделя текущая (или прошлая в первые 12 часов новой), герой недели, разумные дни и время
  const week = String(body.week || '');
  const cur = isoWeekId(nowMs), prev = isoWeekId(nowMs - GRACE_MS);
  if (!/^\d{4}-W\d{2}$/.test(week) || (week !== cur && week !== prev)) return json({ error: 'bad_week' }, 400, cors);
  if (body.hero !== heroForWeek(week)) return json({ error: 'bad_hero' }, 400, cors);
  const days = Number(body.days), active = Number(body.active_ms);
  if (!Number.isInteger(days) || days < MIN_DAYS || days > MAX_DAYS) return json({ error: 'bad_days' }, 400, cors);
  if (!Number.isFinite(active) || active < MIN_ACTIVE_MS || active > MAX_ACTIVE_MS) return json({ error: 'bad_time' }, 400, cors);

  const pid = await playerIdFromTelegram(user.id);
  const res = await env.DB.prepare(
    `INSERT OR IGNORE INTO scores (week, pid, name, hero, days, active_ms, v, created, title) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)`
  ).bind(week, pid, cleanName(user), body.hero, days, Math.round(active), clip(body.v, 16), nowMs, cleanTitle(body.title)).run();
  if (!res.meta || res.meta.changes === 0) return json({ error: 'already' }, 409, cors);

  const ranks = await ranksFor(env, week, days, Math.round(active));
  return json({ ok: true, ...ranks }, 200, cors);
}

/* Звание игрока рядом с именем в таблице: только текст, до 30 символов, без разметки. */
function cleanTitle(t) { return String(t || '').replace(/[<>\u0000-\u001f]/g, '').trim().slice(0, 30); }

/* Процент игроков по достижениям: сколько разных игроков получили каждое (по событиям статистики) и всего игроков. */
async function handleAchStats(request, env, cors) {
  const [counts, total] = await env.DB.batch([
    // псевдоним ach, а не id: в events есть свой столбец id, и SQLite сгруппировал бы по нему
    env.DB.prepare(`SELECT json_extract(d,'$.id') AS ach, COUNT(DISTINCT pid) AS n FROM events WHERE e='achievement' GROUP BY 1`),
    env.DB.prepare(`SELECT COUNT(*) AS n FROM players`),
  ]);
  const out = {}; (counts.results || []).forEach(r => { if (r.ach) out[r.ach] = r.n; });
  return json({ total: (total.results && total.results[0] && total.results[0].n) || 0, counts: out }, 200, { ...cors, 'Cache-Control': 'max-age=600' });
}

/* ---------- приглашения и посылки ----------
 * Код приглашения — первые 10 символов хеша игрока (после tg_). Подарок другу — сразу при регистрации,
 * награда пригласившему — когда в статистике друга появится выигранный бой (проверяет сервер, а не игра).
 * Все награды идут через таблицу rewards: это же место потом примет покупки, промокоды и подарки. */
const REF_INVITEE_GOLD = 300, REF_INVITER_GOLD = 200, REF_NEW_WINDOW_MS = 2 * 3600e3;
async function authPid(body, env) {
  const user = await verifyInitData(String(body.initData || ''), env.BOT_TOKEN);
  return user ? await playerIdFromTelegram(user.id) : null;
}
async function grant(env, pid, kind, payload, nowMs) {
  return env.DB.prepare(`INSERT INTO rewards (pid, kind, payload, created) VALUES (?1, ?2, ?3, ?4)`).bind(pid, kind, JSON.stringify(payload), nowMs).run();
}
async function handleRefRegister(request, env, cors, nowMs = Date.now()) {
  const body = await readBody(request); if (!body) return json({ error: 'bad_json' }, 400, cors);
  const me = await authPid(body, env); if (!me) return json({ error: 'bad_signature' }, 401, cors);
  const code = String(body.code || ''); if (!/^[0-9a-f]{10}$/.test(code)) return json({ error: 'bad_code' }, 400, cors);
  const inv = await env.DB.prepare(`SELECT pid FROM players WHERE pid LIKE ?1 LIMIT 1`).bind('tg_' + code + '%').first();
  if (!inv) return json({ error: 'no_inviter' }, 404, cors);
  if (inv.pid === me) return json({ error: 'self' }, 400, cors);
  // приглашённым считается только новый игрок: впервые замечен не раньше чем 2 часа назад
  const mine = await env.DB.prepare(`SELECT first_seen FROM players WHERE pid=?1`).bind(me).first();
  if (mine && nowMs - mine.first_seen > REF_NEW_WINDOW_MS) return json({ error: 'not_new' }, 409, cors);
  const res = await env.DB.prepare(`INSERT OR IGNORE INTO referrals (invitee, inviter, created) VALUES (?1, ?2, ?3)`).bind(me, inv.pid, nowMs).run();
  if (!res.meta || res.meta.changes === 0) return json({ error: 'already' }, 409, cors);
  await grant(env, me, 'ref_invitee', { gold: REF_INVITEE_GOLD }, nowMs);
  return json({ ok: true, gold: REF_INVITEE_GOLD }, 200, cors);
}
async function handleInbox(request, env, cors, nowMs = Date.now()) {
  const body = await readBody(request); if (!body) return json({ error: 'bad_json' }, 400, cors);
  const me = await authPid(body, env); if (!me) return json({ error: 'bad_signature' }, 401, cors);
  // засчитать друзей, у которых в статистике уже есть выигранный бой
  const fresh = await env.DB.prepare(
    `SELECT invitee FROM referrals r WHERE r.inviter=?1 AND r.qualified=0 AND EXISTS
       (SELECT 1 FROM events e WHERE e.pid=r.invitee AND e.e='battle' AND json_extract(e.d,'$.res')='win')`
  ).bind(me).all();
  for (const row of (fresh.results || [])) {
    const up = await env.DB.prepare(`UPDATE referrals SET qualified=1, qualified_at=?2 WHERE invitee=?1 AND qualified=0`).bind(row.invitee, nowMs).run();
    if (up.meta && up.meta.changes) await grant(env, me, 'ref_inviter', { gold: REF_INVITER_GOLD }, nowMs);
  }
  const [rw, st] = await env.DB.batch([
    env.DB.prepare(`SELECT id, kind, payload, created FROM rewards WHERE pid=?1 AND claimed=0 ORDER BY id LIMIT 20`).bind(me),
    env.DB.prepare(`SELECT COUNT(*) AS invited, COALESCE(SUM(qualified),0) AS qualified FROM referrals WHERE inviter=?1`).bind(me),
  ]);
  const rewards = (rw.results || []).map(r => ({ id: r.id, kind: r.kind, created: r.created, payload: safeJson(r.payload) }));
  const s0 = (st.results && st.results[0]) || { invited: 0, qualified: 0 };
  return json({ rewards, invited: s0.invited, qualified: s0.qualified }, 200, cors);
}
async function handleClaim(request, env, cors, nowMs = Date.now()) {
  const body = await readBody(request); if (!body) return json({ error: 'bad_json' }, 400, cors);
  const me = await authPid(body, env); if (!me) return json({ error: 'bad_signature' }, 401, cors);
  const ids = Array.isArray(body.ids) ? body.ids.filter(Number.isInteger).slice(0, 20) : [];
  const claimed = [];
  for (const id of ids) {
    const row = await env.DB.prepare(`SELECT id, kind, payload FROM rewards WHERE id=?1 AND pid=?2 AND claimed=0`).bind(id, me).first();
    if (!row) continue;
    const up = await env.DB.prepare(`UPDATE rewards SET claimed=1, claimed_at=?3 WHERE id=?1 AND pid=?2 AND claimed=0`).bind(id, me, nowMs).run();
    if (up.meta && up.meta.changes) claimed.push({ id: row.id, kind: row.kind, payload: safeJson(row.payload) });
  }
  return json({ claimed }, 200, cors);
}
function safeJson(t) { try { return JSON.parse(t); } catch { return {}; } }

/* ---------- мировой босс недели ----------
 * Один босс на ISO-неделю для всех. Попытка — 10 раундов боя на клиенте, урон всех игроков суммируется.
 * Одна попытка в сутки (UTC). Убили — каждому участнику посылка с золотом (больше вклад — больше награда),
 * добившему — бонус. Не убили за неделю — наград нет.
 * Запас здоровья следующей недели: убили — на 15% больше прошлого, не убили — на 20% меньше
 * (так он сам подстраивается под число и силу игроков). Первая неделя — BOSS_BASE_HP. */
const BOSS_KEYS = ['dragon', 'giants', 'liches', 'demons', 'cyclopes', 'trolls'];
const BOSS_BASE_HP = 60000, BOSS_MIN_HP = 15000, BOSS_MAX_HP = 50000000;
const BOSS_MAX_POW = 400000;           // правдоподобная сила армии
const BOSS_DMG_PER_POW = 14;           // за 10 раундов армия не наносит больше ~14× своей силы
const BOSS_GOLD_BASE = 300, BOSS_GOLD_TOP = 900, BOSS_KILL_BONUS = 500;
function utcDay(ms) { return new Date(ms).toISOString().slice(0, 10); }
function prevWeekId(week) {
  // понедельник этой недели минус 7 дней
  const y = +week.slice(0, 4), w = +week.slice(6);
  const jan4 = Date.UTC(y, 0, 4), mon1 = jan4 - ((new Date(jan4).getUTCDay() + 6) % 7) * 864e5;
  return isoWeekId(mon1 + (w - 1) * 7 * 864e5 - 7 * 864e5 + 3 * 864e5);
}
async function bossWeek(env, week, nowMs) {
  let row = await env.DB.prepare(`SELECT week, key, hp, killed, killed_at FROM boss_weeks WHERE week=?1`).bind(week).first();
  if (row) return row;
  const prev = await env.DB.prepare(`SELECT hp, killed FROM boss_weeks WHERE week=?1`).bind(prevWeekId(week)).first();
  let hp = prev ? Math.round(prev.hp * (prev.killed ? 1.15 : 0.8)) : BOSS_BASE_HP;
  hp = Math.max(BOSS_MIN_HP, Math.min(BOSS_MAX_HP, hp));
  const y = +week.slice(0, 4), w = +week.slice(6), key = BOSS_KEYS[(y * 53 + w) % BOSS_KEYS.length];
  await env.DB.prepare(`INSERT OR IGNORE INTO boss_weeks (week, key, hp, created) VALUES (?1, ?2, ?3, ?4)`).bind(week, key, hp, nowMs).run();
  return await env.DB.prepare(`SELECT week, key, hp, killed, killed_at FROM boss_weeks WHERE week=?1`).bind(week).first();
}
async function bossState(env, week, me, nowMs) {
  const b = await bossWeek(env, week, nowMs);
  const [tot, top, mine, today] = await env.DB.batch([
    env.DB.prepare(`SELECT COALESCE(SUM(dmg),0) AS dmg, COUNT(DISTINCT pid) AS n FROM boss_hits WHERE week=?1`).bind(week),
    env.DB.prepare(`SELECT pid, MAX(name) AS name, SUM(dmg) AS dmg FROM boss_hits WHERE week=?1 GROUP BY pid ORDER BY 3 DESC LIMIT 10`).bind(week),
    env.DB.prepare(`SELECT COALESCE(SUM(dmg),0) AS dmg, COUNT(*) AS tries FROM boss_hits WHERE week=?1 AND pid=?2`).bind(week, me || ''),
    env.DB.prepare(`SELECT 1 AS x FROM boss_hits WHERE week=?1 AND pid=?2 AND day=?3`).bind(week, me || '', utcDay(nowMs)),
  ]);
  const t = (tot.results && tot.results[0]) || { dmg: 0, n: 0 }, m = (mine.results && mine.results[0]) || { dmg: 0, tries: 0 };
  return {
    week, key: b.key, hp: b.hp, dmg: Math.min(t.dmg, b.hp), participants: t.n, killed: !!b.killed, killed_at: b.killed_at || null,
    top: (top.results || []).map(r => ({ name: r.name || 'Игрок', dmg: r.dmg, me: r.pid === me })),
    me: me ? { dmg: m.dmg, tries: m.tries, today: !!(today.results && today.results.length) } : null,
    day: utcDay(nowMs),
  };
}
async function handleBoss(request, env, cors, nowMs = Date.now()) {
  const body = await readBody(request); if (!body) return json({ error: 'bad_json' }, 400, cors);
  const me = body.initData ? await authPid(body, env) : null;
  return json(await bossState(env, isoWeekId(nowMs), me, nowMs), 200, cors);
}
async function handleBossHit(request, env, cors, nowMs = Date.now()) {
  const body = await readBody(request); if (!body) return json({ error: 'bad_json' }, 400, cors);
  const user = await verifyInitData(String(body.initData || ''), env.BOT_TOKEN);
  if (!user) return json({ error: 'bad_signature' }, 401, cors);
  const pid = await playerIdFromTelegram(user.id), week = isoWeekId(nowMs);
  if (String(body.week || '') !== week) return json({ error: 'bad_week' }, 400, cors);
  const dmg = Number(body.dmg), pow = Number(body.pow);
  if (!Number.isInteger(pow) || pow < 1 || pow > BOSS_MAX_POW) return json({ error: 'bad_pow' }, 400, cors);
  if (!Number.isInteger(dmg) || dmg < 0 || dmg > pow * BOSS_DMG_PER_POW) return json({ error: 'bad_dmg' }, 400, cors);
  const b = await bossWeek(env, week, nowMs);
  if (b.killed) return json({ error: 'killed', state: await bossState(env, week, pid, nowMs) }, 409, cors);
  const res = await env.DB.prepare(
    `INSERT OR IGNORE INTO boss_hits (week, pid, day, name, dmg, pow, v, created) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)`
  ).bind(week, pid, utcDay(nowMs), cleanName(user), dmg, pow, clip(body.v, 16), nowMs).run();
  if (!res.meta || res.meta.changes === 0) return json({ error: 'already', state: await bossState(env, week, pid, nowMs) }, 409, cors);
  // повержен? — помечаем один раз (UPDATE … WHERE killed=0 гарантирует, что награды раздаст ровно один запрос)
  let killedNow = false;
  const tot = await env.DB.prepare(`SELECT COALESCE(SUM(dmg),0) AS dmg FROM boss_hits WHERE week=?1`).bind(week).first();
  if (tot.dmg >= b.hp) {
    const up = await env.DB.prepare(`UPDATE boss_weeks SET killed=1, killed_at=?2 WHERE week=?1 AND killed=0`).bind(week, nowMs).run();
    if (up.meta && up.meta.changes) { killedNow = true; await bossRewards(env, week, b, pid, nowMs); }
  }
  return json({ ok: true, killed_now: killedNow, state: await bossState(env, week, pid, nowMs) }, 200, cors);
}
async function bossRewards(env, week, b, killer, nowMs) {
  const rows = (await env.DB.prepare(`SELECT pid, SUM(dmg) AS dmg FROM boss_hits WHERE week=?1 GROUP BY pid HAVING SUM(dmg)>0`).bind(week).all()).results || [];
  const best = Math.max(1, ...rows.map(r => r.dmg));
  const stmts = rows.map(r => {
    const gold = Math.round(BOSS_GOLD_BASE + (BOSS_GOLD_TOP - BOSS_GOLD_BASE) * Math.sqrt(r.dmg / best)) + (r.pid === killer ? BOSS_KILL_BONUS : 0);
    return env.DB.prepare(`INSERT INTO rewards (pid, kind, payload, created) VALUES (?1, 'boss', ?2, ?3)`)
      .bind(r.pid, JSON.stringify({ gold, week, boss: b.key, killer: r.pid === killer }), nowMs);
  });
  for (let i = 0; i < stmts.length; i += 50) await env.DB.batch(stmts.slice(i, i + 50));
}

/* ---------- бот: ответы на команды ----------
 * Отвечаем только в личном чате с ботом. Ссылки берутся из [vars] в wrangler.toml (есть значения по умолчанию). */
const BOT_LINKS = { app: 'https://t.me/morveyn_game_bot/PlayMorveyn', channel: 'https://t.me/morveynRPG', group: 'https://t.me/+to-YZ0feA7xjODBi', feedback: 'lloyd3101' };
function botLinks(env) { return { app: env.BOT_APP_URL || BOT_LINKS.app, channel: env.CHANNEL_URL || BOT_LINKS.channel, group: env.GROUP_URL || BOT_LINKS.group, feedback: env.FEEDBACK_USERNAME || BOT_LINKS.feedback }; }
function esc(t) { return String(t || '').replace(/[&<>]/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[ch])); }
async function tgCall(env, method, payload) {
  return fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/${method}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
}
function mainKeyboard(L) {
  return { inline_keyboard: [
    [{ text: '▶️ Играть', url: L.app }],
    [{ text: '🏆 Испытание недели', url: L.app + '?startapp=challenge' }],
    [{ text: '📢 Канал', url: L.channel }, { text: '💬 Обсуждение', url: L.group }],
  ] };
}
function fmtMin(ms) { const m = Math.round(ms / 60000); return m >= 60 ? `${Math.floor(m / 60)} ч ${m % 60} мин` : `${m} мин`; }
async function handleTgUpdate(upd, env) {
  const m = upd && upd.message;
  if (!m || !m.chat || m.chat.type !== 'private' || typeof m.text !== 'string') return;
  const L = botLinks(env), chat = m.chat.id;
  const cmd = m.text.trim().split(/\s+/)[0].split('@')[0].toLowerCase();
  const send = (text, markup) => tgCall(env, 'sendMessage', { chat_id: chat, text, parse_mode: 'HTML', disable_web_page_preview: true, ...(markup ? { reply_markup: markup } : {}) });
  const HELP = 'Команды:\n/play — играть\n/top — лидеры испытания недели\n/invite — пригласить друга (вам обоим бонус)\n/channel — канал и обсуждение\n/help — помощь';

  if (cmd === '/start') {
    const hi = m.from && m.from.first_name ? `Привет, ${esc(m.from.first_name)}! ` : '';
    const text = `⚔️ ${hi}<b>Морвейн</b> — пошаговая стратегия прямо в Telegram.\n\nСобирай армию, захватывай замки и покоряй пять земель. Каждую неделю — испытание: одна карта для всех и таблица рекордов.\n\n${HELP}`;
    if (env.COVER_URL) return tgCall(env, 'sendPhoto', { chat_id: chat, photo: env.COVER_URL, caption: text, parse_mode: 'HTML', reply_markup: mainKeyboard(L) });
    return send(text, mainKeyboard(L));
  }
  if (cmd === '/play') return send('▶️ Игра открывается прямо в Telegram:', { inline_keyboard: [[{ text: '▶️ Играть в Морвейн', url: L.app }]] });
  if (cmd === '/channel') return send('📢 Новости игры — в канале, а поговорить с другими игроками и рассказать об ошибках — в обсуждении:', { inline_keyboard: [[{ text: '📢 Канал', url: L.channel }], [{ text: '💬 Обсуждение', url: L.group }]] });
  if (cmd === '/top') {
    const week = isoWeekId(Date.now());
    const rows = (await env.DB.prepare(`SELECT name, title, days, active_ms FROM scores WHERE week=?1 ORDER BY days, active_ms LIMIT 3`).bind(week).all()).results || [];
    const medals = ['🥇', '🥈', '🥉'];
    const text = rows.length
      ? `🏆 <b>Испытание недели</b> — лидеры:\n\n` + rows.map((r, i) => `${medals[i]} ${esc(r.name)}${r.title ? ` «${esc(r.title)}»` : ''} — ${r.days} дн., ${fmtMin(r.active_ms)}`).join('\n')
      : '🏆 На этой неделе испытание ещё никто не прошёл — будьте первым!';
    return send(text, { inline_keyboard: [[{ text: '🏆 Принять вызов', url: L.app + '?startapp=challenge' }]] });
  }
  if (cmd === '/invite') {
    const pid = await playerIdFromTelegram(m.from.id);
    const known = await env.DB.prepare(`SELECT 1 FROM players WHERE pid=?1`).bind(pid).first();
    if (!known) return send('Сначала откройте игру хотя бы раз — тогда ваша ссылка-приглашение заработает.', { inline_keyboard: [[{ text: '▶️ Играть', url: L.app }]] });
    const link = `${L.app}?startapp=ref_${pid.slice(3, 13)}`;
    const shareText = '⚔️ Играю в «Морвейн» — пошаговую стратегию прямо в Telegram. Заходи по моей ссылке — получишь 300 золота на старте!';
    return send(`👥 Ваша ссылка-приглашение:\n${link}\n\nДруг получит 300💰 на старте, а вы — 200💰, когда он выиграет первый бой.`,
      { inline_keyboard: [[{ text: '📤 Отправить другу', url: `https://t.me/share/url?url=${encodeURIComponent(link)}&text=${encodeURIComponent(shareText)}` }]] });
  }
  if (cmd === '/help') return send(`ℹ️ <b>Морвейн</b>\n\n${HELP}\n\nНашли ошибку или есть идея? Напишите в обсуждение или @${esc(L.feedback)}.`, mainKeyboard(L));
  return send(`Я пока отвечаю только на команды 🙂\n\n${HELP}`, mainKeyboard(L));
}

async function ranksFor(env, week, days, active) {
  const r = await env.DB.prepare(
    `SELECT
       (SELECT COUNT(*) FROM scores WHERE week=?1 AND (days<?2 OR (days=?2 AND active_ms<?3))) + 1 AS rank_days,
       (SELECT COUNT(*) FROM scores WHERE week=?1 AND active_ms<?3) + 1 AS rank_time,
       (SELECT COUNT(*) FROM scores WHERE week=?1) AS total`
  ).bind(week, days, active).first();
  return { rank_days: r.rank_days, rank_time: r.rank_time, total: r.total };
}

async function handleLeaderboard(request, env, cors, nowMs = Date.now()) {
  const body = await readBody(request);
  if (!body) return json({ error: 'bad_json' }, 400, cors);
  const week = String(body.week || isoWeekId(nowMs));
  if (!/^\d{4}-W\d{2}$/.test(week)) return json({ error: 'bad_week' }, 400, cors);
  let myPid = null;
  if (body.initData) { const user = await verifyInitData(String(body.initData), env.BOT_TOKEN); if (user) myPid = await playerIdFromTelegram(user.id); }

  const [byDays, byTime, total] = await env.DB.batch([
    env.DB.prepare(`SELECT pid, name, hero, days, active_ms, title FROM scores WHERE week=?1 ORDER BY days, active_ms LIMIT 50`).bind(week),
    env.DB.prepare(`SELECT pid, name, hero, days, active_ms, title FROM scores WHERE week=?1 ORDER BY active_ms, days LIMIT 50`).bind(week),
    env.DB.prepare(`SELECT COUNT(*) AS n FROM scores WHERE week=?1`).bind(week),
  ]);
  // коды игроков наружу не отдаём — только отметка «это вы»
  const strip = rows => (rows.results || []).map(r => ({ name: r.name, title: r.title || '', hero: r.hero, days: r.days, active_ms: r.active_ms, me: r.pid === myPid }));
  let me = null;
  if (myPid) {
    const row = await env.DB.prepare(`SELECT days, active_ms FROM scores WHERE week=?1 AND pid=?2`).bind(week, myPid).first();
    if (row) me = { days: row.days, active_ms: row.active_ms, ...(await ranksFor(env, week, row.days, row.active_ms)) };
  }
  return json({ week, total: (total.results && total.results[0] && total.results[0].n) || 0, top_days: strip(byDays), top_time: strip(byTime), me }, 200, cors);
}

/* ---------- проверка подписи Telegram (initData) ----------
 * secret = HMAC_SHA256(key="WebAppData", data=BOT_TOKEN)
 * hash   = hex(HMAC_SHA256(key=secret, data=data_check_string))
 * data_check_string — все поля кроме hash, по алфавиту, "ключ=значение" через перевод строки.
 * Возвращает объект user или null. */
export async function verifyInitData(initData, botToken, nowSec = Math.floor(Date.now() / 1000)) {
  if (!botToken || !initData) return null;
  const params = new URLSearchParams(initData);
  const hash = params.get('hash');
  if (!hash || !/^[0-9a-f]{64}$/.test(hash)) return null;
  const pairs = [];
  for (const [k, val] of params) if (k !== 'hash') pairs.push(`${k}=${val}`);
  pairs.sort();
  const dataCheck = pairs.join('\n');

  const enc = new TextEncoder();
  const secret = await hmac(enc.encode('WebAppData'), enc.encode(botToken));
  const sig = await hmac(secret, enc.encode(dataCheck));
  if (!timingSafeEqual(hex(sig), hash)) return null;

  const authDate = Number(params.get('auth_date') || 0);
  if (!authDate || nowSec - authDate > INITDATA_MAX_AGE) return null;
  try {
    const user = JSON.parse(params.get('user') || 'null');
    return user && Number.isFinite(user.id) ? user : null;
  } catch { return null; }
}

export async function playerIdFromTelegram(id) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('morveyn:' + id));
  return 'tg_' + hex(new Uint8Array(buf).slice(0, 8));
}

/* ---------- вспомогательное ---------- */
async function hmac(keyBytes, dataBytes) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, dataBytes));
}
function hex(bytes) { return [...bytes].map(b => b.toString(16).padStart(2, '0')).join(''); }
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
function allowedList(env) { return String(env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean); }
function originAllowed(origin, env) { return allowedList(env).includes(origin); }
function corsHeaders(origin, env) {
  const h = { 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Max-Age': '86400', 'Vary': 'Origin' };
  if (originAllowed(origin, env)) h['Access-Control-Allow-Origin'] = origin;
  return h;
}
function json(obj, status, headers) { return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json', ...headers } }); }
function clip(x, n) { return x == null ? null : String(x).slice(0, n); }
function int(x) { const n = Number(x); return Number.isFinite(n) ? Math.round(n) : null; }
