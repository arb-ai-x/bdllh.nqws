const express = require('express'), helmet = require('helmet'), rateLimit = require('express-rate-limit');
const crypto = require('crypto'), { Pool } = require('pg');
const app = express(), PASS = process.env.ADMIN_PASSWORD || '';
const SECRET = process.env.SECRET || crypto.randomBytes(32).toString('hex');
const url = process.env.DATABASE_URL;
const db = new Pool({ connectionString: url, ssl: url && !/localhost/.test(url) ? { rejectUnauthorized: false } : false });

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'"], imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"],
  styleSrc: ["'self'", 'https://fonts.googleapis.com'], fontSrc: ['https://fonts.gstatic.com'] } } }));
app.use(express.json({ limit: '20kb' }));

const hmac = p => crypto.createHmac('sha256', SECRET).update(p).digest('hex');
const sign = exp => exp + '.' + hmac(String(exp));
const valid = t => { try { const [p, s] = t.split('.'), e = hmac(p);
  return Date.now() < +p && s.length === e.length && crypto.timingSafeEqual(Buffer.from(s), Buffer.from(e)); } catch { return false; } };
const auth = (q, r, n) => valid((q.get('authorization') || '').slice(7)) ? n() : r.sendStatus(401);
const lim = (m, w) => rateLimit({ windowMs: w * 60000, limit: m, standardHeaders: true, legacyHeaders: false });
const str = (v, n) => typeof v === 'string' && v.trim().length > 0 && v.length <= n;

db.query(`create table if not exists players(id serial primary key, name text not null, game text not null,
  contact text, lv int default 1, created_at timestamptz default now());
  create table if not exists posts(id serial primary key, title text not null, body text not null,
  tpl text default 'neon', font text default 'Cairo', created_at timestamptz default now())`)
  .catch(e => console.error('DB init failed:', e.message));

app.get('/api/board', async (_q, r) => r.json((await db.query('select name,game,lv from players order by lv desc,id limit 20')).rows));
app.get('/api/posts', async (_q, r) => r.json((await db.query('select * from posts order by id desc limit 50')).rows));

app.post('/api/register', lim(10, 60), async (q, r) => {
  const { name, game, contact } = q.body || {};
  if (!str(name, 40) || !str(game, 40) || (contact && !str(contact, 80))) return r.status(400).json({ error: 'بيانات غير صحيحة' });
  await db.query('insert into players(name,game,contact) values($1,$2,$3)', [name.trim(), game.trim(), contact || null]);
  r.json({ ok: true });
});

app.post('/api/admin/login', lim(5, 15), (q, r) => {
  const a = crypto.createHash('sha256').update(String((q.body || {}).password || '')).digest();
  const b = crypto.createHash('sha256').update(PASS).digest();
  if (!PASS || !crypto.timingSafeEqual(a, b)) return r.status(401).json({ error: 'كلمة السر غلط' });
  r.json({ token: sign(Date.now() + 3600000) });
});

app.get('/api/admin/players', auth, async (_q, r) => r.json((await db.query('select * from players order by id desc')).rows));
app.patch('/api/admin/players/:id', auth, async (q, r) => {
  const lv = Math.max(1, Math.min(99, parseInt(q.body.lv, 10) || 1));
  await db.query('update players set lv=$1 where id=$2', [lv, +q.params.id]); r.json({ ok: true });
});
app.delete('/api/admin/players/:id', auth, async (q, r) => { await db.query('delete from players where id=$1', [+q.params.id]); r.json({ ok: true }); });
app.post('/api/admin/posts', auth, async (q, r) => {
  const { title, body, tpl, font } = q.body || {};
  if (!str(title, 80) || !str(body, 1500) || !['neon', 'fire', 'ice'].includes(tpl) ||
      !['Cairo', 'Tajawal', 'Lalezar', 'Reem Kufi'].includes(font)) return r.status(400).json({ error: 'بيانات غير صحيحة' });
  await db.query('insert into posts(title,body,tpl,font) values($1,$2,$3,$4)', [title.trim(), body.trim(), tpl, font]); r.json({ ok: true });
});
app.delete('/api/admin/posts/:id', auth, async (q, r) => { await db.query('delete from posts where id=$1', [+q.params.id]); r.json({ ok: true }); });

app.use(express.static('public'));
app.use((e, _q, r, _n) => { console.error(e); r.status(500).json({ error: 'خطأ في الخادم' }); });
app.listen(process.env.PORT || 3000);
