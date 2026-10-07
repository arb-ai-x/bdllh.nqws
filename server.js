// أربكس الدردشة: دردشة ومكالمات بين الأعضاء (ملف واحد)
// تم إنشاء الموقع بواسطة عبدالله ابو ناقوس
const express = require('express'), helmet = require('helmet'), rateLimit = require('express-rate-limit');
const crypto = require('crypto'), http = require('http'), { Pool } = require('pg'), { Server } = require('socket.io');
const app = express(), server = http.createServer(app), io = new Server(server, { maxHttpBufferSize: 1e5 });
const PASS = process.env.ADMIN_PASSWORD || '', MAX = +process.env.MAX_ACCOUNTS || 1000;
let SECRET = process.env.SECRET || '';
const url = process.env.DATABASE_URL;
const db = new Pool({ connectionString: url, ssl: url && !/localhost/.test(url) ? { rejectUnauthorized: false } : false });
process.on('unhandledRejection', e => console.error(e));

// أي خطأ داخل async بيروح لمعالج الأخطاء بدل ما الطلب يعلّق (يشتغل على Express 4 و 5)
for (const m of ['get', 'post', 'put', 'delete']) {
  const orig = app[m].bind(app);
  app[m] = (p, ...h) => orig(p, ...h.map(f => typeof f === 'function' && f.length < 4
    ? (q, r, n) => Promise.resolve(f(q, r, n)).catch(n) : f));
}

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'"], imgSrc: ["'self'", 'data:'], connectSrc: ["'self'", 'wss:', 'ws:'], mediaSrc: ["'self'", 'blob:'],
  styleSrc: ["'self'", 'https://fonts.googleapis.com'], fontSrc: ['https://fonts.gstatic.com'] } } }));
app.use(express.json({ limit: '20kb' }));

const online = new Map(), calls = new Map(), answered = new Set(), timers = new Map(), hits = new Map();

const hmac = p => crypto.createHmac('sha256', SECRET).update(p).digest('hex');
const safeEq = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
const sign = exp => exp + '.' + hmac(String(exp));
const valid = t => { try { const [p, s] = t.split('.'); return Date.now() < +p && safeEq(s, hmac(p)); } catch { return false; } };
const auth = (q, r, n) => valid((q.get('authorization') || '').slice(7)) ? n() : r.sendStatus(401);
const lim = (m, w) => rateLimit({ windowMs: w * 60000, limit: m, standardHeaders: true, legacyHeaders: false });
const str = (v, n) => typeof v === 'string' && v.trim().length > 0 && v.length <= n;
const idp = v => { const n = Number(v); return Number.isInteger(n) && n > 0 && n < 2147483647 ? n : 0; };
const AL = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const rnd = (n, al) => Array.from({ length: n }, () => al[crypto.randomInt(al.length)]).join('');
const hashPw = (p, s = crypto.randomBytes(8).toString('hex')) => s + ':' + crypto.scryptSync(p, s, 32, { N: 1024 }).toString('hex');
const checkPw = (p, h) => { const [s, x] = String(h).split(':'); return safeEq(x, crypto.scryptSync(p, s, 32, { N: 1024 }).toString('hex')); };
const ck = (q, n) => ((q.headers.cookie || '').split('; ').find(c => c.startsWith(n + '=')) || '').slice(n.length + 1);
const ssign = id => { const e = Date.now() + 6048e5; return id + '.' + e + '.' + hmac(id + '.' + e); };
const sread = t => { try { const [i, e, s] = t.split('.'); return Date.now() < +e && safeEq(s, hmac(i + '.' + e)) ? +i : 0; } catch { return 0; } };
const sess = (r, id, dv) => { const o = { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 31536e6 };
  r.cookie('dv', dv, o).cookie('sid', ssign(id), { ...o, maxAge: 6048e5 }); };
const getAcc = async (q) => { const id = sread(ck(q, 'sid'));
  const a = id && (await db.query('select * from accounts where id=$1', [id])).rows[0];
  return a && !a.banned && a.device === ck(q, 'dv') ? a : null; };
const member = async (q, r, n) => { const a = await getAcc(q); if (!a) return r.status(401).json({ error: 'سجّل دخولك أول' }); q.acc = a; n(); };
const blocked = async (a, b) => (await db.query('select 1 from blocks where (a=$1 and b=$2) or (a=$2 and b=$1)', [a, b])).rowCount > 0;
const nm = `coalesce(name,'عضو '||right(num,3))`;
const tooFast = id => { const now = Date.now(), a = (hits.get(id) || []).filter(x => now - x < 10000);
  const f = a.length >= 20; if (!f) a.push(now); hits.set(id, a); return f; };

async function init() {
  await db.query(`create table if not exists accounts(id serial primary key, num text unique not null, pass_hash text not null,
    device text, claimed_at timestamptz, created_at timestamptz default now());
    alter table accounts add column if not exists name text;
    alter table accounts add column if not exists bio text;
    alter table accounts add column if not exists banned boolean default false;
    create table if not exists msgs(id bigserial primary key, from_id int not null, to_id int not null, body text not null,
    seen boolean default false, created_at timestamptz default now());
    create index if not exists msgs_pair on msgs(from_id,to_id);
    create table if not exists blocks(a int not null, b int not null, primary key(a,b));
    create table if not exists reports(id serial primary key, from_id int not null, to_id int not null, reason text,
    created_at timestamptz default now());
    alter table reports add column if not exists evidence text;
    create table if not exists settings(k text primary key, v text not null)`);
  if (!SECRET) { // إذا ما حطيت SECRET بالبيئة، بنخزّنه بقاعدة البيانات عشان ما يتغيّر مع كل تشغيل
    await db.query("insert into settings(k,v) values('secret',$1) on conflict do nothing", [crypto.randomBytes(32).toString('hex')]);
    SECRET = (await db.query("select v from settings where k='secret'")).rows[0].v;
  }
  setInterval(() => db.query("delete from msgs where created_at < now() - interval '90 days'").catch(e => console.error(e)), 6 * 3600e3).unref();
}

/* ---------- حسابات ---------- */
app.post('/api/signup', lim(5, 60), async (q, r) => {
  if (!(q.body || {}).adult) return r.status(400).json({ error: 'لازم تأكد إن عمرك 18 سنة أو أكثر' });
  const old = ck(q, 'dv');
  if (old && (await db.query('select 1 from accounts where device=$1', [old])).rowCount) return r.status(403).json({ error: 'عندك حساب على هالجهاز' });
  if ((await db.query('select count(*)::int c from accounts')).rows[0].c >= MAX) return r.status(403).json({ error: 'التسجيل مغلق، انتهت الحسابات' });
  const pass = rnd(10, AL), dv = crypto.randomBytes(16).toString('hex');
  for (let i = 0; i < 20; i++) {
    const num = rnd(6, '0123456789');
    const x = await db.query('insert into accounts(num,pass_hash,device,claimed_at,name) values($1,$2,$3,now(),$4) on conflict do nothing returning id',
      [num, hashPw(pass), dv, 'عضو ' + num.slice(-3)]);
    if (x.rowCount) { sess(r, x.rows[0].id, dv); return r.json({ num, pass }); }
  }
  r.status(500).json({ error: 'جرّب مرة ثانية' });
});
app.post('/api/login', lim(10, 15), async (q, r) => {
  const { num, pass } = q.body || {};
  if (!str(num, 12) || !str(pass, 40)) return r.status(400).json({ error: 'اكتب الرقم وكلمة السر' });
  const a = (await db.query('select * from accounts where num=$1', [num.trim()])).rows[0];
  if (!a || !checkPw(pass, a.pass_hash)) return r.status(401).json({ error: 'رقم أو كلمة سر غلط' });
  if (a.banned) return r.status(403).json({ error: 'هذا الحساب محظور' });
  let dv = ck(q, 'dv');
  if (a.device && a.device !== dv) return r.status(403).json({ error: 'هذا الحساب مرتبط بجهاز ثاني' });
  if (!a.device) {
    dv = crypto.randomBytes(16).toString('hex');
    const u = await db.query('update accounts set device=$1, claimed_at=now() where id=$2 and device is null returning id', [dv, a.id]);
    if (!u.rowCount) return r.status(403).json({ error: 'هذا الحساب مستخدم' });
  }
  sess(r, a.id, dv); r.json({ ok: true });
});
app.post('/api/logout', (_q, r) => { r.clearCookie('sid'); r.json({ ok: true }); });
app.get('/api/me', member, (q, r) => r.json({ id: q.acc.id, num: q.acc.num, name: q.acc.name || 'عضو ' + q.acc.num.slice(-3), bio: q.acc.bio || '' }));
app.put('/api/me', member, async (q, r) => {
  const { name, bio } = q.body || {};
  if (!str(name, 30) || (bio && typeof bio !== 'string')) return r.status(400).json({ error: 'اسم غير صحيح' });
  await db.query('update accounts set name=$1, bio=$2 where id=$3', [name.trim(), (bio || '').slice(0, 120), q.acc.id]); r.json({ ok: true });
});
app.get('/api/ice', member, (q, r) => {
  const s = [{ urls: 'stun:stun.l.google.com:19302' }];
  if (process.env.TURN_URL) {
    const urls = process.env.TURN_URL.split(',').map(x => x.trim());
    if (process.env.TURN_SECRET) { // بيانات TURN مؤقتة (coturn use-auth-secret)
      const u = (Math.floor(Date.now() / 1000) + 3600) + ':' + q.acc.id;
      s.push({ urls, username: u, credential: crypto.createHmac('sha1', process.env.TURN_SECRET).update(u).digest('base64') });
    } else if (process.env.TURN_USER) s.push({ urls, username: process.env.TURN_USER, credential: process.env.TURN_PASS });
  }
  r.json({ servers: s });
});

/* ---------- أعضاء ورسائل ---------- */
app.get('/api/members', member, async (q, r) => r.json((await db.query(
  `select id, ${nm} name, coalesce(bio,'') bio from accounts where id<>$1 and not coalesce(banned,false) and device is not null
   and id not in (select b from blocks where a=$1 union select a from blocks where b=$1) order by id desc limit 500`, [q.acc.id])).rows));
app.get('/api/unread', member, async (q, r) => r.json((await db.query(
  'select from_id, count(*)::int c from msgs where to_id=$1 and not seen group by from_id', [q.acc.id])).rows));
app.get('/api/chat/:id', member, async (q, r) => {
  const o = idp(q.params.id); if (!o) return r.sendStatus(400);
  if (await blocked(q.acc.id, o)) return r.json([]);
  const rows = (await db.query(`select * from (select id,from_id,to_id,body,created_at from msgs
    where (from_id=$1 and to_id=$2) or (from_id=$2 and to_id=$1) order by id desc limit 100) x order by id`, [q.acc.id, o])).rows;
  await db.query('update msgs set seen=true where to_id=$1 and from_id=$2 and not seen', [q.acc.id, o]); r.json(rows);
});
app.post('/api/seen/:id', member, async (q, r) => {
  const o = idp(q.params.id); if (!o) return r.sendStatus(400);
  await db.query('update msgs set seen=true where to_id=$1 and from_id=$2 and not seen', [q.acc.id, o]); r.json({ ok: true });
});
app.post('/api/report', member, lim(20, 60), async (q, r) => {
  const to = idp((q.body || {}).id); if (!to || to === q.acc.id) return r.sendStatus(400);
  const ms = (await db.query(`select from_id,body from msgs where (from_id=$1 and to_id=$2) or (from_id=$2 and to_id=$1)
    order by id desc limit 10`, [q.acc.id, to])).rows.reverse();
  const ev = ms.map(m => (m.from_id === q.acc.id ? 'المُبلِّغ' : 'المُبلَّغ عليه') + ': ' + m.body).join('\n');
  await db.query('insert into reports(from_id,to_id,reason,evidence) values($1,$2,$3,$4)',
    [q.acc.id, to, String(q.body.reason || '').slice(0, 200), ev || null]); r.json({ ok: true });
});
app.post('/api/block', member, async (q, r) => {
  const to = idp((q.body || {}).id); if (!to || to === q.acc.id) return r.sendStatus(400);
  await db.query('insert into blocks(a,b) values($1,$2) on conflict do nothing', [q.acc.id, to]); r.json({ ok: true });
});

/* ---------- الإدارة ---------- */
app.post('/api/admin/login', lim(5, 15), (q, r) => {
  const h = v => crypto.createHash('sha256').update(String(v)).digest();
  if (!PASS || !crypto.timingSafeEqual(h((q.body || {}).password || ''), h(PASS))) return r.status(401).json({ error: 'كلمة السر غلط' });
  r.json({ token: sign(Date.now() + 3600000) });
});
app.get('/api/admin/data', auth, async (_q, r) => {
  const accounts = (await db.query(`select id,num,${nm} name,coalesce(banned,false) banned,claimed_at from accounts order by id desc limit 1000`)).rows;
  const reports = (await db.query(`select r.id,r.reason,r.to_id,(r.evidence is not null) ev,
    coalesce(a.name,'عضو '||right(a.num,3)) fname, b.num tnum, b.name tname, coalesce(b.banned,false) banned
    from reports r join accounts a on a.id=r.from_id join accounts b on b.id=r.to_id order by r.id desc limit 100`)).rows;
  r.json({ accounts, reports, max: MAX, online: online.size });
});
app.get('/api/admin/report/:id', auth, async (q, r) => {
  const x = (await db.query('select evidence from reports where id=$1', [idp(q.params.id)])).rows[0];
  r.json({ evidence: (x && x.evidence) || 'ما في أدلة محفوظة' });
});
app.post('/api/admin/ban/:id', auth, async (q, r) => {
  const on = !!(q.body || {}).on, id = idp(q.params.id); if (!id) return r.sendStatus(400);
  await db.query('update accounts set banned=$1 where id=$2', [on, id]);
  if (on) io.in('u:' + id).disconnectSockets(true);
  r.json({ ok: true });
});
app.post('/api/admin/reset/:id', auth, async (q, r) => {
  const p = rnd(10, AL), id = idp(q.params.id); if (!id) return r.sendStatus(400);
  await db.query('update accounts set pass_hash=$1, device=null, claimed_at=null where id=$2', [hashPw(p), id]);
  io.in('u:' + id).disconnectSockets(true); r.json({ pass: p });
});
app.delete('/api/admin/reports/:id', auth, async (q, r) => { await db.query('delete from reports where id=$1', [idp(q.params.id)]); r.json({ ok: true }); });

/* ---------- الاتصال المباشر (رسائل + إشارات المكالمات) ---------- */
const endPair = (a, b) => {
  for (const x of [a, b]) { calls.delete(x); answered.delete(x); clearTimeout(timers.get(x)); timers.delete(x); }
};
io.use(async (s, n) => {
  try { const a = await getAcc(s.request); if (a) { s.data.id = a.id; return n(); } } catch (e) { console.error(e); }
  n(new Error('auth'));
});
io.on('connection', s => {
  const id = s.data.id; s.join('u:' + id);
  online.set(id, (online.get(id) || 0) + 1);
  if (online.get(id) === 1) io.emit('presence', { id, on: true });
  s.emit('online', [...online.keys()]);

  s.on('msg', async (d, ack) => {
    ack = typeof ack === 'function' ? ack : () => {};
    try {
      const to = idp((d || {}).to), body = String((d || {}).body || '').trim().slice(0, 1000);
      if (!to || to === id || !body) return ack({ error: 'رسالة غير صالحة' });
      if (tooFast(id)) return ack({ error: 'بطّئ شوي' });
      const t = (await db.query('select banned from accounts where id=$1', [to])).rows[0];
      if (!t || t.banned || await blocked(id, to)) return ack({ error: 'ما بتقدر تراسل هالشخص' });
      const m = (await db.query('insert into msgs(from_id,to_id,body) values($1,$2,$3) returning id,from_id,to_id,body,created_at', [id, to, body])).rows[0];
      io.to('u:' + to).to('u:' + id).emit('msg', m); ack({ ok: true });
    } catch (e) { console.error(e); ack({ error: 'صار خطأ' }); }
  });

  s.on('typing', d => { const to = idp((d || {}).to); if (to && to !== id) io.to('u:' + to).emit('typing', { from: id }); });

  s.on('call:offer', async (d, ack) => {
    ack = typeof ack === 'function' ? ack : () => {};
    try {
      const to = idp((d || {}).to);
      if (!to || to === id || !online.has(to)) return ack({ error: 'الشخص مو أونلاين هلأ' });
      if (!d.sdp) return ack({ error: 'صار خطأ' });
      if (calls.has(id) || calls.has(to)) return ack({ error: 'مشغول، جرّب بعد شوي' });
      calls.set(id, to); calls.set(to, id); // نحجز المكالمة فوراً عشان إشارات ICE ما تضيع
      if (await blocked(id, to)) { endPair(id, to); return ack({ error: 'ما بتقدر تتصل فيه' }); }
      timers.set(id, setTimeout(() => { // مهلة 45 ثانية إذا ما حدا رد
        if (calls.get(id) === to && !answered.has(id)) { endPair(id, to); io.to('u:' + id).to('u:' + to).emit('call:end', { from: 0 }); }
      }, 45000));
      io.to('u:' + to).emit('call:offer', { from: id, sdp: d.sdp, video: !!d.video }); ack({ ok: true });
    } catch (e) { console.error(e); ack({ error: 'صار خطأ' }); }
  });
  s.on('call:answer', d => {
    const to = idp((d || {}).to); if (!to || calls.get(id) !== to) return;
    answered.add(id); answered.add(to); clearTimeout(timers.get(to)); timers.delete(to);
    io.to('u:' + to).emit('call:answer', { from: id, sdp: d.sdp });
  });
  s.on('call:ice', d => {
    const to = idp((d || {}).to); if (!to || calls.get(id) !== to) return;
    io.to('u:' + to).emit('call:ice', { from: id, c: d.c });
  });
  for (const ev of ['call:end', 'call:reject'])
    s.on(ev, d => { const to = idp((d || {}).to); if (!to || calls.get(id) !== to) return; endPair(id, to); io.to('u:' + to).emit(ev, { from: id }); });

  s.on('disconnect', () => {
    const c = (online.get(id) || 1) - 1;
    if (c > 0) { online.set(id, c); return; }
    online.delete(id); io.emit('presence', { id, on: false });
    const p = calls.get(id);
    if (p) { endPair(id, p); io.to('u:' + p).emit('call:end', { from: id }); }
  });
});

/* ---------- الواجهة ---------- */
const HTML = `<!doctype html>
<html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#07050f">
<title>أربكس الدردشة</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;700&family=Lalezar&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/style.css"></head><body>
<div class="bg" aria-hidden="true"><i></i><i></i></div>
<section id="land" class="hero">
  <div class="ring"><span>أ</span></div>
  <p class="kicker">أهلاً فيك في</p><h1>أربكس الدردشة</h1>
  <p class="by">تم إنشاء الموقع بواسطة <a href="https://www.instagram.com/bdllh.nqws" target="_blank" rel="noopener noreferrer">عبدالله ابو ناقوس</a></p>
  <p class="sub">دردشة ومكالمات حقيقية بين الأعضاء.</p>
  <a class="ig" href="https://www.instagram.com/bdllh.nqws" target="_blank" rel="noopener noreferrer">تابعني على انستجرام</a>
  <div class="links">
    <a href="https://www.instagram.com/rbkslbrmjh" target="_blank" rel="noopener noreferrer">انستجرام أربكس البرمجة</a>
    <a href="https://arb-ai-x.github.io/arabesque-de/" target="_blank" rel="noopener noreferrer">موقع أربكس البرمجة</a>
  </div>
  <form id="su" class="glass"><label class="chk"><input type="checkbox" name="adult"> أؤكد أن عمري 18 سنة أو أكثر وألتزم بقواعد الموقع</label>
    <button>سجّل واحصل على حسابك</button><p id="sumsg" role="status"></p></form>
  <div id="got" class="glass" hidden><p>حسابك جاهز. احفظهم هلأ، ما رح يظهروا مرة ثانية:</p>
    <p>رقمك: <b id="gnum"></b></p><p>كلمة السر: <b id="gpass"></b></p><button id="gok">حفظتهم، ادخل</button></div>
  <form id="lg" class="glass"><p>عندك حساب؟</p><input name="num" inputmode="numeric" placeholder="رقمك" maxlength="12" required>
    <input name="pass" type="password" placeholder="كلمة السر" autocomplete="current-password" maxlength="40" required>
    <button>دخول</button><p id="lgmsg" role="status"></p></form>
</section>
<section id="app" hidden>
  <aside><div class="brand">أربكس الدردشة</div>
    <div class="mebar"><b id="myname"></b><button id="edit">تعديل</button><button id="out">خروج</button></div>
    <input id="q" placeholder="ابحث عن عضو"><div id="list"></div></aside>
  <div id="chat"><p id="hint">اختر عضو من القائمة لتبدأ المحادثة.</p>
    <div id="cbox" hidden><div class="chead"><button id="back">رجوع</button><b id="cname"></b>
      <button id="vc">صوت</button><button id="vv">فيديو</button><button id="rep">إبلاغ</button><button id="blk">حظر</button></div>
      <div id="msgs"></div><p id="typing" hidden>يكتب...</p>
      <form id="send"><input id="txt" maxlength="1000" autocomplete="off" placeholder="اكتب رسالة"><button>إرسال</button></form></div></div>
</section>
<div id="call" hidden><video id="rv" autoplay playsinline></video><video id="lv" autoplay playsinline muted></video>
  <div class="cc"><button id="mute">كتم</button><button id="cam">كاميرا</button><button id="end">إنهاء</button></div></div>
<dialog id="ring"><p id="rtext"></p><button id="acc">رد</button> <button id="rej">رفض</button></dialog>
<footer><div class="foot">
  <p>تم إنشاء الموقع بواسطة <a href="https://www.instagram.com/bdllh.nqws" target="_blank" rel="noopener noreferrer">عبدالله ابو ناقوس</a></p>
  <p><a href="https://www.instagram.com/rbkslbrmjh" target="_blank" rel="noopener noreferrer">انستجرام أربكس البرمجة</a> ·
     <a href="https://arb-ai-x.github.io/arabesque-de/" target="_blank" rel="noopener noreferrer">موقع أربكس البرمجة</a></p>
  <p class="rules">للأعضاء 18 سنة فأكثر فقط. ممنوع الإساءة والتحرش وانتحال الشخصية، وأي بلاغ بيتراجع.</p></div>
  <button id="dot" aria-label="."></button></footer>
<dialog id="admin"><form method="dialog"><button>إغلاق</button></form>
<form id="alogin"><input type="password" id="pw" placeholder="كلمة السر" autocomplete="current-password"><button>دخول</button><p id="amsg" role="status"></p></form>
<div id="panel" hidden><h3>البلاغات</h3><div class="scroll"><table id="reps"></table></div>
<h3>الحسابات <small id="cnt"></small></h3><div class="scroll"><table id="accs"></table></div></div></dialog>
<script src="/socket.io/socket.io.js"></script><script src="/app.js"></script></body></html>`;

const CSS = `:root{--ink:#07050f;--m:#ff2e88;--c:#19e3ff;--g:#ffc83d;--p:#f6f1ff}
*{box-sizing:border-box}[hidden]{display:none!important}
body{margin:0;background:var(--ink);color:var(--p);font-family:Cairo,sans-serif;line-height:1.6}
a{color:var(--c)}
.bg{position:fixed;inset:0;z-index:-1;overflow:hidden}
.bg i{position:absolute;width:55vmax;height:55vmax;border-radius:50%;filter:blur(90px);opacity:.5;animation:dr 18s ease-in-out infinite alternate}
.bg i:nth-child(1){background:#6a1bff;top:-20%;right:-15%}.bg i:nth-child(2){background:var(--m);bottom:-25%;left:-20%;animation-delay:-6s}
@keyframes dr{to{transform:translate(8vmax,-6vmax) scale(1.15)}}
.hero{min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:40px 18px}
.ring{position:relative;width:132px;height:132px;display:grid;place-items:center;margin-bottom:14px}
.ring::before{content:"";position:absolute;inset:0;border-radius:50%;background:conic-gradient(var(--c),var(--m),var(--g),var(--c));animation:sp 5s linear infinite;box-shadow:0 0 50px #ff2e8877}
.ring span{position:relative;width:118px;height:118px;border-radius:50%;background:var(--ink);display:grid;place-items:center;font:4.4rem/1 Lalezar,sans-serif;color:var(--g)}
@keyframes sp{to{transform:rotate(1turn)}}
.kicker{margin:0;letter-spacing:.2em;color:var(--c);font-weight:700}
h1{font:clamp(3rem,13vw,7rem)/1.05 Lalezar,sans-serif;margin:4px 0 8px;background:linear-gradient(100deg,var(--g),var(--m),var(--c),var(--g));background-size:300% 100%;-webkit-background-clip:text;background-clip:text;color:transparent;animation:sh 7s linear infinite}
@keyframes sh{to{background-position:-300% 0}}
.by{margin:0 0 10px;font-size:1.05rem;color:#d8cdf5}.by a{color:var(--g);font-weight:700;text-decoration:none}.by a:hover{text-decoration:underline}
.sub{font-size:1.15rem;margin:0 0 20px;color:#d8cdf5}
.ig{padding:12px 30px;border-radius:50px;background:linear-gradient(135deg,var(--m),#ff8a3d);color:#fff;font-weight:700;text-decoration:none;box-shadow:0 10px 40px #ff2e8877;margin-bottom:14px}
.links{display:flex;flex-wrap:wrap;gap:10px;justify-content:center;margin-bottom:12px}
.links a{padding:8px 18px;border-radius:40px;border:1px solid #ffffff33;background:#ffffff0d;color:var(--p);text-decoration:none;font-weight:700;font-size:.95rem}
.links a:hover{border-color:var(--c);color:var(--c)}
.glass{background:#ffffff0d;border:1px solid #ffffff22;backdrop-filter:blur(14px);border-radius:22px;padding:18px;width:min(380px,100%);margin:8px 0}
.chk{display:flex;gap:8px;align-items:center;justify-content:center;margin-bottom:12px;font-size:.95rem}.chk input{width:auto;margin:0}
input{width:100%;margin-bottom:10px;padding:12px 14px;border-radius:12px;border:1px solid #ffffff2a;background:#0b0818aa;color:var(--p);font:inherit}
input:focus,button:focus-visible,a:focus-visible{outline:2px solid var(--c);outline-offset:2px}
button{padding:10px 20px;border:0;border-radius:12px;background:linear-gradient(135deg,var(--c),#7a5cff);color:#06111a;font:700 1rem Cairo,sans-serif;cursor:pointer}
button:hover{filter:brightness(1.15)}
#got b{color:var(--g);font-size:1.5rem;letter-spacing:.1em;user-select:all}
#app{display:grid;grid-template-columns:320px 1fr;height:100dvh}
aside{border-inline-end:1px solid #ffffff1f;display:flex;flex-direction:column;min-height:0;background:#0b0818cc;padding:10px}
.brand{font:1.5rem/1.2 Lalezar,sans-serif;color:var(--g);margin-bottom:8px}
.mebar{display:flex;gap:6px;align-items:center;margin-bottom:10px}.mebar b{flex:1}.mebar button{padding:6px 12px}
#list{overflow:auto;flex:1}
.mem{display:flex;flex-wrap:wrap;gap:2px 10px;align-items:center;padding:12px;cursor:pointer;border-bottom:1px solid #ffffff12;border-radius:10px}
.mem.act,.mem:hover{background:#ffffff14}.mem small{flex-basis:100%;color:#b9aedd}
.dot{width:10px;height:10px;border-radius:50%;background:#555}.dot.on{background:#2ee6a0;box-shadow:0 0 8px #2ee6a0}
.bdg{background:var(--m);border-radius:20px;padding:0 9px;font-weight:700;margin-inline-start:auto}
#chat{display:flex;flex-direction:column;min-height:0}#hint{margin:auto;color:#b9aedd}
#cbox{display:flex;flex-direction:column;flex:1;min-height:0}
.chead{display:flex;gap:6px;align-items:center;padding:10px;border-bottom:1px solid #ffffff1f}.chead b{flex:1}.chead button{padding:6px 12px}
#back{display:none}
#msgs{flex:1;overflow:auto;padding:16px;display:flex;flex-direction:column;gap:8px}
.m{max-width:75%;padding:9px 14px;border-radius:16px;background:#ffffff18;align-self:flex-start;overflow-wrap:anywhere}
.m.me{align-self:flex-end;background:linear-gradient(135deg,#7a5cff,var(--m))}
.m small.t{display:block;opacity:.6;font-size:.7rem;margin-top:2px}
#typing{margin:0;padding:0 16px 4px;color:var(--c);font-size:.85rem}
#send{display:flex;gap:8px;padding:10px}#send input{margin:0}
#call{position:fixed;inset:0;background:#000;z-index:50}#rv{width:100%;height:100%;object-fit:cover}
#lv{position:absolute;width:110px;bottom:90px;left:14px;border-radius:12px}
.cc{position:absolute;bottom:20px;width:100%;display:flex;justify-content:center;gap:12px}
footer{display:flex;flex-direction:column;align-items:center;gap:10px;padding:24px;text-align:center}
.foot p{margin:2px 0;font-size:.9rem;color:#d8cdf5}.foot a{color:var(--g);text-decoration:none;font-weight:700}.foot a:hover{text-decoration:underline}
.foot .rules{color:#b9aedd;font-size:.8rem}
#dot{width:9px;height:9px;padding:0;border-radius:50%;background:#e11d2e;opacity:.8}
dialog{border:1px solid var(--c);border-radius:18px;background:var(--ink);color:var(--p);width:min(680px,94vw);max-height:90vh}
dialog::backdrop{background:#000b}.scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:.9rem}td,th{padding:6px 8px;border-bottom:1px solid #2c2250;text-align:right}td button{padding:4px 10px;margin-inline-start:4px}
@media (max-width:700px){#app{grid-template-columns:1fr}body.chatting aside{display:none}body:not(.chatting) #chat{display:none}#back{display:block}}
@media (prefers-reduced-motion:reduce){*{animation:none!important}h1{color:var(--g);background:none}}`;

const JS = `const $=s=>document.querySelector(s);
const el=(t,c,x)=>{const e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e};
let token='',me,members=[],on=new Set(),unread={},cur=0,sock,pc,ls,peer=0,pend=null,seen=false,tTimer=0,lastT=0;const qc=[];
async function api(path,method='GET',body){
  const r=await fetch('/api'+path,{method,headers:{'Content-Type':'application/json',...(token&&{Authorization:'Bearer '+token})},body:body&&JSON.stringify(body)});
  const d=await r.json().catch(()=>({}));
  if(!r.ok)throw new Error(d.error||(r.status===429?'محاولات كثيرة، انتظر شوي':'صار خطأ'));
  return d}
const safe=f=>async()=>{try{await f()}catch(x){alert(x.message)}};
const nameOf=id=>(members.find(m=>m.id===id)||{}).name||'عضو';
const tm=t=>{try{return new Date(t).toLocaleTimeString('ar',{hour:'2-digit',minute:'2-digit'})}catch(e){return ''}};
const bub=m=>{const d=el('div','m'+(m.from_id===me.id?' me':''));d.append(el('span','',m.body),el('small','t',tm(m.created_at)));return d};
function list(){const q=$('#q').value.trim();
  const n=Object.values(unread).reduce((a,b)=>a+b,0);document.title=(n?'('+n+') ':'')+'أربكس الدردشة';
  $('#list').replaceChildren(...members.filter(m=>m.name.includes(q)).sort((a,b)=>on.has(b.id)-on.has(a.id)).map(m=>{
    const d=el('div','mem'+(m.id===cur?' act':''));d.append(el('i',on.has(m.id)?'dot on':'dot'),el('b','',m.name),el('small','',m.bio));
    if(unread[m.id])d.append(el('span','bdg',unread[m.id]));d.onclick=()=>open(m.id);return d}))}
async function open(id){cur=id;unread[id]=0;document.body.classList.add('chatting');$('#cbox').hidden=false;$('#hint').hidden=true;$('#typing').hidden=true;
  $('#cname').textContent=nameOf(id);list();
  try{const rows=await api('/chat/'+id);if(cur!==id)return;$('#msgs').replaceChildren(...rows.map(bub));$('#msgs').scrollTop=1e9}catch(x){alert(x.message)}}
$('#q').oninput=list;
$('#back').onclick=()=>document.body.classList.remove('chatting');
$('#send').onsubmit=e=>{e.preventDefault();const v=$('#txt').value.trim();if(!v||!cur)return;
  sock.emit('msg',{to:cur,body:v},r=>{if(r&&r.error)alert(r.error)});$('#txt').value=''};
$('#txt').oninput=()=>{const n=Date.now();if(cur&&sock&&n-lastT>2000){lastT=n;sock.emit('typing',{to:cur})}};
$('#rep').onclick=async()=>{const r=prompt('سبب الإبلاغ؟');if(r===null)return;try{await api('/report','POST',{id:cur,reason:r});alert('تم الإبلاغ')}catch(x){alert(x.message)}};
$('#blk').onclick=async()=>{if(!confirm('حظر '+nameOf(cur)+'؟'))return;try{await api('/block','POST',{id:cur});
  members=members.filter(m=>m.id!==cur);cur=0;$('#cbox').hidden=true;$('#hint').hidden=false;document.body.classList.remove('chatting');list()}catch(x){alert(x.message)}};
$('#edit').onclick=async()=>{const n=prompt('اسمك',me.name);if(!n)return;const b=prompt('نبذة قصيرة',me.bio)||'';
  try{await api('/me','PUT',{name:n,bio:b});me.name=n.trim();me.bio=b;$('#myname').textContent=me.name}catch(x){alert(x.message)}};
$('#out').onclick=async()=>{try{await api('/logout','POST')}catch(x){}location.reload()};

const flush=()=>qc.splice(0).forEach(c=>pc.addIceCandidate(c).catch(()=>{}));
async function mk(){const s=(await api('/ice')).servers;pc=new RTCPeerConnection({iceServers:s});
  ls.getTracks().forEach(t=>pc.addTrack(t,ls));pc.ontrack=e=>{$('#rv').srcObject=e.streams[0]};
  pc.onicecandidate=e=>{if(e.candidate)sock.emit('call:ice',{to:peer,c:e.candidate})};
  pc.onconnectionstatechange=()=>{if(['failed','closed'].includes(pc.connectionState))hang(false)}}
function show(v){$('#lv').srcObject=ls;$('#lv').hidden=!v;$('#call').hidden=false}
function hang(send){if(send&&peer)sock.emit('call:end',{to:peer});if(pc){pc.onconnectionstatechange=null;pc.close()}pc=null;
  if(ls)ls.getTracks().forEach(t=>t.stop());ls=null;peer=0;qc.length=0;$('#call').hidden=true;$('#rv').srcObject=null}
async function dial(v){if(pc||pend||!cur)return;peer=cur;qc.length=0;
  try{ls=await navigator.mediaDevices.getUserMedia({audio:true,video:v})}catch(x){peer=0;return alert('ما قدرت أوصل للمايك أو الكاميرا')}
  try{await mk();await pc.setLocalDescription(await pc.createOffer())}catch(x){hang(false);return alert('صار خطأ بالاتصال')}
  sock.emit('call:offer',{to:peer,sdp:pc.localDescription,video:v},r=>{if(r&&r.error){alert(r.error);hang(false)}});show(v);
  const my=pc;setTimeout(()=>{if(pc===my&&pc.connectionState!=='connected'){alert('ما رد');hang(true)}},30000)}
$('#vc').onclick=()=>dial(false);$('#vv').onclick=()=>dial(true);
$('#acc').onclick=async()=>{const o=pend;pend=null;$('#ring').close();peer=o.from;
  try{ls=await navigator.mediaDevices.getUserMedia({audio:true,video:o.video})}catch(x){sock.emit('call:reject',{to:peer});peer=0;return alert('ما قدرت أوصل للمايك أو الكاميرا')}
  try{await mk();await pc.setRemoteDescription(o.sdp);flush();await pc.setLocalDescription(await pc.createAnswer())}catch(x){sock.emit('call:reject',{to:peer});hang(false);return alert('صار خطأ بالاتصال')}
  sock.emit('call:answer',{to:peer,sdp:pc.localDescription});show(o.video)};
$('#rej').onclick=()=>$('#ring').close();
$('#ring').addEventListener('close',()=>{if(pend){sock.emit('call:reject',{to:pend.from});pend=null}});
$('#end').onclick=()=>hang(true);
$('#mute').onclick=()=>ls&&ls.getAudioTracks().forEach(t=>t.enabled=!t.enabled);
$('#cam').onclick=()=>ls&&ls.getVideoTracks().forEach(t=>t.enabled=!t.enabled);

async function refresh(){try{members=await api('/members');unread={};(await api('/unread')).forEach(u=>unread[u.from_id]=u.c);list();
  if(cur){const id=cur;const rows=await api('/chat/'+id);if(cur===id){$('#msgs').replaceChildren(...rows.map(bub));$('#msgs').scrollTop=1e9;unread[id]=0;list()}}}catch(x){}}
function wire(){
  sock.on('connect',()=>{if(seen)refresh();seen=true});
  sock.on('connect_error',e=>{if(e&&e.message==='auth')location.reload()});
  sock.on('online',a=>{on=new Set(a);list()});
  sock.on('presence',p=>{p.on?on.add(p.id):on.delete(p.id);list()});
  sock.on('typing',d=>{if(d.from!==cur)return;$('#typing').hidden=false;clearTimeout(tTimer);tTimer=setTimeout(()=>{$('#typing').hidden=true},2500)});
  sock.on('msg',async m=>{const o=m.from_id===me.id?m.to_id:m.from_id;
    if(!members.some(x=>x.id===o))members=await api('/members');
    if(o===cur){$('#msgs').append(bub(m));$('#msgs').scrollTop=1e9;if(m.from_id!==me.id){$('#typing').hidden=true;api('/seen/'+o,'POST').catch(()=>{})}}
    else if(m.from_id!==me.id){unread[o]=(unread[o]||0)+1;list()}});
  sock.on('call:offer',d=>{qc.length=0;pend=d;$('#rtext').textContent=nameOf(d.from)+(d.video?' يتصل فيديو':' يتصل صوت');$('#ring').showModal()});
  sock.on('call:answer',async d=>{if(pc){await pc.setRemoteDescription(d.sdp);flush()}});
  sock.on('call:ice',d=>{if(pc&&pc.remoteDescription)pc.addIceCandidate(d.c).catch(()=>{});else qc.push(d.c)});
  sock.on('call:end',()=>{if(pend){pend=null;$('#ring').close()}hang(false)});
  sock.on('call:reject',()=>{alert('المكالمة انرفضت');hang(false)});
  sock.on('disconnect',r=>{if(r==='io server disconnect'){alert('تم إنهاء جلستك');location.reload()}})}
async function enter(){me=await api('/me');members=await api('/members');
  (await api('/unread')).forEach(u=>unread[u.from_id]=u.c);
  $('#land').hidden=true;$('#app').hidden=false;$('#myname').textContent=me.name;list();
  if(!sock){sock=io();wire()}}
$('#su').onsubmit=async e=>{e.preventDefault();
  try{const d=await api('/signup','POST',{adult:e.target.adult.checked});$('#gnum').textContent=d.num;$('#gpass').textContent=d.pass;$('#got').hidden=false;$('#su').hidden=true;$('#lg').hidden=true}
  catch(x){$('#sumsg').textContent=x.message}};
$('#gok').onclick=()=>enter().catch(x=>alert(x.message));
$('#lg').onsubmit=async e=>{e.preventDefault();
  try{await api('/login','POST',Object.fromEntries(new FormData(e.target)));await enter()}catch(x){$('#lgmsg').textContent=x.message}};
api('/me').then(enter).catch(()=>{});

const row=(c,act,h)=>{const tr=el('tr');c.forEach(x=>tr.append(el(h?'th':'td','',x)));if(act)tr.append(act);return tr};
async function adm(){const d=await api('/admin/data');$('#cnt').textContent='('+d.accounts.length+' من '+d.max+' - أونلاين: '+d.online+')';
  const rp=$('#reps');rp.replaceChildren(row(['من','على','السبب',''],null,true));
  d.reports.forEach(x=>{const t=el('td'),b=el('button','',x.banned?'محظور':'حظر'),k=el('button','','حذف');
    b.onclick=safe(async()=>{await api('/admin/ban/'+x.to_id,'POST',{on:true});await adm()});
    k.onclick=safe(async()=>{await api('/admin/reports/'+x.id,'DELETE');await adm()});t.append(b,k);
    if(x.ev){const v=el('button','','الأدلة');v.onclick=safe(async()=>{alert((await api('/admin/report/'+x.id)).evidence)});t.append(v)}
    rp.append(row([x.fname,x.tname||x.tnum,x.reason||'-'],t))});
  const ac=$('#accs');ac.replaceChildren(row(['الرقم','الاسم','الحالة',''],null,true));
  d.accounts.forEach(x=>{const t=el('td'),b=el('button','',x.banned?'فك الحظر':'حظر'),rs=el('button','','إعادة ضبط');
    b.onclick=safe(async()=>{await api('/admin/ban/'+x.id,'POST',{on:!x.banned});await adm()});
    rs.onclick=safe(async()=>{if(!confirm('إعادة ضبط '+x.num+'؟'))return;const r=await api('/admin/reset/'+x.id,'POST');alert(x.num+' : '+r.pass);await adm()});
    t.append(b,rs);ac.append(row([x.num,x.name,x.banned?'محظور':(x.claimed_at?'مستخدم':'متاح')],t))})}
let clicks=0,timer;
$('#dot').addEventListener('click',()=>{clearTimeout(timer);timer=setTimeout(()=>clicks=0,3000);if(++clicks>=10){clicks=0;$('#admin').showModal()}});
$('#alogin').addEventListener('submit',async e=>{e.preventDefault();
  try{token=(await api('/admin/login','POST',{password:$('#pw').value})).token;$('#pw').value='';$('#alogin').hidden=true;$('#panel').hidden=false;await adm()}
  catch(x){$('#amsg').textContent=x.message}});`;

app.get('/', (_q, r) => r.type('html').send(HTML));
app.get('/style.css', (_q, r) => r.type('css').send(CSS));
app.get('/app.js', (_q, r) => r.type('js').send(JS));
app.use((e, _q, r, _n) => { console.error(e); if (!r.headersSent) r.status(500).json({ error: 'خطأ في الخادم' }); });

init()
  .then(() => server.listen(process.env.PORT || 3000, () => console.log('أربكس الدردشة شغّال')))
  .catch(e => { console.error('فشل التشغيل:', e.message); process.exit(1); });
