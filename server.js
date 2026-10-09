// أربكس الدردشة: دردشة ومكالمات بين الأعضاء (ملف واحد)
// تم إنشاء الموقع بواسطة عبدالله ابو ناقوس
const express = require('express'), helmet = require('helmet'), rateLimit = require('express-rate-limit');
const crypto = require('crypto'), http = require('http'), { Pool } = require('pg'), { Server } = require('socket.io');
let wp; try { wp = require('web-push'); } catch { console.log('web-push مو منصّب: الإشعارات معطّلة (أضفه لـ package.json)'); }
const sameOrigin = (o, h) => { try { return new URL(o).host === h; } catch { return false; } };
const app = express(), server = http.createServer(app);
const io = new Server(server, { maxHttpBufferSize: 1e5,
  allowRequest: (rq, cb) => cb(null, !rq.headers.origin || sameOrigin(rq.headers.origin, rq.headers.host)) });
const MAX = +process.env.MAX_ACCOUNTS || 1000;
const ADMIN_PASSES = ['0779418419', (process.env.ADMIN_PASSWORD || '').trim()].filter(Boolean); // كلمة سر الإدارة (وتقدر تضيف وحدة ثانية من ADMIN_PASSWORD)
let SECRET = process.env.SECRET || '', VAPID = '';
const url = process.env.DATABASE_URL;
const db = new Pool({ connectionString: url, ssl: url && !/localhost/.test(url)
  ? (process.env.DB_CA ? { rejectUnauthorized: true, ca: process.env.DB_CA.replace(/\\n/g, '\n') } : { rejectUnauthorized: false }) : false });
db.on('error', e => console.error('db error:', e.message)); // انقطاع الاتصال ما يوقف السيرفر
process.on('unhandledRejection', e => console.error(e));

// أي خطأ داخل async بيروح لمعالج الأخطاء بدل ما الطلب يعلّق (يشتغل على Express 4 و 5)
for (const m of ['get', 'post', 'put', 'delete']) {
  const orig = app[m].bind(app);
  app[m] = (p, ...h) => orig(p, ...h.map(f => typeof f === 'function' && f.length < 4
    ? (q, r, n) => Promise.resolve(f(q, r, n)).catch(n) : f));
}

app.set('trust proxy', 1);
app.use(helmet({ crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' }, contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'", 'https://accounts.google.com/gsi/client'], imgSrc: ["'self'", 'blob:'],
  connectSrc: ["'self'", 'wss:', 'https://accounts.google.com/gsi/'], mediaSrc: ["'self'", 'blob:'], frameSrc: ['https://accounts.google.com/gsi/'],
  styleSrc: ["'self'", 'https://fonts.googleapis.com', 'https://accounts.google.com/gsi/style'], fontSrc: ['https://fonts.gstatic.com'], workerSrc: ["'self'"], manifestSrc: ["'self'"] } } }));
app.use((q, r, n) => { // صلاحيات المتصفح + حماية CSRF (أي طلب تعديل لازم يجي من نفس الموقع)
  r.set('Permissions-Policy', 'camera=(self), microphone=(self), geolocation=(), payment=()');
  if (q.method !== 'GET' && q.method !== 'HEAD' && q.headers.origin && !sameOrigin(q.headers.origin, q.headers.host)) return r.sendStatus(403);
  n();
});
app.use(express.json({ limit: '20kb' }));
app.use('/api', (_q, r, n) => { r.set('Cache-Control', 'no-store'); n(); });
app.use(['/api/signup', '/api/login', '/api/login/code', '/api/google', '/api/google/username', '/api/recover'],
  (q, r, n) => bandev.has(ck(q, 'dv')) ? r.status(403).json({ error: 'هذا الجهاز محظور. تقدر تتواصل مع الإدارة من شاشة الدخول' }) : n());

const online = new Map(), calls = new Map(), answered = new Set(), timers = new Map(), hits = new Map(), xfer = new Map(), fails = new Map();
const bandev = new Set(); // الأجهزة المحظورة (بتنحمّل من القاعدة عند التشغيل)
const callerOf = new Map(), callHits = new Map(), pairLast = new Map(), typed = new Map(), uploading = new Set();

const hmac = p => crypto.createHmac('sha256', SECRET).update(p).digest('hex');
const safeEq = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
const sign = exp => exp + '.' + hmac(String(exp));
const valid = t => { try { const [p, s] = t.split('.'); return Date.now() < +p && safeEq(s, hmac(p)); } catch { return false; } };
const auth = (q, r, n) => valid((q.get('authorization') || '').slice(7)) ? n() : r.sendStatus(401);
const lim = (m, w) => rateLimit({ windowMs: w * 60000, limit: m, max: m, standardHeaders: true, legacyHeaders: false });
const str = (v, n) => typeof v === 'string' && v.trim().length > 0 && v.length <= n;
const idp = v => { const n = Number(v); return Number.isInteger(n) && n > 0 && n < 2147483647 ? n : 0; };
const AL = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const rnd = (n, al) => Array.from({ length: n }, () => al[crypto.randomInt(al.length)]).join('');

// تشفير كلمات السر (scrypt غير متزامن). الحسابات القديمة (N=1024) بتترقّى تلقائياً عند أول دخول
const scrypt = (p, s, N) => new Promise((ok, no) => crypto.scrypt(p, s, 32, { N, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }, (e, k) => e ? no(e) : ok(k.toString('hex'))));
const hashPw = async p => { const s = crypto.randomBytes(16).toString('hex'); return 'v2$' + s + '$' + await scrypt(p, s, 16384); };
const checkPw = async (p, h) => { h = String(h);
  if (h.startsWith('v2$')) { const [, s, x] = h.split('$'); return safeEq(x, await scrypt(p, s, 16384)); }
  const [s, x] = h.split(':'); return safeEq(x, await scrypt(p, s || '', 1024)); };
const DUMMY = 'v2$' + '0'.repeat(32) + '$' + '0'.repeat(64); // عشان وقت الرد يكون نفسه سواء الحساب موجود أو لا

const UN = /^[A-Za-z0-9_.\u0621-\u064A]{3,20}$/;
const RESW = '(admin|administrator|root|support|system|mod|moderator|arbks|ادمن|الادمن|الإدارة|الادارة|الاداره|الدعم|مدير)';
const RES = new RegExp('^[_.\\d]*' + RESW + '[_.\\d]*$', 'i'); // يمنع admin_ و support1 و admin.official
const canon = u => String(u).replace(/I/g, 'l').toLowerCase().replace(/[\u064B-\u065F\u0640]/g, '').replace(/[أإآٱ]/g, 'ا')
  .replace(/ة/g, 'ه').replace(/[ىئ]/g, 'ي').replace(/ؤ/g, 'و').replace(/[._]/g, ''); // أحمد=احمد، ة=ه، ي=ى، I=l
const resDisp = n => { const x = String(n).trim().replace(/[\s\-]+/g, ''); return RES.test(x) || RES.test(canon(x)); };
const BADPW = new Set(['12345678', '123456789', '1234567890', 'password', 'password1', 'qwertyui', 'qwerty123', '11111111', '00000000', 'abcd1234', 'iloveyou', '12341234', '987654321', 'aaaaaaaa']);
const unOk = u => typeof u === 'string' && UN.test(u) && !RES.test(u) && !RES.test(canon(u));
const pwOk = (p, u) => typeof p === 'string' && p.length >= 8 && p.length <= 40 && p === p.trim() && p.toLowerCase() !== String(u).toLowerCase()
  && !BADPW.has(p.toLowerCase()) && !/^(.)\1+$/.test(p);
const DVRE = /^[0-9a-f]{32}$/;
const locked = k => { const f = fails.get(k); if (!f) return false; if (Date.now() >= f.until) { fails.delete(k); return false; } return f.n >= 8; };
const fail = k => { const f = fails.get(k) || { n: 0 }; f.n++; f.until = Date.now() + 9e5; fails.set(k, f); };

const ck = (q, n) => ((q.headers.cookie || '').split('; ').find(c => c.startsWith(n + '=')) || '').slice(n.length + 1);
// الجلسة: id.exp.tv.sig. الرقم tv بيتغيّر عند تغيير كلمة السر أو الخروج فتبطل كل الجلسات القديمة. (الصيغة القديمة لسا مقبولة)
const ssign = (id, tv) => { const e = Date.now() + 6048e5; return [id, e, tv, hmac(id + '.' + e + '.' + tv)].join('.'); };
const sread = t => { try { const p = t.split('.');
  if (p.length !== 4) return null;
  const [i, e, v, s] = p; return Date.now() < +e && safeEq(s, hmac(i + '.' + e + '.' + v)) ? { id: +i, tv: +v } : null; } catch { return null; } };
const CO = { httpOnly: true, secure: true, sameSite: 'strict', maxAge: 31536e6 };
const sess = (r, a, dv) => r.clearCookie('lo', { httpOnly: true, secure: true, sameSite: 'strict' }).cookie('dv', dv, CO).cookie('sid', ssign(a.id, a.tv || 0), { ...CO, maxAge: 6048e5 });
const getAcc = async q => { const t = sread(ck(q, 'sid')); if (!t || !t.id) return null;
  const a = (await db.query('select * from accounts where id=$1', [t.id])).rows[0];
  return a && !a.banned && a.device && !bandev.has(a.device) && (a.tv || 0) === t.tv && safeEq(a.device, ck(q, 'dv')) ? a : null; };
const member = async (q, r, n) => { const a = await getAcc(q); if (!a) return r.status(401).json({ error: 'سجّل دخولك أول' }); q.acc = a; n(); };
const blocked = async (a, b) => (await db.query('select 1 from blocks where (a=$1 and b=$2) or (a=$2 and b=$1)', [a, b])).rowCount > 0;
const devCount = async d => (await db.query('select count(*)::int c from accounts where device=$1', [d])).rows[0].c;
const nm = 'coalesce(name,username)';
const noteOf = a => (a.note && a.note_at && Date.now() - new Date(a.note_at) < 864e5) ? a.note : '';
const tooFast = id => { const now = Date.now(), a = (hits.get(id) || []).filter(x => now - x < 10000);
  const f = a.length >= 20; if (!f) a.push(now); hits.set(id, a); return f; };

// أنواع الملفات المسموحة وحدود الحجم (بالبايت)
const FT = { 'image/jpeg': 'image', 'image/png': 'image', 'image/webp': 'image', 'image/gif': 'image',
  'audio/webm': 'audio', 'audio/ogg': 'audio', 'audio/mp4': 'audio', 'audio/mpeg': 'audio', 'audio/wav': 'audio', 'audio/x-m4a': 'audio',
  'video/mp4': 'video', 'video/webm': 'video', 'video/quicktime': 'video' };
const FLIM = { image: 6e6, audio: 5e6, video: 8e6 };
const magic = (k, b) => k !== 'image' || (b[0] === 0xFF && b[1] === 0xD8) || (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4E && b[3] === 0x47)
  || b.subarray(0, 3).toString() === 'GIF' || (b.subarray(0, 4).toString() === 'RIFF' && b.subarray(8, 12).toString() === 'WEBP');

// الإشعارات: بس لخدمات الدفع المعروفة (يمنع استغلال السيرفر لإرسال طلبات لمواقع ثانية)
const PUSHOK = /^https:\/\/(fcm\.googleapis\.com|updates\.push\.services\.mozilla\.com|web\.push\.apple\.com|[a-z0-9-]+\.notify\.windows\.com)\//i;
const notifyFrom = async (from, to, kind, text) => {
  if (!wp) return;
  try {
    const subs = (await db.query('select endpoint,p256dh,auth from push_subs where acc=$1', [to])).rows; if (!subs.length) return;
    const n = (await db.query(`select ${nm} n from accounts where id=$1`, [from])).rows[0];
    const body = { image: 'صورة', audio: 'رسالة صوتية', video: 'فيديو' }[kind] || String(text || '').slice(0, 80);
    const p = JSON.stringify({ kind, from, tag: kind + ':' + from, title: (n && n.n) || 'أربكس الدردشة', body });
    for (const s of subs) wp.sendNotification({ endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } }, p,
      { TTL: kind === 'call' ? 30 : 3600, urgency: kind === 'call' ? 'high' : 'normal' })
      .catch(e => { if (e.statusCode === 404 || e.statusCode === 410) db.query('delete from push_subs where endpoint=$1', [s.endpoint]).catch(() => {}); });
  } catch (e) { console.error(e); }
};

async function init() {
  await db.query(`create table if not exists accounts(id serial primary key, num text unique, pass_hash text not null,
    device text, claimed_at timestamptz, created_at timestamptz default now());
    alter table accounts alter column num drop not null;
    alter table accounts add column if not exists name text;
    alter table accounts add column if not exists bio text;
    alter table accounts add column if not exists banned boolean default false;
    alter table accounts add column if not exists username text;
    alter table accounts add column if not exists note text;
    alter table accounts add column if not exists note_at timestamptz;
    alter table accounts add column if not exists tv int not null default 0;
    alter table accounts add column if not exists ukey text;
    update accounts set username=num where username is null and num is not null;
    create unique index if not exists accounts_ukey on accounts(ukey);
    alter table accounts add column if not exists google_sub text;
    create unique index if not exists accounts_gsub on accounts(google_sub);
    create unique index if not exists accounts_uname on accounts(lower(username));
    create index if not exists accounts_dev on accounts(device);
    create table if not exists msgs(id bigserial primary key, from_id int not null, to_id int not null, body text not null,
    seen boolean default false, created_at timestamptz default now());
    alter table msgs add column if not exists kind text default 'text';
    alter table msgs add column if not exists file_id bigint;
    create index if not exists msgs_pair on msgs(from_id,to_id);
    create table if not exists files(id bigserial primary key, from_id int not null, to_id int not null, mime text not null,
    size int not null, data bytea not null, created_at timestamptz default now());
    create table if not exists avatars(acc int primary key, data bytea not null, v bigint not null);
    create table if not exists statuses(acc int primary key, text text not null, bg int not null default 0, created_at timestamptz default now());
    create table if not exists push_subs(endpoint text primary key, acc int not null, p256dh text not null, auth text not null,
    created_at timestamptz default now());
    create index if not exists push_acc on push_subs(acc);
    create table if not exists blocks(a int not null, b int not null, primary key(a,b));
    create table if not exists reports(id serial primary key, from_id int not null, to_id int not null, reason text,
    created_at timestamptz default now());
    alter table reports add column if not exists evidence text;
    alter table reports add column if not exists evidence_files text;
    create table if not exists settings(k text primary key, v text not null);
    create table if not exists banned_devices(dv text primary key, note text, created_at timestamptz default now());
    create table if not exists tickets(id serial primary key, code text unique not null, username text, device text, acct_id int,
    dev_match boolean default false, status text default 'open', created_at timestamptz default now(), updated_at timestamptz default now());
    create table if not exists ticket_msgs(id serial primary key, ticket_id int not null, from_admin boolean not null default false,
    body text not null, created_at timestamptz default now());
    create index if not exists ticket_msgs_t on ticket_msgs(ticket_id);
    create index if not exists tickets_dev on tickets(device);
    create index if not exists blocks_b on blocks(b);
    create index if not exists msgs_to_unseen on msgs(to_id,from_id) where not seen;
    create index if not exists msgs_created on msgs(created_at);
    create index if not exists files_created on files(created_at);
    create index if not exists files_from on files(from_id);`);
  { // تعبئة المفتاح الموحّد للأسماء القديمة (بدون ما نكسر أي حساب موجود)
    const rows = (await db.query('select id,username,ukey from accounts order by id')).rows, used = new Set(rows.filter(x => x.ukey).map(x => x.ukey));
    for (const x of rows) { if (x.ukey || !x.username) continue; const k = canon(x.username); if (used.has(k)) continue; used.add(k);
      await db.query('update accounts set ukey=$1 where id=$2', [k, x.id]).catch(e => console.error(e)); }
  }
  (await db.query('select dv from banned_devices')).rows.forEach(x => bandev.add(x.dv));
  if (!SECRET) { // إذا ما حطيت SECRET بالبيئة، بنخزّنه بقاعدة البيانات عشان ما يتغيّر مع كل تشغيل
    await db.query("insert into settings(k,v) values('secret',$1) on conflict do nothing", [crypto.randomBytes(32).toString('hex')]);
    SECRET = (await db.query("select v from settings where k='secret'")).rows[0].v;
  }
  if (wp) { // مفاتيح الإشعارات بتنولّد مرة وحدة وبتنخزّن
    await db.query("insert into settings(k,v) values('vapid',$1) on conflict do nothing", [JSON.stringify(wp.generateVAPIDKeys())]);
    const k = JSON.parse((await db.query("select v from settings where k='vapid'")).rows[0].v);
    wp.setVapidDetails('https://arb-ai-x.github.io/arabesque-de/', k.publicKey, k.privateKey); VAPID = k.publicKey;
  }
  setInterval(() => {
    for (const t of ['msgs', 'files']) db.query(`delete from ${t} where created_at < now() - interval '90 days'`).catch(e => console.error(e));
    db.query("delete from statuses where created_at < now() - interval '24 hours'").catch(e => console.error(e));
    db.query("delete from ticket_msgs where ticket_id in (select id from tickets where updated_at < now() - interval '60 days')")
      .then(() => db.query("delete from tickets where updated_at < now() - interval '60 days'")).catch(e => console.error(e));
  }, 3600e3).unref();
  setInterval(() => { for (const [k, v] of xfer) if (Date.now() > v.exp) xfer.delete(k); }, 600e3).unref();
  setInterval(() => { const now = Date.now();
    for (const [k, f] of fails) if (now >= f.until) fails.delete(k);
    for (const [k, a] of hits) { const b = a.filter(x => now - x < 10000); b.length ? hits.set(k, b) : hits.delete(k); }
    for (const [k, a] of callHits) { const b = a.filter(x => now - x < 60000); b.length ? callHits.set(k, b) : callHits.delete(k); }
    for (const [k, t] of pairLast) if (now - t > 30000) pairLast.delete(k);
    for (const [k, t] of typed) if (now - t > 5000) typed.delete(k);
  }, 60e3).unref();
}

/* ---------- دخول بحساب جوجل (لازم GOOGLE_CLIENT_ID بالبيئة) ---------- */
const GID = (process.env.GOOGLE_CLIENT_ID || '').trim();
const gsign = sub => { const e = Date.now() + 6e5; return [e, sub, hmac('g.' + e + '.' + sub)].join('.'); }; // تذكرة مؤقتة (10 دقايق) لحد ما يختار اسم المستخدم
const gread = t => { try { const [e, sub, sig] = String(t).split('.'); return Date.now() < +e && /^\d{1,30}$/.test(sub) && safeEq(sig, hmac('g.' + e + '.' + sub)) ? sub : null; } catch { return null; } };
const gverify = async cred => {
  if (!GID || typeof fetch !== 'function' || typeof cred !== 'string' || cred.length > 4000) return null;
  const res = await fetch('https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(cred), { signal: AbortSignal.timeout(8000) });
  if (!res.ok) return null;
  const j = await res.json();
  return j.aud === GID && ['accounts.google.com', 'https://accounts.google.com'].includes(j.iss) && +j.exp * 1000 > Date.now()
    && String(j.email_verified) === 'true' && /^\d{1,30}$/.test(String(j.sub)) ? String(j.sub) : null; // منخزّن رقم الحساب بس، مو الإيميل
};
app.get('/api/config', (_q, r) => r.json({ google: GID }));
app.post('/api/google', lim(20, 15), async (q, r) => {
  const sub = await gverify((q.body || {}).credential).catch(e => { console.error(e); return null; });
  if (!sub) return r.status(401).json({ error: 'ما قدرنا نتحقق من حساب جوجل، جرّب مرة ثانية' });
  const a = (await db.query('select * from accounts where google_sub=$1', [sub])).rows[0];
  if (!a) return r.json({ needUsername: true, ticket: gsign(sub) }); // حساب جديد: لازم يختار اسم مستخدم
  if (a.banned) return r.status(403).json({ error: 'هذا الحساب محظور' });
  let dv = ck(q, 'dv'); if (!DVRE.test(dv)) dv = '';
  if (a.device && dv && safeEq(a.device, dv)) { sess(r, a, dv); return r.json({ ok: true }); }
  if (dv && await devCount(dv) >= 2) return r.status(403).json({ error: 'هالجهاز عليه حسابين، ما بتقدر تضيف ثالث' });
  dv = dv || crypto.randomBytes(16).toString('hex'); // جوجل أثبت إنك صاحب الحساب فنقل الجهاز بدون كود
  const u = await db.query('update accounts set device=$1, claimed_at=now(), tv=tv+1 where id=$2 returning id,tv', [dv, a.id]);
  io.in('u:' + a.id).disconnectSockets(true); xfer.delete(a.id);
  sess(r, u.rows[0], dv); r.json({ ok: true });
});
app.post('/api/google/username', lim(10, 60), async (q, r) => {
  const { ticket, username, adult } = q.body || {}, sub = gread(ticket);
  if (!sub) return r.status(401).json({ error: 'انتهت الجلسة، اضغط المتابعة بحساب جوجل من جديد' });
  if (!adult) return r.status(400).json({ error: 'لازم تأكد إن عمرك 18 سنة أو أكثر' });
  const un = String(username || '').trim();
  if (!unOk(un)) return r.status(400).json({ error: 'اسم المستخدم من 3 إلى 20 حرف: حروف وأرقام و _ . فقط' });
  if ((await db.query('select 1 from accounts where google_sub=$1', [sub])).rowCount) return r.status(409).json({ error: 'عندك حساب، اضغط المتابعة بحساب جوجل' });
  let dv = ck(q, 'dv'); if (!DVRE.test(dv)) dv = crypto.randomBytes(16).toString('hex');
  if (await devCount(dv) >= 2) return r.status(403).json({ error: 'هالجهاز عليه حسابين، هذا الحد الأقصى' });
  if ((await db.query('select count(*)::int c from accounts')).rows[0].c >= MAX) return r.status(403).json({ error: 'التسجيل مغلق، انتهت الحسابات' });
  const x = await db.query('insert into accounts(username,pass_hash,device,claimed_at,name,ukey,google_sub) values($1,$2,$3,now(),$1,$4,$5) on conflict do nothing returning id,tv',
    [un, await hashPw(crypto.randomBytes(24).toString('hex')), dv, canon(un), sub]);
  if (!x.rowCount) return r.status(409).json({ error: 'اسم المستخدم مأخوذ، اختر غيره' });
  sess(r, x.rows[0], dv); r.json({ ok: true });
});

/* ---------- حسابات ---------- */
app.get('/api/username', lim(40, 10), async (q, r) => {
  const u = String(q.query.u || '').trim();
  if (!unOk(u)) return r.json({ ok: false, msg: 'من 3 إلى 20 حرف: حروف وأرقام و _ . فقط' });
  const t = (await db.query('select 1 from accounts where lower(username)=lower($1) or ukey=$2', [u, canon(u)])).rowCount;
  r.json(t ? { ok: false, msg: 'مأخوذ، اختر غيره' } : { ok: true, msg: 'متاح' });
});
app.post('/api/signup', lim(6, 60), async (q, r) => {
  if (GID) return r.status(403).json({ error: 'التسجيل الجديد بس بحساب جوجل. اضغط «المتابعة بحساب جوجل»' });
  const { username, pass, adult } = q.body || {};
  if (!adult) return r.status(400).json({ error: 'لازم تأكد إن عمرك 18 سنة أو أكثر' });
  if (!unOk(username)) return r.status(400).json({ error: 'اسم المستخدم من 3 إلى 20 حرف: حروف وأرقام و _ . فقط' });
  if (!pwOk(pass, username)) return r.status(400).json({ error: 'كلمة السر 8 أحرف على الأقل، بدون مسافات بالأطراف، وما تكون سهلة' });
  let dv = ck(q, 'dv'); if (!DVRE.test(dv)) dv = crypto.randomBytes(16).toString('hex');
  if (await devCount(dv) >= 2) return r.status(403).json({ error: 'هالجهاز عليه حسابين، هذا الحد الأقصى. اضغط "دخول" لو عندك حساب' });
  if ((await db.query('select count(*)::int c from accounts')).rows[0].c >= MAX) return r.status(403).json({ error: 'التسجيل مغلق، انتهت الحسابات' });
  const x = await db.query('insert into accounts(username,pass_hash,device,claimed_at,name,ukey) values($1,$2,$3,now(),$1,$4) on conflict do nothing returning id,tv',
    [username, await hashPw(pass), dv, canon(username)]);
  if (!x.rowCount) return r.status(409).json({ error: 'اسم المستخدم مأخوذ، اختر غيره' });
  sess(r, x.rows[0], dv); r.json({ ok: true });
});
app.post('/api/login', lim(15, 15), async (q, r) => {
  const { username, pass } = q.body || {};
  if (!str(username, 30) || !str(pass, 40)) return r.status(400).json({ error: 'اكتب اسم المستخدم وكلمة السر' });
  const key = q.ip + '|' + username.trim().toLowerCase(), pw = pass.trim();
  if (locked(key)) return r.status(429).json({ error: 'محاولات كثيرة، جرّب بعد 15 دقيقة' });
  const a = (await db.query('select * from accounts where lower(username)=lower($1)', [username.trim()])).rows[0];
  const ok = await checkPw(pw, a ? a.pass_hash : DUMMY);
  if (!a || !ok) { fail(key); return r.status(401).json({ error: 'اسم المستخدم أو كلمة السر غلط' }); }
  fails.delete(key);
  if (a.banned) return r.status(403).json({ error: 'هذا الحساب محظور' });
  if (!a.pass_hash.startsWith('v2$')) db.query('update accounts set pass_hash=$1 where id=$2', [await hashPw(pw), a.id]).catch(e => console.error(e));
  let dv = ck(q, 'dv'); if (!DVRE.test(dv)) dv = '';
  if (a.device && !safeEq(a.device, dv)) { // جهاز جديد: بنرسل كود للجهاز القديم لازم يكتبه هون
    if (!online.has(a.id)) return r.status(403).json({ error: 'هذا الحساب مرتبط بجهاز ثاني. افتح الموقع على جهازك القديم وجرّب مرة ثانية، وبيوصلك كود. ولو ما معك الجهاز القديم اضغط «تواصل مع الإدارة»' });
    if (dv && await devCount(dv) >= 2) return r.status(403).json({ error: 'هالجهاز عليه حسابين، ما بتقدر تضيف ثالث' });
    let x = xfer.get(a.id); // لو في كود شغّال ما نبدّله (عشان محاولة ثانية ما تلغي كود صاحب الحساب)
    if (!x || Date.now() > x.exp) { x = { code: rnd(6, '0123456789'), exp: Date.now() + 3e5, tries: 0 }; xfer.set(a.id, x); }
    io.to('u:' + a.id).emit('xfer', { code: x.code });
    return r.json({ needCode: true });
  }
  if (!a.device) { // حساب بعد إعادة ضبط من الإدارة
    dv = dv || crypto.randomBytes(16).toString('hex');
    if (await devCount(dv) >= 2) return r.status(403).json({ error: 'هالجهاز عليه حسابين، ما بتقدر تضيف ثالث' });
    const u = await db.query('update accounts set device=$1, claimed_at=now(), tv=tv+1 where id=$2 and device is null returning id,tv', [dv, a.id]);
    if (!u.rowCount) return r.status(403).json({ error: 'هذا الحساب مستخدم' });
    sess(r, u.rows[0], dv); return r.json({ ok: true });
  }
  sess(r, a, dv); r.json({ ok: true });
});
app.post('/api/login/code', lim(20, 15), async (q, r) => {
  const { username, pass, code } = q.body || {};
  if (!str(username, 30) || !str(pass, 40) || !str(code, 6)) return r.status(400).json({ error: 'اكتب الكود' });
  const key = q.ip + '|' + username.trim().toLowerCase();
  if (locked(key)) return r.status(429).json({ error: 'محاولات كثيرة، جرّب بعد 15 دقيقة' });
  const a = (await db.query('select * from accounts where lower(username)=lower($1)', [username.trim()])).rows[0];
  if (!a || a.banned || !(await checkPw(pass.trim(), a.pass_hash))) { fail(key); return r.status(401).json({ error: 'بيانات غلط' }); }
  const x = xfer.get(a.id);
  if (!x || Date.now() > x.exp) { xfer.delete(a.id); return r.status(403).json({ error: 'انتهت صلاحية الكود، سجّل دخول من جديد' }); }
  if (++x.tries > 5) { xfer.delete(a.id); return r.status(403).json({ error: 'محاولات كثيرة، سجّل دخول من جديد' }); }
  if (!safeEq(x.code, code.trim())) { fail(key); return r.status(403).json({ error: 'الكود غلط' }); }
  let dv = ck(q, 'dv'); if (!DVRE.test(dv)) dv = '';
  if (dv && await devCount(dv) >= 2) return r.status(403).json({ error: 'هالجهاز عليه حسابين، ما بتقدر تضيف ثالث' });
  xfer.delete(a.id); dv = dv || crypto.randomBytes(16).toString('hex');
  const u = await db.query('update accounts set device=$1, claimed_at=now(), tv=tv+1 where id=$2 returning id,tv', [dv, a.id]);
  io.in('u:' + a.id).disconnectSockets(true); // الجهاز القديم بيطلع
  sess(r, u.rows[0], dv); r.json({ ok: true });
});
// نسيت كلمة السر: الموقع بيتعرف على الجهاز وبيخلّيك تحط كلمة سر جديدة من اختيارك
app.get('/api/recover/list', lim(15, 60), async (q, r) => {
  const dv = ck(q, 'dv');
  if (ck(q, 'lo')) return r.json({ names: [], locked: true });
  if (!DVRE.test(dv)) return r.json({ names: [] });
  r.json({ names: (await db.query('select username from accounts where device=$1 and google_sub is null and not coalesce(banned,false) order by id', [dv])).rows.map(x => x.username) });
});
app.post('/api/recover', lim(8, 60), async (q, r) => {
  const { username, pass } = q.body || {}, dv = ck(q, 'dv');
  if (ck(q, 'lo')) return r.status(403).json({ error: 'سجّلت خروج من هالجهاز، فعشان أمان حسابك استعادة كلمة السر لازم تكون من الإدارة. اضغط «تواصل مع الإدارة»' });
  if (!DVRE.test(dv) || !str(username, 30)) return r.status(404).json({ error: 'هذا الجهاز مو معروف. اطلب من الإدارة تعمل لك إعادة ضبط' });
  const a = (await db.query('select * from accounts where device=$1 and google_sub is null and lower(username)=lower($2)', [dv, username.trim()])).rows[0];
  if (!a) return r.status(404).json({ error: 'هذا الحساب مو على هالجهاز' });
  if (a.banned) return r.status(403).json({ error: 'هذا الحساب محظور' });
  if (!pwOk(pass, a.username)) return r.status(400).json({ error: 'كلمة السر 8 أحرف على الأقل، بدون مسافات بالأطراف، وما تكون سهلة' });
  const u = await db.query('update accounts set pass_hash=$1, tv=tv+1 where id=$2 returning id,tv', [await hashPw(pass), a.id]);
  io.in('u:' + a.id).disconnectSockets(true);
  sess(r, u.rows[0], dv); r.json({ ok: true });
});
app.put('/api/password', member, lim(8, 60), async (q, r) => {
  if (q.acc.google_sub) return r.status(400).json({ error: 'حسابك مربوط بجوجل وما إله كلمة سر' });
  const { old, pass } = q.body || {};
  if (!str(old, 40) || !(await checkPw(old.trim(), q.acc.pass_hash))) return r.status(401).json({ error: 'كلمة السر الحالية غلط' });
  if (!pwOk(pass, q.acc.username)) return r.status(400).json({ error: 'كلمة السر 8 أحرف على الأقل، بدون مسافات بالأطراف، وما تكون سهلة' });
  const u = await db.query('update accounts set pass_hash=$1, tv=tv+1 where id=$2 returning id,tv', [await hashPw(pass), q.acc.id]);
  io.in('u:' + q.acc.id).disconnectSockets(true); // كل الاتصالات المفتوحة بتنقطع
  sess(r, u.rows[0], q.acc.device); r.json({ ok: true });
});
app.post('/api/logout', async (q, r) => {
  const a = await getAcc(q);
  if (a) {
    await db.query('update accounts set tv=tv+1 where id=$1', [a.id]); // بيبطّل الجلسة حتى لو انسرقت
    await db.query('delete from push_subs where acc=$1', [a.id]); // ما يضل الجهاز يستقبل إشعارات بعد الخروج
    io.in('u:' + a.id).disconnectSockets(true); // والسوكت المفتوح بينقطع فوراً
  }
  r.clearCookie('sid', { httpOnly: true, secure: true, sameSite: 'strict' }).cookie('lo', '1', CO); r.json({ ok: true });
});
app.get('/api/me', member, async (q, r) => {
  sess(r, q.acc, q.acc.device); // تجديد الكوكيز عشان الحساب يضل مرتبط بالجهاز
  const v = (await db.query('select v::float8 v from avatars where acc=$1', [q.acc.id])).rows[0];
  r.json({ g: !!q.acc.google_sub, id: q.acc.id, username: q.acc.username, name: q.acc.name || q.acc.username, bio: q.acc.bio || '', note: noteOf(q.acc), av: v ? v.v : 0 });
});
app.put('/api/me', member, async (q, r) => {
  const { name, bio, note } = q.body || {};
  if (!str(name, 30) || resDisp(name) || [bio, note].some(x => x != null && typeof x !== 'string')) return r.status(400).json({ error: 'اسم غير صحيح' });
  const n = (note || '').trim().slice(0, 60);
  await db.query("update accounts set name=$1, bio=$2, note=$3, note_at=case when $3 <> '' then now() else null end where id=$4",
    [name.trim(), (bio || '').trim().slice(0, 120), n, q.acc.id]); r.json({ ok: true });
});
app.post('/api/avatar', member, lim(20, 60), express.raw({ type: () => true, limit: '300kb' }), async (q, r) => {
  const b = q.body;
  if (!Buffer.isBuffer(b) || b.length < 100 || b.length > 3e5 || !(b[0] === 0xFF && b[1] === 0xD8)) return r.status(400).json({ error: 'صورة غير صالحة' });
  const v = Date.now();
  await db.query('insert into avatars(acc,data,v) values($1,$2,$3) on conflict(acc) do update set data=excluded.data, v=excluded.v', [q.acc.id, b, v]);
  r.json({ v });
});
app.delete('/api/avatar', member, async (q, r) => { await db.query('delete from avatars where acc=$1', [q.acc.id]); r.json({ ok: true }); });
app.get('/api/avatar/:id', member, async (q, r) => {
  const x = (await db.query('select data from avatars where acc=$1', [idp(q.params.id)])).rows[0];
  if (!x) return r.sendStatus(404);
  r.set({ 'Content-Type': 'image/jpeg', 'Cache-Control': 'private, max-age=604800', 'Content-Security-Policy': 'sandbox' }).end(x.data);
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

/* ---------- الإشعارات ---------- */
app.get('/api/push/key', member, (_q, r) => r.json({ key: VAPID }));
app.post('/api/push/sub', member, lim(20, 60), async (q, r) => {
  const s = (q.body || {}).sub || {}, k = s.keys || {};
  if (!wp || !str(s.endpoint, 600) || !PUSHOK.test(s.endpoint) || !str(k.p256dh, 200) || !str(k.auth, 100)) return r.status(400).json({ error: 'اشتراك غير صالح' });
  await db.query(`insert into push_subs(endpoint,acc,p256dh,auth) values($1,$2,$3,$4)
    on conflict(endpoint) do update set acc=excluded.acc, p256dh=excluded.p256dh, auth=excluded.auth`, [s.endpoint, q.acc.id, k.p256dh, k.auth]);
  r.json({ ok: true });
});

/* ---------- أعضاء ورسائل ---------- */
app.get('/api/members', member, async (q, r) => r.json((await db.query(
  `select u.id, coalesce(u.name,u.username) name, u.username, coalesce(u.bio,'') bio,
   case when u.note_at > now() - interval '24 hours' then coalesce(u.note,'') else '' end note, coalesce(av.v,0)::float8 av,
   lm.body lb, lm.kind lk, lm.created_at lt, lm.from_id lf
   from accounts u left join avatars av on av.acc=u.id
   left join lateral (select body,kind,created_at,from_id from msgs where (from_id=u.id and to_id=$1) or (from_id=$1 and to_id=u.id) order by id desc limit 1) lm on true
   where u.id<>$1 and not coalesce(u.banned,false) and u.device is not null
   and u.id not in (select b from blocks where a=$1 union select a from blocks where b=$1) order by lm.created_at desc nulls last, u.id desc limit $2`, [q.acc.id, MAX + 50])).rows));
app.get('/api/unread', member, async (q, r) => r.json((await db.query(
  `select from_id, count(*)::int c from msgs where to_id=$1 and not seen
   and from_id not in (select b from blocks where a=$1 union select a from blocks where b=$1) group by from_id`, [q.acc.id])).rows));
app.get('/api/chat/:id', member, async (q, r) => {
  const o = idp(q.params.id); if (!o) return r.sendStatus(400);
  if (await blocked(q.acc.id, o)) return r.json([]);
  const bf = idp(q.query.before); // تحميل الرسائل الأقدم
  const rows = (await db.query(`select * from (select id,from_id,to_id,body,kind,file_id,created_at,seen from msgs
    where ((from_id=$1 and to_id=$2) or (from_id=$2 and to_id=$1)) and ($3::bigint=0 or id<$3) order by id desc limit 100) x order by id`, [q.acc.id, o, bf])).rows;
  if (!bf) { const u = await db.query('update msgs set seen=true where to_id=$1 and from_id=$2 and not seen', [q.acc.id, o]);
    if (u.rowCount) io.to('u:' + o).emit('seen', { by: q.acc.id }); }
  r.json(rows);
});
app.post('/api/seen/:id', member, async (q, r) => {
  const o = idp(q.params.id); if (!o) return r.sendStatus(400);
  const u = await db.query('update msgs set seen=true where to_id=$1 and from_id=$2 and not seen', [q.acc.id, o]);
  if (u.rowCount) io.to('u:' + o).emit('seen', { by: q.acc.id });
  r.json({ ok: true });
});

/* ---------- الحالات (24 ساعة) ---------- */
app.get('/api/statuses', member, async (q, r) => r.json((await db.query(
  `select s.acc id, coalesce(u.name,u.username) name, s.text, s.bg, s.created_at t, coalesce(av.v,0)::float8 av
   from statuses s join accounts u on u.id=s.acc left join avatars av on av.acc=s.acc
   where s.created_at > now() - interval '24 hours' and not coalesce(u.banned,false)
   and (s.acc=$1 or s.acc not in (select b from blocks where a=$1 union select a from blocks where b=$1))
   order by (s.acc=$1) desc, s.created_at desc limit 200`, [q.acc.id])).rows));
app.post('/api/status', member, lim(20, 60), async (q, r) => {
  const { text, bg } = q.body || {}, b = Number(bg);
  if (!str(text, 140) || !Number.isInteger(b) || b < 0 || b > 7) return r.status(400).json({ error: 'حالة غير صالحة' });
  await db.query(`insert into statuses(acc,text,bg) values($1,$2,$3)
    on conflict(acc) do update set text=excluded.text, bg=excluded.bg, created_at=now()`, [q.acc.id, text.trim(), b]);
  r.json({ ok: true });
});
app.delete('/api/status', member, async (q, r) => { await db.query('delete from statuses where acc=$1', [q.acc.id]); r.json({ ok: true }); });

/* ---------- الصور والتسجيلات الصوتية والفيديو ---------- */
app.post('/api/upload/:id', member, lim(40, 60), express.raw({ type: () => true, limit: '8mb' }), async (q, r) => {
  const to = idp(q.params.id), id = q.acc.id; if (!to || to === id) return r.sendStatus(400);
  const mime = String(q.headers['content-type'] || '').split(';')[0].trim().toLowerCase(), kind = FT[mime], b = q.body;
  if (!kind || !Buffer.isBuffer(b) || !b.length) return r.status(400).json({ error: 'نوع الملف غير مدعوم' });
  if (b.length > FLIM[kind]) return r.status(413).json({ error: 'الملف كبير' });
  if (!magic(kind, b)) return r.status(400).json({ error: 'ملف غير صالح' });
  if (tooFast(id)) return r.status(429).json({ error: 'بطّئ شوي' });
  if (uploading.has(id)) return r.status(429).json({ error: 'استنى لين يخلص الرفع السابق' });
  uploading.add(id); r.on('close', () => uploading.delete(id)); // يمنع تجاوز حد المساحة بطلبات متوازية
  const t = (await db.query('select banned from accounts where id=$1', [to])).rows[0];
  if (!t || t.banned || await blocked(id, to)) return r.status(403).json({ error: 'ما بتقدر تراسل هالشخص' });
  if (!(await db.query('select 1 from msgs where from_id=$1 and to_id=$2 limit 1', [to, id])).rowCount) // ما في صور وفيديو بدون موافقة: لازم هو يراسلك أول
    return r.status(403).json({ error: 'ما بتقدر ترسل صور أو فيديو أو صوت لهالشخص إلا بعد ما يراسلك هو أول' });
  const u = (await db.query('select coalesce(sum(size) filter (where from_id=$1),0)::float8 mine, coalesce(sum(size),0)::float8 total from files', [id])).rows[0];
  if (u.mine + b.length > 60e6) return r.status(413).json({ error: 'وصلت الحد الأقصى للملفات (60 ميغا). الملفات القديمة بتنحذف بعد 90 يوم' });
  if (u.total + b.length > (+process.env.MAX_FILES_MB || 500) * 1e6) return r.status(413).json({ error: 'مساحة الملفات بالموقع ممتلئة حالياً' });
  const f = (await db.query('insert into files(from_id,to_id,mime,size,data) values($1,$2,$3,$4,$5) returning id', [id, to, mime, b.length, b])).rows[0];
  const m = (await db.query("insert into msgs(from_id,to_id,body,kind,file_id) values($1,$2,'',$3,$4) returning id,from_id,to_id,body,kind,file_id,created_at",
    [id, to, kind, f.id])).rows[0];
  io.to('u:' + to).to('u:' + id).emit('msg', m); notifyFrom(id, to, kind, ''); r.json({ ok: true });
});
app.get('/api/file/:id', member, async (q, r) => {
  const fid = idp(q.params.id);
  const f = (await db.query('select mime,size from files where id=$1 and (from_id=$2 or to_id=$2)', [fid, q.acc.id])).rows[0];
  if (!f) return r.sendStatus(404);
  const n = f.size; let s = 0, e = n - 1;
  const rg = /bytes=(\d*)-(\d*)/.exec(q.headers.range || '');
  if (rg) { // دعم Range عشان الفيديو والصوت يشتغلوا على سفاري والجوال
    if (rg[1] !== '') { s = +rg[1]; if (rg[2] !== '') e = Math.min(+rg[2], e); } else if (rg[2] !== '') s = Math.max(0, n - +rg[2]);
    if (s > e || s >= n) return r.status(416).set('Content-Range', 'bytes */' + n).end();
    r.status(206).set('Content-Range', `bytes ${s}-${e}/${n}`);
  }
  const d = (await db.query('select substring(data from $2::int for $3::int) d from files where id=$1', [fid, s + 1, e - s + 1])).rows[0]; // بنقرأ الجزء المطلوب بس من القاعدة
  if (!d) return r.sendStatus(404);
  r.set({ 'Content-Type': f.mime, 'Accept-Ranges': 'bytes', 'Content-Length': e - s + 1, 'Cache-Control': 'private, max-age=86400', 'Content-Security-Policy': 'sandbox' })
    .end(d.d);
});

app.post('/api/report', member, lim(20, 60), async (q, r) => {
  const to = idp((q.body || {}).id); if (!to || to === q.acc.id) return r.sendStatus(400);
  const ms = (await db.query(`select from_id,body,kind,file_id from msgs where (from_id=$1 and to_id=$2) or (from_id=$2 and to_id=$1)
    order by id desc limit 10`, [q.acc.id, to])).rows.reverse();
  const ev = ms.map(m => (m.from_id === q.acc.id ? 'المُبلِّغ' : 'المُبلَّغ عليه') + ': ' + ((m.kind || 'text') === 'text' ? m.body : '[' + m.kind + ']')).join('\n');
  const fl = ms.filter(m => m.file_id).map(m => m.file_id).join(',');
  await db.query('insert into reports(from_id,to_id,reason,evidence,evidence_files) values($1,$2,$3,$4,$5)',
    [q.acc.id, to, String(q.body.reason || '').slice(0, 200), ev || null, fl || null]); r.json({ ok: true });
});
app.post('/api/block', member, async (q, r) => {
  const to = idp((q.body || {}).id); if (!to || to === q.acc.id) return r.sendStatus(400);
  await db.query('insert into blocks(a,b) values($1,$2) on conflict do nothing', [q.acc.id, to]); r.json({ ok: true });
});
app.get('/api/blocked', member, async (q, r) => r.json((await db.query(
  'select u.id, coalesce(u.name,u.username) name from blocks b join accounts u on u.id=b.b where b.a=$1 order by u.id', [q.acc.id])).rows));
app.delete('/api/block/:id', member, async (q, r) => {
  const to = idp(q.params.id); if (!to) return r.sendStatus(400);
  await db.query('delete from blocks where a=$1 and b=$2', [q.acc.id, to]); r.json({ ok: true });
});
// حذف رسالة (للطرفين). الملف المُبلَّغ عنه بيضل محفوظ للإدارة
app.delete('/api/msg/:id', member, lim(60, 10), async (q, r) => {
  const mid = idp(q.params.id); if (!mid) return r.sendStatus(400);
  const m = (await db.query('delete from msgs where id=$1 and from_id=$2 returning id,to_id,file_id', [mid, q.acc.id])).rows[0];
  if (!m) return r.sendStatus(404);
  if (m.file_id) await db.query(`delete from files where id=$1 and not exists
    (select 1 from reports where $1::text = any(string_to_array(evidence_files, ',')))`, [m.file_id]);
  io.to('u:' + m.to_id).to('u:' + q.acc.id).emit('msg:del', { id: mid }); r.json({ ok: true });
});
// حذف الحساب نهائياً مع كل بياناته
app.delete('/api/me', member, lim(5, 60), async (q, r) => {
  const { pass } = q.body || {}, id = q.acc.id;
  const okDel = q.acc.google_sub ? str(pass, 40) && pass.trim().toLowerCase() === String(q.acc.username).toLowerCase() // حساب جوجل: بنأكّد باسم المستخدم
    : str(pass, 40) && await checkPw(pass.trim(), q.acc.pass_hash);
  if (!okDel) return r.status(401).json({ error: q.acc.google_sub ? 'اسم المستخدم غلط' : 'كلمة السر غلط' });
  const c = await db.connect();
  try {
    await c.query('begin');
    for (const sql of ['delete from files where from_id=$1 or to_id=$1', 'delete from msgs where from_id=$1 or to_id=$1', 'delete from avatars where acc=$1',
      'delete from statuses where acc=$1', 'delete from push_subs where acc=$1', 'delete from blocks where a=$1 or b=$1',
      'delete from reports where from_id=$1 or to_id=$1', 'delete from accounts where id=$1']) await c.query(sql, [id]);
    await c.query('commit');
  } catch (e) { await c.query('rollback').catch(() => {}); throw e; } finally { c.release(); }
  xfer.delete(id); io.in('u:' + id).disconnectSockets(true);
  r.clearCookie('sid', { httpOnly: true, secure: true, sameSite: 'strict' }).cookie('lo', '1', CO); r.json({ ok: true });
});

/* ---------- طلبات الدعم: المستخدم يكتب مشكلته (حتى لو نسي كلمة السر) والإدارة ترد ---------- */
const TKRE = /^[A-Z0-9]{10}$/;
const tkGet = async code => { code = String(code || '').trim().toUpperCase(); return TKRE.test(code) ? (await db.query('select id,status from tickets where code=$1', [code])).rows[0] : null; };
app.post('/api/support', lim(5, 60), async (q, r) => {
  const { username, message } = q.body || {};
  if (!str(message, 1000)) return r.status(400).json({ error: 'اكتب مشكلتك (حتى 1000 حرف)' });
  let dv = ck(q, 'dv'); if (!DVRE.test(dv)) dv = null;
  if (dv && (await db.query("select count(*)::int c from tickets where device=$1 and status='open'", [dv])).rows[0].c >= 3)
    return r.status(429).json({ error: 'عندك طلبات مفتوحة كثيرة، استنى رد الإدارة' });
  const un = typeof username === 'string' ? username.trim().slice(0, 30) : '';
  const acct = un ? (await db.query('select id,device from accounts where lower(username)=lower($1)', [un])).rows[0] : null;
  const dm = !!(acct && acct.device && dv && safeEq(acct.device, dv)); // هل الطلب جاي من نفس الجهاز المسجّل للحساب؟
  const code = rnd(10, AL);
  const t = (await db.query('insert into tickets(code,username,device,acct_id,dev_match) values($1,$2,$3,$4,$5) returning id', [code, un || null, dv, acct ? acct.id : null, dm])).rows[0];
  await db.query('insert into ticket_msgs(ticket_id,from_admin,body) values($1,false,$2)', [t.id, message.trim()]);
  r.json({ code });
});
app.get('/api/support/:code', lim(60, 15), async (q, r) => {
  const t = await tkGet(q.params.code); if (!t) return r.status(404).json({ error: 'كود الطلب غلط أو انحذف' });
  r.json({ status: t.status, msgs: (await db.query('select from_admin,body,created_at t from ticket_msgs where ticket_id=$1 order by id', [t.id])).rows });
});
app.post('/api/support/:code/reply', lim(20, 60), async (q, r) => {
  const t = await tkGet(q.params.code); if (!t) return r.status(404).json({ error: 'كود الطلب غلط أو انحذف' });
  const body = (q.body || {}).body;
  if (!str(body, 1000)) return r.status(400).json({ error: 'اكتب الرد' });
  if (t.status === 'closed') return r.status(403).json({ error: 'الطلب مسكّر، افتح طلب جديد' });
  if ((await db.query('select count(*)::int c from ticket_msgs where ticket_id=$1', [t.id])).rows[0].c >= 40) return r.status(429).json({ error: 'كثرت الرسائل بهالطلب' });
  await db.query('insert into ticket_msgs(ticket_id,from_admin,body) values($1,false,$2)', [t.id, body.trim()]);
  await db.query('update tickets set updated_at=now() where id=$1', [t.id]); r.json({ ok: true });
});

/* ---------- الإدارة ---------- */
const AR = '٠١٢٣٤٥٦٧٨٩', FA = '۰۱۲۳۴۵۶۷۸۹';
const normPw = v => String(v).replace(/[٠-٩]/g, d => AR.indexOf(d)).replace(/[۰-۹]/g, d => FA.indexOf(d)).replace(/[\u200B-\u200F\u202A-\u202E\uFEFF]/g, '').trim(); // يقبل الأرقام العربية وأي مسافات مخفية
app.post('/api/admin/login', lim(15, 15), (q, r) => {
  const h = v => crypto.createHash('sha256').update(normPw(v)).digest();
  const given = h((q.body || {}).password || '');
  const okp = ADMIN_PASSES.map(p => crypto.timingSafeEqual(given, h(p))).some(Boolean);
  if (!okp) return r.status(401).json({ error: 'كلمة السر غلط' });
  r.json({ token: sign(Date.now() + 3600000) });
});
app.get('/api/admin/data', auth, async (_q, r) => {
  const accounts = (await db.query(`select id,username,${nm} name,coalesce(banned,false) banned,claimed_at,coalesce(device in (select dv from banned_devices),false) dban from accounts order by id desc limit 1000`)).rows;
  const reports = (await db.query(`select r.id,r.reason,r.to_id,(r.evidence is not null) ev,
    coalesce(a.name,a.username) fname, coalesce(b.name,b.username) tname, coalesce(b.banned,false) banned
    from reports r join accounts a on a.id=r.from_id join accounts b on b.id=r.to_id order by r.id desc limit 100`)).rows;
  const mb = (await db.query('select coalesce(sum(size),0)::float8 s from files')).rows[0].s / 1e6;
  r.json({ accounts, reports, max: MAX, online: online.size, mb: Math.round(mb) });
});
app.get('/api/admin/report/:id', auth, async (q, r) => {
  const x = (await db.query('select evidence,evidence_files from reports where id=$1', [idp(q.params.id)])).rows[0];
  r.json({ evidence: (x && x.evidence) || 'ما في أدلة محفوظة', files: ((x && x.evidence_files) || '').split(',').map(Number).filter(n => n > 0) });
});
app.get('/api/admin/file/:id', auth, async (q, r) => {
  const f = (await db.query('select mime,data from files where id=$1', [idp(q.params.id)])).rows[0];
  if (!f) return r.sendStatus(404);
  r.set({ 'Content-Type': f.mime, 'Content-Security-Policy': 'sandbox', 'Cache-Control': 'no-store' }).end(f.data);
});
app.delete('/api/admin/file/:id', auth, async (q, r) => {
  const id = idp(q.params.id); if (!id) return r.sendStatus(400);
  await db.query('delete from files where id=$1', [id]);
  await db.query("update msgs set kind='text', body='[تم حذف الملف من الإدارة]', file_id=null where file_id=$1", [id]);
  r.json({ ok: true });
});
app.post('/api/admin/ban/:id', auth, async (q, r) => {
  const on = !!(q.body || {}).on, id = idp(q.params.id); if (!id) return r.sendStatus(400);
  await db.query('update accounts set banned=$1 where id=$2', [on, id]);
  if (on) io.in('u:' + id).disconnectSockets(true);
  r.json({ ok: true });
});
app.post('/api/admin/reset/:id', auth, async (q, r) => {
  const p = rnd(10, AL), id = idp(q.params.id); if (!id) return r.sendStatus(400);
  await db.query('update accounts set pass_hash=$1, device=null, claimed_at=null, tv=tv+1 where id=$2', [await hashPw(p), id]);
  await db.query('delete from push_subs where acc=$1', [id]); xfer.delete(id);
  io.in('u:' + id).disconnectSockets(true); r.json({ pass: p });
});
app.delete('/api/admin/reports/:id', auth, async (q, r) => { await db.query('delete from reports where id=$1', [idp(q.params.id)]); r.json({ ok: true }); });

app.get('/api/admin/tickets', auth, async (_q, r) => r.json((await db.query(`select t.id,t.username,t.status,t.dev_match,t.acct_id,t.updated_at,
  coalesce((select not m.from_admin from ticket_msgs m where m.ticket_id=t.id order by m.id desc limit 1),false) waiting
  from tickets t order by (t.status='open') desc, t.updated_at desc limit 200`)).rows));
app.get('/api/admin/ticket/:id', auth, async (q, r) => {
  const id = idp(q.params.id);
  const t = (await db.query('select id,username,status,dev_match,acct_id from tickets where id=$1', [id])).rows[0];
  if (!t) return r.sendStatus(404);
  r.json({ ...t, msgs: (await db.query('select from_admin,body,created_at t from ticket_msgs where ticket_id=$1 order by id', [id])).rows });
});
app.post('/api/admin/ticket/:id/reply', auth, async (q, r) => {
  const id = idp(q.params.id), body = String((q.body || {}).body || '').trim().slice(0, 1000), close = !!(q.body || {}).close;
  if (!id || (!body && !close)) return r.sendStatus(400);
  if (!(await db.query('select 1 from tickets where id=$1', [id])).rowCount) return r.sendStatus(404);
  if (body) await db.query('insert into ticket_msgs(ticket_id,from_admin,body) values($1,true,$2)', [id, body]);
  await db.query('update tickets set status=$2, updated_at=now() where id=$1', [id, close ? 'closed' : 'open']); r.json({ ok: true });
});
app.delete('/api/admin/ticket/:id', auth, async (q, r) => {
  const id = idp(q.params.id); if (!id) return r.sendStatus(400);
  await db.query('delete from ticket_msgs where ticket_id=$1', [id]); await db.query('delete from tickets where id=$1', [id]); r.json({ ok: true });
});
// حظر / فك حظر الجهاز: كل الحسابات على هالجهاز بتنحظر، وما بيقدر يسجّل أو يدخل منه
app.post('/api/admin/device/:id', auth, async (q, r) => {
  const id = idp(q.params.id), on = !!(q.body || {}).on; if (!id) return r.sendStatus(400);
  const a = (await db.query('select username,device from accounts where id=$1', [id])).rows[0];
  if (!a || !a.device) return r.status(400).json({ error: 'هذا الحساب ما إله جهاز مسجّل' });
  const ids = (await db.query('select id from accounts where device=$1', [a.device])).rows.map(x => x.id);
  if (on) { await db.query('insert into banned_devices(dv,note) values($1,$2) on conflict do nothing', [a.device, a.username]); bandev.add(a.device); }
  else { await db.query('delete from banned_devices where dv=$1', [a.device]); bandev.delete(a.device); }
  await db.query('update accounts set banned=$1 where device=$2', [on, a.device]);
  if (on) ids.forEach(x => io.in('u:' + x).disconnectSockets(true));
  r.json({ ok: true, accounts: ids.length });
});

/* ---------- الاتصال المباشر (رسائل + إشارات المكالمات) ---------- */
const endPair = (a, b) => {
  for (const x of [a, b]) { calls.delete(x); callerOf.delete(x); answered.delete(x); clearTimeout(timers.get(x)); timers.delete(x); }
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
      const m = (await db.query('insert into msgs(from_id,to_id,body) values($1,$2,$3) returning id,from_id,to_id,body,kind,file_id,created_at', [id, to, body])).rows[0];
      io.to('u:' + to).to('u:' + id).emit('msg', m); ack({ ok: true });
      notifyFrom(id, to, 'msg', body);
    } catch (e) { console.error(e); ack({ error: 'صار خطأ' }); }
  });

  s.on('typing', async d => {
    const to = idp((d || {}).to); if (!to || to === id) return;
    const now = Date.now(); if (now - (typed.get(id) || 0) < 1500) return; typed.set(id, now); // حد للمعدل
    try { if (!(await blocked(id, to))) io.to('u:' + to).emit('typing', { from: id }); } catch (e) { console.error(e); }
  });

  s.on('call:offer', async (d, ack) => {
    ack = typeof ack === 'function' ? ack : () => {};
    let to = 0;
    try {
      to = idp((d || {}).to);
      if (!to || to === id || !online.has(to)) return ack({ error: 'الشخص مو أونلاين هلأ' });
      if (!d.sdp) return ack({ error: 'صار خطأ' });
      if (tooFast(id)) return ack({ error: 'بطّئ شوي' });
      const now = Date.now(), ch = (callHits.get(id) || []).filter(x => now - x < 60000), pk = id + ':' + to;
      if (ch.length >= 3 || now - (pairLast.get(pk) || 0) < 30000) return ack({ error: 'كثرت المحاولات، جرّب بعد شوي' }); // منع الإزعاج
      if (calls.has(id) || calls.has(to)) return ack({ error: 'مشغول، جرّب بعد شوي' });
      ch.push(now); callHits.set(id, ch); pairLast.set(pk, now);
      calls.set(id, to); calls.set(to, id); callerOf.set(id, id); callerOf.set(to, id); // نحجز المكالمة فوراً عشان إشارات ICE ما تضيع
      if (await blocked(id, to)) { endPair(id, to); return ack({ error: 'ما بتقدر تتصل فيه' }); }
      timers.set(id, setTimeout(() => { // مهلة 45 ثانية إذا ما حدا رد
        if (calls.get(id) === to && !answered.has(id)) { endPair(id, to); io.to('u:' + id).to('u:' + to).emit('call:end', { from: 0 }); }
      }, 45000));
      io.to('u:' + to).emit('call:offer', { from: id, sdp: d.sdp, video: !!d.video }); ack({ ok: true });
      notifyFrom(id, to, 'call', d.video ? 'مكالمة فيديو' : 'مكالمة صوتية');
    } catch (e) { console.error(e); if (to && calls.get(id) === to) endPair(id, to); ack({ error: 'صار خطأ' }); } // تنظيف الحجز لو صار خطأ
  });
  s.on('call:answer', d => {
    const to = idp((d || {}).to); if (!to || calls.get(id) !== to) return;
    if (callerOf.get(id) !== to || answered.has(id)) return; // بس المستقبِل يقدر يرد، ومرة وحدة
    answered.add(id); answered.add(to); clearTimeout(timers.get(to)); timers.delete(to);
    s.to('u:' + id).emit('call:end', { from: 0 }); // التابات الثانية عند المستقبِل بتوقف الرنين
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

/* ---------- الشعار ---------- */
const LOGO = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
<stop offset="0" stop-color="#19e3ff"/><stop offset=".5" stop-color="#ff2e88"/><stop offset="1" stop-color="#ffc83d"/></linearGradient></defs>
<circle cx="64" cy="64" r="60" fill="#07050f" stroke="url(#g)" stroke-width="6"/>
<path d="M38 36h52a12 12 0 0 1 12 12v30a12 12 0 0 1-12 12H72L56 106V90H38a12 12 0 0 1-12-12V48a12 12 0 0 1 12-12z" fill="none" stroke="url(#g)" stroke-width="5" stroke-linejoin="round"/>
<rect x="60" y="52" width="8" height="30" rx="4" fill="#ffc83d"/><path d="M58 45l12-5" stroke="#ffc83d" stroke-width="5" stroke-linecap="round"/></svg>`;
const MANIFEST = JSON.stringify({ name: 'أربكس الدردشة', short_name: 'أربكس', start_url: '/', display: 'standalone', dir: 'rtl', lang: 'ar',
  background_color: '#07050f', theme_color: '#07050f', icons: [{ src: '/logo.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any' }] });

// عامل الخدمة: بيعرض إشعار الجهاز لما توصل رسالة أو مكالمة والموقع مو أمامك
const SW = `self.addEventListener('push',e=>{let d={};try{d=e.data.json()}catch(x){}
e.waitUntil(self.clients.matchAll({type:'window',includeUncontrolled:true}).then(cs=>{
const vis=cs.some(c=>c.visibilityState==='visible'&&c.focused),call=d.kind==='call',tag=d.tag||'x';
return self.registration.showNotification(d.title||'أربكس الدردشة',{body:d.body||'',tag:tag,renotify:!vis,silent:vis,icon:'/logo.svg',badge:'/logo.svg',
requireInteraction:call&&!vis,vibrate:call?[300,200,300,200,300]:[120]}).then(()=>{if(!vis)return;
return new Promise(k=>setTimeout(k,700)).then(()=>self.registration.getNotifications({tag:tag})).then(ns=>ns.forEach(n=>n.close()))})}))});
self.addEventListener('notificationclick',e=>{e.notification.close();
e.waitUntil(self.clients.matchAll({type:'window',includeUncontrolled:true}).then(cs=>{
for(const c of cs){if('focus' in c)return c.focus()}return self.clients.openWindow('/')}))});`;

/* ---------- الواجهة ---------- */
const HTML = `<!doctype html>
<html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="google-site-verification" content="-ZH8A2zcBXWEltSL4_qjskRG7Bs0gUjzplly7_XwF1M" />
<meta name="theme-color" content="#07050f"><meta name="mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-capable" content="yes">
<title>أربكس الدردشة</title>
<link rel="icon" href="/logo.svg" type="image/svg+xml"><link rel="manifest" href="/manifest.json">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;700&family=Lalezar&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/style.css"></head><body>
<div class="bg" aria-hidden="true"><i></i><i></i></div>
<section id="land" class="hero">
  <img class="logo" src="/logo.svg" alt="شعار أربكس الدردشة" width="132" height="132">
  <p class="kicker">أهلاً فيك في</p><h1>أربكس الدردشة</h1>
  <p class="by">تم إنشاء الموقع بواسطة <a href="https://www.instagram.com/bdllh.nqws" target="_blank" rel="noopener noreferrer">عبدالله ابو ناقوس</a></p>
  <p class="sub">دردشة ومكالمات حقيقية بين الأعضاء.</p>
  <a class="ig" href="https://www.instagram.com/bdllh.nqws" target="_blank" rel="noopener noreferrer">تابعني على انستجرام</a>
  <div class="links">
    <a href="https://www.instagram.com/rbkslbrmjh" target="_blank" rel="noopener noreferrer">انستجرام أربكس البرمجة</a>
    <a href="https://arb-ai-x.github.io/arabesque-de/" target="_blank" rel="noopener noreferrer">موقع أربكس البرمجة</a>
  </div>
  <div id="auth" class="glass">
    <div id="tabs" class="tabs"><button type="button" id="tl" class="tab on">دخول</button><button type="button" id="ts" class="tab" hidden>حساب جديد</button></div>
    <div id="gwrap" hidden><div id="gbtn"></div><p class="hintp">أو بالاسم وكلمة السر:</p></div>
    <form id="lg"><input name="username" placeholder="اسم المستخدم" maxlength="30" autocomplete="username" autocapitalize="off" autocorrect="off" spellcheck="false" required>
      <input name="pass" type="password" placeholder="كلمة السر" autocomplete="current-password" autocapitalize="off" autocorrect="off" spellcheck="false" maxlength="40" required>
      <button>دخول</button><p id="lgmsg" role="status"></p><button type="button" id="fg" class="lnk">نسيت كلمة السر</button> <button type="button" id="hp" class="lnk">تواصل مع الإدارة</button></form>
    <form id="su" hidden><input id="suu" name="username" placeholder="اختر اسم مستخدم" maxlength="20" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" required>
      <p id="unmsg" role="status"></p>
      <input name="pass" type="password" placeholder="اختر كلمة سر (8 أحرف على الأقل)" autocomplete="new-password" maxlength="40" required>
      <input name="pass2" type="password" placeholder="أعد كتابة كلمة السر" autocomplete="new-password" maxlength="40" required>
      <label class="chk"><input type="checkbox" name="adult"> أؤكد أن عمري 18 سنة أو أكثر وألتزم بقواعد الموقع</label>
      <button>إنشاء الحساب</button><p id="sumsg" role="status"></p><p class="hintp">حسابين كحد أقصى لكل جهاز.</p></form>
    <form id="cd" hidden><p>وصل كود من 6 أرقام لجهازك القديم. افتح الموقع عليه واكتب الكود هون:</p>
      <input name="code" inputmode="numeric" placeholder="الكود" maxlength="6" autocomplete="one-time-code" required>
      <button>تأكيد</button> <button type="button" id="cdx" class="lnk">رجوع</button><p id="cdmsg" role="status"></p></form>
    <form id="rc" hidden><p>اختر حسابك واكتب كلمة سر جديدة:</p><select name="username" id="rcsel"></select>
      <input name="pass" type="password" placeholder="كلمة السر الجديدة (8 أحرف على الأقل)" autocomplete="new-password" maxlength="40" required>
      <input name="pass2" type="password" placeholder="أعد كتابتها" autocomplete="new-password" maxlength="40" required>
      <button>حفظ ودخول</button> <button type="button" id="rcx" class="lnk">رجوع</button><p id="rcmsg" role="status"></p></form>
    <form id="gu" hidden><p>تمام! اختر اسم مستخدم لحسابك:</p>
      <input id="guu" name="username" placeholder="اسم المستخدم" maxlength="20" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" required>
      <p id="gunmsg" role="status"></p>
      <label class="chk"><input type="checkbox" name="adult"> أؤكد أن عمري 18 سنة أو أكثر وألتزم بقواعد الموقع</label>
      <button>متابعة</button> <button type="button" id="gux" class="lnk">رجوع</button><p id="gumsg" role="status"></p></form>
    <form id="sp" hidden><p>اكتب مشكلتك (نسيت كلمة السر، حسابك محظور، فقدت جهازك...) وبترد عليك الإدارة.</p>
      <input name="username" placeholder="اسم المستخدم (إذا بتتذكره)" maxlength="30" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false">
      <textarea name="message" rows="4" maxlength="1000" placeholder="اشرح مشكلتك" required></textarea>
      <button>إرسال للإدارة</button> <button type="button" id="spo" class="lnk">عندي كود طلب</button> <button type="button" id="spx" class="lnk">رجوع</button><p id="spmsg" role="status"></p></form>
    <div id="spt" hidden><p>كود طلبك (احتفظ فيه): <b id="spc"></b></p><p id="sps" class="hintp"></p><div id="spm"></div>
      <textarea id="spr" rows="3" maxlength="1000" placeholder="اكتب ردك"></textarea>
      <button type="button" id="sprb">إرسال</button> <button type="button" id="spre" class="lnk">تحديث</button> <button type="button" id="spn" class="lnk">طلب جديد</button> <button type="button" id="sptx" class="lnk">رجوع</button><p id="sptm" role="status"></p></div>
  </div>
</section>
<section id="app" hidden>
  <aside>
    <div class="top"><div class="brand"><img src="/logo.svg" alt="" width="34" height="34"><span>أربكس الدردشة</span></div><button id="gear">الإعدادات</button></div>
    <button id="me" class="meb"><span id="meav"></span><b id="myname"></b></button>
    <div class="tabs"><button type="button" id="tc" class="tab on">المحادثات</button><button type="button" id="tst" class="tab">الحالات</button></div>
    <div id="onc"></div>
    <div id="pc" class="pane"><input id="q" placeholder="ابحث بالاسم أو اسم المستخدم"><div id="list"></div></div>
    <div id="ps" class="pane" hidden><button id="mys">أضف حالة</button><div id="slist"></div></div>
    <div class="slinks"><a href="https://www.instagram.com/bdllh.nqws" target="_blank" rel="noopener noreferrer">عبدالله ابو ناقوس</a>
      <a href="https://www.instagram.com/rbkslbrmjh" target="_blank" rel="noopener noreferrer">انستجرام أربكس البرمجة</a>
      <a href="https://arb-ai-x.github.io/arabesque-de/" target="_blank" rel="noopener noreferrer">موقع أربكس البرمجة</a></div>
  </aside>
  <div id="chat" data-bg="0"><p id="hint">اختر عضو من القائمة لتبدأ المحادثة.</p>
    <div id="cbox" hidden><div class="chead"><button id="back">رجوع</button><span id="cav"></span><div class="cn"><b id="cname"></b><small id="cstat"></small></div>
      <button id="vc">صوت</button><button id="vv">فيديو</button>
      <details class="more"><summary>المزيد</summary><div><button id="rep">إبلاغ</button><button id="blk">حظر</button></div></details></div>
      <button id="older" class="alt" hidden>تحميل الرسائل الأقدم</button><div id="msgs"></div><p id="typing" hidden>يكتب...</p>
      <form id="send"><label class="att">مرفق<input type="file" id="file" accept="image/*,video/*" hidden></label><button type="button" id="rec">تسجيل</button>
        <input id="txt" maxlength="1000" autocomplete="off" placeholder="اكتب رسالة"><button>إرسال</button></form></div></div>
</section>
<div id="call" hidden><video id="rv" autoplay playsinline></video><video id="lv" autoplay playsinline muted></video>
  <div class="cc"><button id="mute">كتم</button><button id="cam">كاميرا</button><button id="end">إنهاء</button></div></div>
<dialog id="ring"><p id="rtext"></p><button id="acc">رد</button> <button id="rej">رفض</button></dialog>
<dialog id="xf"><p>في طلب دخول لحسابك من جهاز جديد. هذا الكود:</p><b id="xcode"></b><p>اكتبه بالجهاز الجديد. إذا مو إنت، تجاهله.</p><button id="xok">تم</button></dialog>
<dialog id="stc"><h3>حالتك (تنحذف بعد 24 ساعة)</h3>
  <div id="stp" class="sc s0"><p id="stpt" class="stx">اكتب حالتك</p></div>
  <textarea id="stt" maxlength="140" rows="3" placeholder="اكتب حالتك"></textarea>
  <div id="stsw" class="swr"></div>
  <div class="row"><button id="stpub">نشر</button><button id="stdel" class="alt">حذف حالتي</button><button id="stx" class="alt">إغلاق</button></div></dialog>
<dialog id="st"><div class="row"><h3>الإعدادات</h3><button id="stclose" class="alt">إغلاق</button></div>
  <h4>ملفي</h4>
  <div class="row"><span id="stav"></span><label class="att">تغيير الصورة<input type="file" id="avf" accept="image/*" hidden></label><button type="button" id="avd" class="alt">حذف الصورة</button></div>
  <label>الاسم<input id="sn" maxlength="30"></label>
  <label>النبذة<input id="sb" maxlength="120"></label>
  <label>ملاحظة تظهر 24 ساعة جنب اسمك<input id="sno" maxlength="60"></label>
  <button id="ssave">حفظ</button>
  <h4>المحظورين</h4><div id="bl"></div>
  <h4>المظهر</h4>
  <label>المود<select id="th"><option value="">الأصلي</option><option value="girls">بنات</option><option value="boys">شباب</option><option value="disco">ديسكو</option><option value="hacker">هكر</option></select></label>
  <div class="row"><label>لون الخط<input type="color" id="fc"></label><button type="button" id="fcr" class="alt">الافتراضي</button></div>
  <label>حجم الخط<select id="fs"><option value="14">صغير</option><option value="16">عادي</option><option value="18">كبير</option><option value="20">كبير جداً</option></select></label>
  <label>خلفية المحادثة<select id="bgs"><option value="0">سادة</option><option value="1">تدرج</option><option value="2">نقاط</option><option value="3">شبكة</option><option value="4">نجوم</option><option value="5">خطوط</option></select></label>
  <h4>الإشعارات والصوت</h4>
  <button id="pn">تفعيل إشعارات الجهاز</button><p id="pmsg" role="status"></p>
  <label class="chk"><input type="checkbox" id="snd"> صوت الرسائل</label>
  <div id="pwbox"><h4>كلمة السر</h4>
  <input type="password" id="op" placeholder="الحالية" autocomplete="current-password"><input type="password" id="np" placeholder="الجديدة (8 أحرف على الأقل)" autocomplete="new-password">
  <button id="pch">تغيير كلمة السر</button></div>
  <h4>الحساب</h4><button id="out" class="alt">تبديل الحساب / خروج</button> <button id="del" class="alt">حذف حسابي نهائياً</button></dialog>
<footer><div class="foot">
  <p>تم إنشاء الموقع بواسطة <a href="https://www.instagram.com/bdllh.nqws" target="_blank" rel="noopener noreferrer">عبدالله ابو ناقوس</a></p>
  <p><a href="https://www.instagram.com/rbkslbrmjh" target="_blank" rel="noopener noreferrer">انستجرام أربكس البرمجة</a> ·
     <a href="https://arb-ai-x.github.io/arabesque-de/" target="_blank" rel="noopener noreferrer">موقع أربكس البرمجة</a></p>
  <p class="rules">للأعضاء 18 سنة فأكثر فقط. ممنوع الإساءة والتحرش وانتحال الشخصية، وأي بلاغ بيتراجع.</p></div>
  <button id="dot" aria-label="."></button></footer>
<dialog id="admin"><form method="dialog"><button>إغلاق</button></form>
<form id="alogin"><input type="password" id="pw" placeholder="كلمة السر" autocomplete="current-password" autocapitalize="off" autocorrect="off" spellcheck="false"><button>دخول</button><p id="amsg" role="status"></p></form>
<div id="panel" hidden><div id="evbox" hidden></div><div id="tkbox" hidden></div><h3>طلبات الدعم <small id="tcnt"></small></h3><div class="scroll"><table id="tkt"></table></div><h3>البلاغات</h3><div class="scroll"><table id="reps"></table></div>
<h3>الحسابات <small id="cnt"></small></h3><div class="scroll"><table id="accs"></table></div></div></dialog>
<script src="/socket.io/socket.io.js"></script><script src="/app.js"></script></body></html>`;

const CSS = `:root{--ink:#07050f;--m:#ff2e88;--c:#19e3ff;--g:#ffc83d;--p:#f6f1ff;--b2:#7a5cff;--ff:Cairo,sans-serif}
html[data-theme=girls]{--ink:#1a0b14;--m:#ff4fa3;--c:#ff9ad5;--g:#ffd1e8;--p:#fff0f7;--b2:#b44cff}
html[data-theme=boys]{--ink:#06101f;--m:#2f80ff;--c:#19c3ff;--g:#8ec5ff;--p:#eaf3ff;--b2:#1b4fd8}
html[data-theme=disco]{--ink:#0a0014;--m:#ff00e6;--c:#00fff0;--g:#fff700;--p:#ffffff;--b2:#7a00ff}
html[data-theme=hacker]{--ink:#000;--m:#00ff41;--c:#00ff41;--g:#39ff14;--p:#b6ffb6;--b2:#006b1c;--ff:"Courier New",monospace}
*{box-sizing:border-box}[hidden]{display:none!important}
html{font-size:var(--fs,16px)}
body{margin:0;background:var(--ink);color:var(--p);font-family:var(--ff);line-height:1.6}
a{color:var(--c)}
.bg{position:fixed;inset:0;z-index:-1;overflow:hidden}
.bg i{position:absolute;width:55vmax;height:55vmax;border-radius:50%;filter:blur(90px);opacity:.5;animation:dr 18s ease-in-out infinite alternate}
.bg i:nth-child(1){background:var(--b2);top:-20%;right:-15%}.bg i:nth-child(2){background:var(--m);bottom:-25%;left:-20%;animation-delay:-6s}
html[data-theme=disco] .bg i{animation:dr 18s ease-in-out infinite alternate,hue 5s linear infinite}
html[data-theme=hacker] .bg{background:repeating-linear-gradient(0deg,#00ff4112 0 2px,transparent 2px 4px)}
@keyframes dr{to{transform:translate(8vmax,-6vmax) scale(1.15)}}
@keyframes hue{to{filter:blur(90px) hue-rotate(360deg)}}
.hero{min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:40px 18px}
.logo{width:132px;height:132px;margin-bottom:14px;filter:drop-shadow(0 0 26px #ff2e8888);animation:fl 4s ease-in-out infinite alternate}
@keyframes fl{to{transform:translateY(-8px)}}
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
.glass form{margin:0}
.chk{display:flex;gap:8px;align-items:center;justify-content:center;margin-bottom:12px;font-size:.95rem}
input,select,textarea{width:100%;margin-bottom:10px;padding:12px 14px;border-radius:12px;border:1px solid #ffffff2a;background:#0b0818aa;color:var(--p);font:inherit}
input[type=checkbox],input[type=color]{width:auto;margin:0}input[type=color]{height:38px;padding:2px;vertical-align:middle}
textarea{resize:none}select option{background:#0b0818;color:#fff}
input:focus,select:focus,textarea:focus,button:focus-visible,a:focus-visible,summary:focus-visible{outline:2px solid var(--c);outline-offset:2px}
button{padding:10px 20px;border:0;border-radius:12px;background:linear-gradient(135deg,var(--c),var(--b2));color:#06111a;font:700 1rem var(--ff);cursor:pointer}
button:hover{filter:brightness(1.15)}
button.alt{background:#ffffff18;color:var(--p)}
button.lnk{background:none;color:var(--c);text-decoration:underline;padding:8px;font-size:.9rem}
p[role=status]{min-height:1.4em;margin:6px 0 0;font-size:.9rem}.good{color:#2ee6a0}.bad{color:#ff6b8a}.hintp{font-size:.8rem;color:#b9aedd;margin:4px 0 0}
.tabs{display:flex;gap:6px;margin-bottom:10px}.tab{flex:1;background:#ffffff14;color:var(--p);padding:8px}.tab.on{background:linear-gradient(135deg,var(--c),var(--b2));color:#06111a}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:10px}.row h3{flex:1;margin:0}
.av{display:inline-grid;place-items:center;border-radius:50%;overflow:hidden;color:#fff;font-weight:700;flex:none}.av img{width:100%;height:100%;object-fit:cover}
.avw{position:relative;flex:none;display:inline-flex}.avw .dot{position:absolute;bottom:0;inset-inline-end:0;border:2px solid var(--ink)}
#app{display:grid;grid-template-columns:340px 1fr;height:100dvh}
body.in footer{display:none}
aside{border-inline-end:1px solid #ffffff1f;display:flex;flex-direction:column;min-height:0;background:#0b0818cc;padding:10px}
.top{display:flex;align-items:center;gap:8px;margin-bottom:6px}.top button{padding:6px 12px;font-size:.85rem}
.brand{flex:1;display:flex;align-items:center;gap:8px;font:1.5rem/1.2 Lalezar,sans-serif;color:var(--g)}
.meb{display:flex;align-items:center;gap:8px;width:100%;background:#ffffff0d;color:var(--p);margin-bottom:8px;padding:6px 10px;text-align:start}
#onc{font-size:.85rem;color:#2ee6a0;margin-bottom:6px}
.pane{flex:1;min-height:0;display:flex;flex-direction:column}
#list,#slist{overflow:auto;flex:1}
.slinks{display:flex;flex-wrap:wrap;gap:4px 10px;padding-top:8px;margin-top:6px;border-top:1px solid #ffffff1f;font-size:.8rem}
.slinks a{color:var(--g);text-decoration:none}.slinks a:hover{text-decoration:underline}
.mem{display:flex;gap:12px;align-items:center;padding:10px;cursor:pointer;border-radius:14px}
.mem.act,.mem:hover{background:#ffffff14}.mt{flex:1;min-width:0}.mt b{display:block}
.mt small{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#b9aedd}
.dot{width:12px;height:12px;border-radius:50%;background:#555}.dot.on{background:#2ee6a0;box-shadow:0 0 8px #2ee6a0}
.bdg{background:var(--m);border-radius:20px;padding:0 9px;font-weight:700;color:#fff}
.mut{color:#b9aedd;text-align:center;margin:20px 0}
.sc{border-radius:18px;padding:16px;margin:8px 0;min-height:96px;display:flex;flex-direction:column;justify-content:space-between;color:#fff;text-shadow:0 1px 3px #0006}
.stx{margin:0 0 10px;font-size:1.15rem;font-weight:700;text-align:center;overflow-wrap:anywhere}
.sf{display:flex;align-items:center;gap:8px;font-size:.85rem}.sf small{margin-inline-start:auto;opacity:.85}
.s0{background:linear-gradient(135deg,#6a1bff,#ff2e88)}.s1{background:linear-gradient(135deg,#19e3ff,#7a5cff)}.s2{background:linear-gradient(135deg,#ff8a3d,#ff2e88)}.s3{background:linear-gradient(135deg,#2ee6a0,#0b8f6a)}
.s4{background:linear-gradient(135deg,#ff8a3d,#c2410c)}.s5{background:linear-gradient(135deg,#ff4fa3,#b44cff)}.s6{background:linear-gradient(135deg,#1b4fd8,#19c3ff)}.s7{background:linear-gradient(135deg,#111,#555)}
.swr{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px}.sw{width:34px;height:34px;border-radius:50%;padding:0;border:3px solid transparent}.sw.on{border-color:#fff}
#chat{display:flex;flex-direction:column;min-height:0;background-color:#00000026}#hint{margin:auto;color:#b9aedd}
#chat[data-bg="1"]{background-image:linear-gradient(160deg,#ffffff08,#ff2e8818 60%,#19e3ff18)}
#chat[data-bg="2"]{background-image:radial-gradient(#ffffff1c 1.5px,transparent 1.5px);background-size:22px 22px}
#chat[data-bg="3"]{background-image:linear-gradient(#ffffff0f 1px,transparent 1px),linear-gradient(90deg,#ffffff0f 1px,transparent 1px);background-size:26px 26px}
#chat[data-bg="4"]{background-image:radial-gradient(2px 2px at 20px 30px,#fff9,transparent),radial-gradient(1.5px 1.5px at 90px 80px,#fff8,transparent),radial-gradient(2px 2px at 160px 40px,#ffc83dcc,transparent),radial-gradient(1.5px 1.5px at 60px 140px,#19e3ffaa,transparent);background-size:200px 180px}
#chat[data-bg="5"]{background-image:repeating-linear-gradient(45deg,#ffffff0a 0 12px,transparent 12px 24px)}
#cbox{display:flex;flex-direction:column;flex:1;min-height:0}
.chead{display:flex;gap:8px;align-items:center;padding:10px;border-bottom:1px solid #ffffff1f;background:#0b0818cc}.chead button{padding:6px 12px}
.cn{flex:1;min-width:0;display:flex;flex-direction:column;line-height:1.3}.cn small{color:#b9aedd}.cn small.ok{color:#2ee6a0}
.more{position:relative}.more summary{list-style:none;cursor:pointer;padding:6px 12px;border-radius:12px;background:#ffffff18;font-weight:700}
.more summary::-webkit-details-marker{display:none}
.more>div{position:absolute;inset-inline-end:0;top:115%;background:var(--ink);border:1px solid #ffffff2a;border-radius:12px;padding:6px;display:flex;flex-direction:column;gap:6px;z-index:5}
#back{display:none}
#msgs{flex:1;overflow:auto;padding:16px;display:flex;flex-direction:column;gap:6px}
.m{max-width:75%;padding:9px 14px;border-radius:20px;background:#ffffff1f;align-self:flex-start;overflow-wrap:anywhere;border-end-start-radius:6px}
.m.me{align-self:flex-end;background:linear-gradient(135deg,var(--b2),var(--m));border-end-start-radius:20px;border-end-end-radius:6px}
.m small.t{display:block;opacity:.65;font-size:.7rem;margin-top:2px}
.pic{max-width:100%;max-height:300px;border-radius:12px;display:block}.vid{max-width:100%;max-height:320px;border-radius:12px;display:block}
.m audio{width:240px;max-width:100%;display:block}
#typing{margin:0;padding:0 16px 4px;color:var(--c);font-size:.85rem}
#send{display:flex;gap:8px;padding:10px;align-items:center;background:#0b0818cc}#send input{margin:0;border-radius:24px}
#send button,.att{padding:10px 14px;font-size:.9rem;white-space:nowrap}
.att{border-radius:12px;background:#ffffff18;cursor:pointer;font-weight:700;display:inline-block}.att:hover{background:#ffffff2a}
#rec{background:#ffffff18;color:var(--p)}#rec.on{background:#e11d2e;color:#fff}
#call{position:fixed;inset:0;background:#000;z-index:50}#rv{width:100%;height:100%;object-fit:cover}
#lv{position:absolute;width:110px;bottom:90px;left:14px;border-radius:12px}
.cc{position:absolute;bottom:20px;width:100%;display:flex;justify-content:center;gap:12px}
footer{display:flex;flex-direction:column;align-items:center;gap:10px;padding:24px;text-align:center}
.foot p{margin:2px 0;font-size:.9rem;color:#d8cdf5}.foot a{color:var(--g);text-decoration:none;font-weight:700}.foot a:hover{text-decoration:underline}
.foot .rules{color:#b9aedd;font-size:.8rem}
#dot{width:9px;height:9px;padding:0;border-radius:50%;background:#e11d2e;opacity:.8}
dialog{border:1px solid var(--c);border-radius:18px;background:var(--ink);color:var(--p);width:min(680px,94vw);max-height:90vh}
dialog::backdrop{background:#000b}.scroll{overflow-x:auto}
#st,#stc{width:min(460px,94vw)}#st h4{margin:16px 0 8px;color:var(--g)}#st label{display:block;margin-bottom:6px;font-size:.9rem}
#xf{text-align:center;width:min(380px,94vw)}#xcode{display:block;font-size:2.2rem;letter-spacing:.3em;color:var(--g);margin:10px 0}
table{width:100%;border-collapse:collapse;font-size:.9rem}td,th{padding:6px 8px;border-bottom:1px solid #2c2250;text-align:right}td button{padding:4px 10px;margin-inline-start:4px}
@media (max-width:700px){#app{grid-template-columns:1fr}body.chatting aside{display:none}body:not(.chatting) #chat{display:none}#back{display:block}.m{max-width:85%}}
@media (prefers-reduced-motion:reduce){*{animation:none!important}h1{color:var(--g);background:none}}
#gwrap{display:flex;flex-direction:column;align-items:center;margin-bottom:10px}#tabs[hidden]~#gwrap{display:none!important}
.rd{color:#19e3ff;font-weight:700}
.sm{background:#ffffff14;border-radius:12px;padding:8px 12px;margin:6px 0;text-align:right;overflow-wrap:anywhere}.sm.adm{background:linear-gradient(135deg,var(--b2),var(--m))}
.sm small{display:block;opacity:.7;font-size:.7rem}#spm,#tkbox .spm{max-height:240px;overflow:auto}#spc{letter-spacing:.15em;color:var(--g)}
#tkbox{border:1px solid #ffffff2a;border-radius:12px;padding:10px;margin-bottom:12px}#bl .row span{flex:1}#older{width:100%;border-radius:0;margin:0}
.m .del{background:none;color:inherit;opacity:.6;padding:0 6px;font-size:.7rem;margin-inline-start:6px;display:inline}
#evbox{border:1px solid #ffffff2a;border-radius:12px;padding:10px;margin-bottom:12px}#evbox>div{margin:8px 0}
#evbox pre{white-space:pre-wrap;text-align:right;background:#ffffff0d;padding:8px;border-radius:10px;overflow-wrap:anywhere}`;

const JS = `const $=s=>document.querySelector(s);
const el=(t,c,x)=>{const e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e};
let token='',me,members=[],on=new Set(),unread={},cur=0,sock,pc,ls,peer=0,pend=null,seen=false,tTimer=0,lastT=0,cred=null,rc=null,rch=[],reg=null,vk='',sbg=0,ac=null,rt=0,quiet=false;const qc=[];
let pr={};try{pr=JSON.parse(localStorage.getItem('prefs')||'{}')||{}}catch(e){pr={}}
function applyPr(){const h=document.documentElement;h.dataset.theme=pr.th||'';
  if(pr.fc)h.style.setProperty('--p',pr.fc);else h.style.removeProperty('--p');
  if(pr.fs)h.style.setProperty('--fs',pr.fs+'px');else h.style.removeProperty('--fs');
  $('#chat').dataset.bg=pr.bg||'0'}
const savePr=()=>{try{localStorage.setItem('prefs',JSON.stringify(pr))}catch(e){}applyPr()};
applyPr();
async function api(path,method='GET',body){
  const r=await fetch('/api'+path,{method,headers:{'Content-Type':'application/json',...(token&&{Authorization:'Bearer '+token})},body:body&&JSON.stringify(body)});
  const d=await r.json().catch(()=>({}));
  if(!r.ok)throw new Error(d.error||(r.status===429?'محاولات كثيرة، انتظر شوي':'صار خطأ'));
  return d}
const safe=f=>async()=>{try{await f()}catch(x){alert(x.message)}};
const nameOf=id=>(members.find(m=>m.id===id)||{}).name||'عضو';
const tm=t=>{try{return new Date(t).toLocaleTimeString('ar',{hour:'2-digit',minute:'2-digit'})}catch(e){return ''}};
const ago=t=>{const m=Math.max(1,Math.round((Date.now()-new Date(t))/6e4));return m<60?m+' د':Math.round(m/60)+' س'};
const bot=()=>{$('#msgs').scrollTop=1e9};
const ini=n=>[...String(n).trim()][0]||'؟';
function av(m,sz){const d=el('span','av');d.style.width=d.style.height=sz+'px';d.style.fontSize=Math.round(sz*.45)+'px';d.style.background='hsl('+(m.id*47%360)+',55%,42%)';
  if(m.av){const i=el('img');i.src='/api/avatar/'+m.id+'?v='+m.av;i.alt='';i.onerror=()=>{i.remove();d.textContent=ini(m.name)};d.append(i)}else d.textContent=ini(m.name);return d}

/* أصوات: نغمة الرسائل ورنين المكالمات */
const actx=()=>{ac=ac||new(window.AudioContext||window.webkitAudioContext)();if(ac.state==='suspended')ac.resume();return ac};
function tone(f,t0,d,v){const c=actx(),o=c.createOscillator(),g=c.createGain(),t=c.currentTime+t0;o.type='sine';o.frequency.value=f;
  g.gain.setValueAtTime(0,t);g.gain.linearRampToValueAtTime(v||.15,t+.02);g.gain.linearRampToValueAtTime(0,t+d);o.connect(g);g.connect(c.destination);o.start(t);o.stop(t+d+.05)}
const ding=()=>{if(pr.snd===false)return;try{tone(880,0,.15);tone(1175,.16,.25)}catch(e){}};
function ringStop(){clearInterval(rt);rt=0}
function ringStart(out){ringStop();
  const p=out?()=>{tone(440,0,.5,.1);tone(480,0,.5,.1)}:()=>{[0,.2,.4,.9,1.1,1.3].forEach((t,i)=>tone([659,784,988][i%3],t,i%3===2?.3:.18))};
  try{p()}catch(e){}rt=setInterval(()=>{try{p()}catch(e){}},out?3000:2600);if(!out&&navigator.vibrate)navigator.vibrate([300,200,300])}
document.addEventListener('pointerdown',()=>{try{actx()}catch(e){}},{once:true});

function stat(){if(!cur)return;const o=on.has(cur);$('#cstat').textContent=o?'نشط الآن':'غير متصل';$('#cstat').className=o?'ok':''}
const KL={image:'صورة',audio:'رسالة صوتية',video:'فيديو'};
const prev=m=>{if(m.lt){const b=m.lk&&m.lk!=='text'?(KL[m.lk]||'ملف'):(m.lb||'');return(m.lf===me.id?'أنت: ':'')+b}return m.note||m.bio||'@'+m.username};
const bub=m=>{const d=el('div','m'+(m.from_id===me.id?' me':'')),u='/api/file/'+m.file_id;let c;
  if(m.kind==='image'){c=el('a');c.href=u;c.target='_blank';c.rel='noopener';const i=el('img','pic');i.src=u;i.alt='صورة';i.onload=bot;c.append(i)}
  else if(m.kind==='audio'){c=el('audio');c.controls=true;c.preload='none';c.src=u}
  else if(m.kind==='video'){c=el('video','vid');c.controls=true;c.preload='metadata';c.playsInline=true;c.src=u}
  else c=el('span','',m.body);
  const t=el('small','t',tm(m.created_at));d.dataset.id=m.id;
  if(m.from_id===me.id){const x=el('button','del','حذف');x.type='button';x.onclick=safe(async()=>{if(!confirm('حذف الرسالة عند الطرفين؟'))return;await api('/msg/'+m.id,'DELETE')});t.append(x)}
  if(m.from_id===me.id)t.append(el('span','rd',m.seen?' ✓✓':' ✓'));
  d.append(c,t);return d};
function list(){const q=$('#q').value.trim().toLowerCase(),n=Object.values(unread).reduce((a,b)=>a+b,0);
  document.title=(n?'('+n+') ':'')+'أربكس الدردشة';
  $('#onc').textContent='نشط الآن: '+members.filter(m=>on.has(m.id)).length;stat();
  $('#list').replaceChildren(...members.filter(m=>(m.name+' '+m.username+' '+m.bio).toLowerCase().includes(q)).sort((a,b)=>(+new Date(b.lt||0))-(+new Date(a.lt||0))||on.has(b.id)-on.has(a.id)).map(m=>{
    const d=el('div','mem'+(m.id===cur?' act':'')),w=el('span','avw'),t=el('span','mt');
    w.append(av(m,46));if(on.has(m.id))w.append(el('i','dot on'));
    t.append(el('b','',m.name),el('small','',prev(m)));d.append(w,t);
    if(unread[m.id])d.append(el('span','bdg',unread[m.id]));d.onclick=()=>open(m.id);return d}))}
async function open(id){cur=id;unread[id]=0;document.body.classList.add('chatting');$('#cbox').hidden=false;$('#hint').hidden=true;$('#typing').hidden=true;
  const m=members.find(x=>x.id===id);$('#cname').textContent=nameOf(id);$('#cav').replaceChildren(m?av(m,40):'');list();
  try{const rows=await api('/chat/'+id);if(cur!==id)return;$('#msgs').replaceChildren(...rows.map(bub));$('#older').hidden=rows.length<100;bot()}catch(x){alert(x.message)}}
$('#older').onclick=safe(async()=>{const f=$('#msgs').firstElementChild;if(!f||!cur)return;const id=cur,rows=await api('/chat/'+id+'?before='+f.dataset.id);if(cur!==id)return;
  const box=$('#msgs'),h=box.scrollHeight;box.prepend(...rows.map(bub));box.scrollTop+=box.scrollHeight-h;$('#older').hidden=rows.length<100});
$('#q').oninput=list;
$('#back').onclick=()=>document.body.classList.remove('chatting');
$('#send').onsubmit=e=>{e.preventDefault();const v=$('#txt').value.trim();if(!v||!cur)return;
  sock.emit('msg',{to:cur,body:v},r=>{if(r&&r.error)alert(r.error)});$('#txt').value=''};
$('#txt').oninput=()=>{const n=Date.now();if(cur&&sock&&n-lastT>2000){lastT=n;sock.emit('typing',{to:cur})}};
$('#rep').onclick=async()=>{const r=prompt('سبب الإبلاغ؟');if(r===null)return;try{await api('/report','POST',{id:cur,reason:r});alert('تم الإبلاغ')}catch(x){alert(x.message)}};
$('#blk').onclick=async()=>{if(!confirm('حظر '+nameOf(cur)+'؟'))return;try{await api('/block','POST',{id:cur});
  members=members.filter(m=>m.id!==cur);cur=0;$('#cbox').hidden=true;$('#hint').hidden=false;document.body.classList.remove('chatting');list()}catch(x){alert(x.message)}};

/* مرفقات: صور وفيديو وتسجيل صوتي */
async function up(blob,mime,to){
  const r=await fetch('/api/upload/'+to,{method:'POST',headers:{'Content-Type':mime},body:blob});
  const d=await r.json().catch(()=>({}));
  if(!r.ok)throw new Error(d.error||(r.status===413?'الملف كبير':'فشل الإرسال'))}
const shrink=(f,max,sq)=>new Promise((ok,no)=>{const u=URL.createObjectURL(f),i=new Image();
  i.onload=()=>{const c=document.createElement('canvas'),x=c.getContext('2d');
    if(sq){const s=Math.min(i.width,i.height);c.width=c.height=sq;x.drawImage(i,(i.width-s)/2,(i.height-s)/2,s,s,0,0,sq,sq)}
    else{const k=Math.min(1,max/Math.max(i.width,i.height));c.width=Math.round(i.width*k);c.height=Math.round(i.height*k);x.drawImage(i,0,0,c.width,c.height)}
    URL.revokeObjectURL(u);c.toBlob(b=>b?ok(b):no(new Error('صورة غير صالحة')),'image/jpeg',.82)};
  i.onerror=()=>{URL.revokeObjectURL(u);no(new Error('صورة غير صالحة'))};i.src=u});
$('#file').onchange=safe(async()=>{const f=$('#file').files[0],to=cur;$('#file').value='';if(!f||!to)return;
  if(f.type.startsWith('image/'))await up(await shrink(f,1280),'image/jpeg',to);
  else if(f.type.startsWith('video/')){if(f.size>8e6)throw new Error('الفيديو كبير، الحد الأقصى 8 ميغا');await up(f,f.type,to)}
  else throw new Error('نوع الملف غير مدعوم')});
$('#rec').onclick=safe(async()=>{
  if(rc){rc.stop();return}
  if(!cur||!window.MediaRecorder)throw new Error('التسجيل مو مدعوم بهالمتصفح');
  const to=cur,st=await navigator.mediaDevices.getUserMedia({audio:true}).catch(()=>{throw new Error('ما قدرت أوصل للمايك')});
  const mt=['audio/webm;codecs=opus','audio/webm','audio/mp4','audio/ogg'].find(t=>MediaRecorder.isTypeSupported(t))||'';
  rch=[];const my=rc=new MediaRecorder(st,mt?{mimeType:mt}:{});
  my.ondataavailable=e=>{if(e.data.size)rch.push(e.data)};
  my.onstop=async()=>{st.getTracks().forEach(t=>t.stop());const b=new Blob(rch,{type:(my.mimeType||'audio/webm').split(';')[0]});
    rc=null;$('#rec').textContent='تسجيل';$('#rec').classList.remove('on');
    try{if(b.size>5e6)throw new Error('التسجيل طويل');if(b.size>0)await up(b,b.type,to)}catch(x){alert(x.message)}};
  my.start();$('#rec').textContent='إيقاف وإرسال';$('#rec').classList.add('on');
  setTimeout(()=>{if(rc===my&&my.state==='recording')my.stop()},12e4)});

/* مكالمات */
const flush=()=>qc.splice(0).forEach(c=>pc.addIceCandidate(c).catch(()=>{}));
async function mk(){const s=(await api('/ice')).servers;pc=new RTCPeerConnection({iceServers:s});
  ls.getTracks().forEach(t=>pc.addTrack(t,ls));pc.ontrack=e=>{$('#rv').srcObject=e.streams[0]};
  pc.onicecandidate=e=>{if(e.candidate)sock.emit('call:ice',{to:peer,c:e.candidate})};
  pc.onconnectionstatechange=()=>{if(['failed','closed'].includes(pc.connectionState))hang(false)}}
function show(v){$('#lv').srcObject=ls;$('#lv').hidden=!v;$('#call').hidden=false}
function hang(send){ringStop();if(send&&peer)sock.emit('call:end',{to:peer});if(pc){pc.onconnectionstatechange=null;pc.close()}pc=null;
  if(ls)ls.getTracks().forEach(t=>t.stop());ls=null;peer=0;qc.length=0;$('#call').hidden=true;$('#rv').srcObject=null}
async function dial(v){if(pc||pend||!cur)return;peer=cur;qc.length=0;
  try{ls=await navigator.mediaDevices.getUserMedia({audio:true,video:v})}catch(x){peer=0;return alert('ما قدرت أوصل للمايك أو الكاميرا')}
  try{await mk();await pc.setLocalDescription(await pc.createOffer())}catch(x){hang(false);return alert('صار خطأ بالاتصال')}
  sock.emit('call:offer',{to:peer,sdp:pc.localDescription,video:v},r=>{if(r&&r.error){alert(r.error);hang(false)}});show(v);ringStart(true);
  const my=pc;setTimeout(()=>{if(pc===my&&pc.connectionState!=='connected'){alert('ما رد');hang(true)}},30000)}
$('#vc').onclick=()=>dial(false);$('#vv').onclick=()=>dial(true);
$('#acc').onclick=async()=>{const o=pend;pend=null;$('#ring').close();peer=o.from;
  try{ls=await navigator.mediaDevices.getUserMedia({audio:true,video:o.video})}catch(x){sock.emit('call:reject',{to:peer});peer=0;return alert('ما قدرت أوصل للمايك أو الكاميرا')}
  try{await mk();await pc.setRemoteDescription(o.sdp);flush();await pc.setLocalDescription(await pc.createAnswer())}catch(x){sock.emit('call:reject',{to:peer});hang(false);return alert('صار خطأ بالاتصال')}
  sock.emit('call:answer',{to:peer,sdp:pc.localDescription});show(o.video)};
$('#rej').onclick=()=>$('#ring').close();
$('#ring').addEventListener('close',()=>{ringStop();if(pend){sock.emit('call:reject',{to:pend.from});pend=null}});
$('#end').onclick=()=>hang(true);
$('#mute').onclick=()=>ls&&ls.getAudioTracks().forEach(t=>t.enabled=!t.enabled);
$('#cam').onclick=()=>ls&&ls.getVideoTracks().forEach(t=>t.enabled=!t.enabled);
$('#xok').onclick=()=>$('#xf').close();

async function refresh(){try{members=await api('/members');unread={};(await api('/unread')).forEach(u=>unread[u.from_id]=u.c);list();
  if(cur){const id=cur;const rows=await api('/chat/'+id);if(cur===id){$('#msgs').replaceChildren(...rows.map(bub));$('#older').hidden=rows.length<100;bot();unread[id]=0;list()}}}catch(x){}}
function wire(){
  sock.on('connect',()=>{if(seen)refresh();seen=true});
  sock.on('connect_error',e=>{if(e&&e.message==='auth')location.reload()});
  sock.on('online',a=>{on=new Set(a);list()});
  sock.on('presence',p=>{p.on?on.add(p.id):on.delete(p.id);list()});
  sock.on('xfer',d=>{$('#xcode').textContent=d.code;if(!$('#xf').open)$('#xf').showModal()});
  sock.on('seen',d=>{if(d.by===cur)document.querySelectorAll('#msgs .rd').forEach(e=>{e.textContent=' ✓✓'})});
  sock.on('msg:del',d=>{const e=document.querySelector('#msgs [data-id="'+d.id+'"]');if(e)e.remove();
    api('/unread').then(a=>{unread={};a.forEach(u=>unread[u.from_id]=u.c);list()}).catch(()=>{})});
  sock.on('typing',d=>{if(d.from!==cur)return;$('#typing').hidden=false;clearTimeout(tTimer);tTimer=setTimeout(()=>{$('#typing').hidden=true},2500)});
  sock.on('msg',async m=>{const o=m.from_id===me.id?m.to_id:m.from_id,mine=m.from_id===me.id;
    if(!members.some(x=>x.id===o))members=await api('/members');
    const mm=members.find(x=>x.id===o);if(mm){mm.lb=m.body;mm.lk=m.kind;mm.lt=m.created_at;mm.lf=m.from_id}list();
    if(!mine&&(document.hidden||o!==cur))ding();
    if(o===cur){$('#msgs').append(bub(m));bot();if(!mine){$('#typing').hidden=true;api('/seen/'+o,'POST').catch(()=>{})}}
    else if(!mine){unread[o]=(unread[o]||0)+1;list()}});
  sock.on('call:offer',d=>{qc.length=0;pend=d;$('#rtext').textContent=nameOf(d.from)+(d.video?' يتصل فيديو':' يتصل صوت');$('#ring').showModal();ringStart(false)});
  sock.on('call:answer',async d=>{ringStop();if(pc){await pc.setRemoteDescription(d.sdp);flush()}});
  sock.on('call:ice',d=>{if(pc&&pc.remoteDescription)pc.addIceCandidate(d.c).catch(()=>{});else qc.push(d.c)});
  sock.on('call:end',()=>{if(pend){pend=null;$('#ring').close()}hang(false)});
  sock.on('call:reject',()=>{alert('المكالمة انرفضت');hang(false)});
  sock.on('disconnect',r=>{if(r==='io server disconnect'){if(!quiet)alert('تم إنهاء جلستك');location.reload()}})}

/* إشعارات الجهاز */
const b64=s=>{const p='='.repeat((4-s.length%4)%4),r=atob((s+p).replace(/-/g,'+').replace(/_/g,'/'));return Uint8Array.from(r,c=>c.charCodeAt(0))};
async function pushSub(ask){
  if(!('serviceWorker' in navigator)||!('PushManager' in window)||!('Notification' in window))return 'مو مدعوم بهالمتصفح (بالآيفون لازم تضيف الموقع للشاشة الرئيسية أول)';
  reg=reg||await navigator.serviceWorker.register('/sw.js');await navigator.serviceWorker.ready;
  if(Notification.permission==='default'&&ask)await Notification.requestPermission();
  if(Notification.permission==='denied')return 'الإشعارات محظورة، فعّلها من إعدادات المتصفح للموقع';
  if(Notification.permission!=='granted')return 'ما انفعلت';
  if(!vk)vk=(await api('/push/key')).key;if(!vk)return 'الإشعارات مو مفعّلة بالسيرفر';
  let s=await reg.pushManager.getSubscription();
  if(!s)s=await reg.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:b64(vk)});
  await api('/push/sub','POST',{sub:s.toJSON()});return 'إشعارات الجهاز شغّالة'}

/* الحالات */
async function loadSt(){const rows=await api('/statuses');
  $('#slist').replaceChildren(...(rows.length?rows.map(s=>{const d=el('div','sc s'+s.bg),f=el('div','sf');d.append(el('p','stx',s.text));
    f.append(av({id:s.id,name:s.name,av:s.av},26),el('span','',s.id===me.id?'حالتي':s.name),el('small','',ago(s.t)));d.append(f);return d}):[el('p','mut','ما في حالات هلأ. أضف حالتك!')]))}
function stSel(i){sbg=i;$('#stp').className='sc s'+i;document.querySelectorAll('#stsw button').forEach((b,k)=>b.classList.toggle('on',k===i))}
$('#stsw').replaceChildren(...[0,1,2,3,4,5,6,7].map(i=>{const b=el('button','sw s'+i);b.type='button';b.setAttribute('aria-label','لون '+(i+1));b.onclick=()=>stSel(i);return b}));
$('#stt').oninput=()=>{$('#stpt').textContent=$('#stt').value||'اكتب حالتك'};
$('#mys').onclick=()=>{$('#stt').value='';stSel(0);$('#stpt').textContent='اكتب حالتك';$('#stc').showModal()};
$('#stpub').onclick=safe(async()=>{const t=$('#stt').value.trim();if(!t)throw new Error('اكتب نص الحالة');await api('/status','POST',{text:t,bg:sbg});$('#stc').close();await loadSt()});
$('#stdel').onclick=safe(async()=>{await api('/status','DELETE');$('#stc').close();await loadSt()});
$('#stx').onclick=()=>$('#stc').close();
$('#tc').onclick=()=>{$('#pc').hidden=false;$('#ps').hidden=true;$('#tc').classList.add('on');$('#tst').classList.remove('on')};
$('#tst').onclick=()=>{$('#pc').hidden=true;$('#ps').hidden=false;$('#tst').classList.add('on');$('#tc').classList.remove('on');safe(loadSt)()};

/* الإعدادات */
const meav=()=>$('#meav').replaceChildren(av(me,34));
const stav=()=>$('#stav').replaceChildren(av(me,64));
function openSt(){$('#sn').value=me.name;$('#sb').value=me.bio;$('#sno').value=me.note||'';$('#th').value=pr.th||'';$('#fc').value=pr.fc||'#f6f1ff';
  $('#fs').value=pr.fs||'16';$('#bgs').value=pr.bg||'0';$('#snd').checked=pr.snd!==false;$('#pmsg').textContent='';$('#pwbox').hidden=!!me.g;stav();loadBl();$('#st').showModal()}
$('#gear').onclick=openSt;$('#me').onclick=openSt;$('#stclose').onclick=()=>$('#st').close();
$('#ssave').onclick=safe(async()=>{await api('/me','PUT',{name:$('#sn').value,bio:$('#sb').value,note:$('#sno').value});
  me.name=$('#sn').value.trim();me.bio=$('#sb').value.trim();me.note=$('#sno').value.trim();$('#myname').textContent=me.name;meav();stav();alert('تم الحفظ')});
$('#avf').onchange=safe(async()=>{const f=$('#avf').files[0];$('#avf').value='';if(!f)return;const b=await shrink(f,0,256);
  const r=await fetch('/api/avatar',{method:'POST',headers:{'Content-Type':'image/jpeg'},body:b}),d=await r.json().catch(()=>({}));
  if(!r.ok)throw new Error(d.error||'فشل رفع الصورة');me.av=d.v;stav();meav()});
$('#avd').onclick=safe(async()=>{await api('/avatar','DELETE');me.av=0;stav();meav()});
$('#th').onchange=()=>{pr.th=$('#th').value;savePr()};
$('#fc').oninput=()=>{pr.fc=$('#fc').value;savePr()};
$('#fcr').onclick=()=>{delete pr.fc;$('#fc').value='#f6f1ff';savePr()};
$('#fs').onchange=()=>{pr.fs=$('#fs').value;savePr()};
$('#bgs').onchange=()=>{pr.bg=$('#bgs').value;savePr()};
$('#snd').onchange=()=>{pr.snd=$('#snd').checked;savePr();if(pr.snd)ding()};
$('#pn').onclick=safe(async()=>{$('#pmsg').textContent=await pushSub(true)});
$('#pch').onclick=safe(async()=>{quiet=true;try{await api('/password','PUT',{old:$('#op').value,pass:$('#np').value})}catch(x){quiet=false;throw x}
  $('#op').value=$('#np').value='';alert('تم تغيير كلمة السر');location.reload()});
$('#out').onclick=async()=>{quiet=true;try{await api('/logout','POST')}catch(x){}location.reload()};
$('#del').onclick=safe(async()=>{if(!confirm('حذف حسابك نهائياً مع كل رسائلك وملفاتك؟ ما في رجعة.'))return;
  const p=prompt(me.g?'اكتب اسم المستخدم لتأكيد الحذف':'اكتب كلمة السر لتأكيد الحذف');if(!p)return;quiet=true;try{await api('/me','DELETE',{pass:p})}catch(x){quiet=false;throw x}alert('تم حذف حسابك');location.reload()});
async function loadBl(){try{const rows=await api('/blocked');$('#bl').replaceChildren(...(rows.length?rows.map(b=>{const d=el('div','row'),x=el('button','alt','فك الحظر');d.append(el('span','',b.name),x);
  x.onclick=safe(async()=>{await api('/block/'+b.id,'DELETE');members=await api('/members');list();await loadBl()});return d}):[el('p','mut','ما حظرت أحد')]))}catch(x){}}

async function enter(){me=await api('/me');members=await api('/members');
  (await api('/unread')).forEach(u=>unread[u.from_id]=u.c);
  $('#land').hidden=true;$('#app').hidden=false;document.body.classList.add('in');$('#myname').textContent=me.name;meav();list();
  if(!sock){sock=io();wire()}pushSub(false).catch(()=>{})}

/* تسجيل ودخول */
function tab(w){$('#lg').hidden=w!=='l';$('#su').hidden=w!=='s';$('#cd').hidden=true;$('#rc').hidden=true;$('#gu').hidden=true;$('#sp').hidden=true;$('#spt').hidden=true;$('#tabs').hidden=false;
  $('#tl').classList.toggle('on',w==='l');$('#ts').classList.toggle('on',w==='s')}
$('#tl').onclick=()=>tab('l');$('#ts').onclick=()=>tab('s');
let ut=0;$('#suu').oninput=()=>{clearTimeout(ut);const v=$('#suu').value.trim(),m=$('#unmsg');m.className='';if(!v){m.textContent='';return}
  ut=setTimeout(async()=>{try{const d=await api('/username?u='+encodeURIComponent(v));if($('#suu').value.trim()!==v)return;m.textContent=d.msg;m.className=d.ok?'good':'bad'}catch(x){m.textContent=x.message}},400)};
$('#su').onsubmit=async e=>{e.preventDefault();const f=e.target;
  if(f.pass.value!==f.pass2.value){$('#sumsg').textContent='كلمتا السر مو متطابقتين';return}
  try{await api('/signup','POST',{username:f.username.value.trim(),pass:f.pass.value,adult:f.adult.checked});await enter()}catch(x){$('#sumsg').textContent=x.message}};
$('#lg').onsubmit=async e=>{e.preventDefault();
  try{const f=Object.fromEntries(new FormData(e.target)),d=await api('/login','POST',f);
    if(d.needCode){cred=f;$('#lg').hidden=true;$('#tabs').hidden=true;$('#cd').hidden=false;return}
    await enter()}catch(x){$('#lgmsg').textContent=x.message}};
$('#cd').onsubmit=async e=>{e.preventDefault();
  try{await api('/login/code','POST',{username:cred.username,pass:cred.pass,code:e.target.code.value.trim()});await enter()}catch(x){$('#cdmsg').textContent=x.message}};
$('#cdx').onclick=()=>location.reload();
$('#fg').onclick=async()=>{try{const d=await api('/recover/list');
  if(!d.names.length){$('#lgmsg').textContent=d.locked?'سجّلت خروج من هالجهاز، فعشان أمان حسابك استعادة كلمة السر لازم تكون من الإدارة. اضغط «تواصل مع الإدارة»':'ما في حساب مسجّل على هالجهاز. اضغط «تواصل مع الإدارة»';return}
  $('#rcsel').replaceChildren(...d.names.map(n=>{const o=el('option','',n);o.value=n;return o}));$('#lg').hidden=true;$('#tabs').hidden=true;$('#rc').hidden=false}
  catch(x){$('#lgmsg').textContent=x.message}};
$('#rcx').onclick=()=>tab('l');
$('#rc').onsubmit=async e=>{e.preventDefault();const f=e.target;
  if(f.pass.value!==f.pass2.value){$('#rcmsg').textContent='كلمتا السر مو متطابقتين';return}
  try{await api('/recover','POST',{username:f.username.value,pass:f.pass.value});await enter()}catch(x){$('#rcmsg').textContent=x.message}};
api('/me').then(enter).catch(()=>{});

/* المتابعة بحساب جوجل */
let gtk='';
async function gcb(resp){try{const d=await api('/google','POST',{credential:resp.credential});
  if(d.needUsername){gtk=d.ticket;$('#lg').hidden=true;$('#su').hidden=true;$('#tabs').hidden=true;$('#gu').hidden=false;return}
  await enter()}catch(x){alert(x.message)}}
(async()=>{try{const c=await api('/config');if(!c.google)return;
  await new Promise((ok,no)=>{const s=document.createElement('script');s.src='https://accounts.google.com/gsi/client';s.async=true;s.onload=ok;s.onerror=no;document.head.append(s)});
  google.accounts.id.initialize({client_id:c.google,callback:gcb,ux_mode:'popup'});
  google.accounts.id.renderButton($('#gbtn'),{theme:'filled_black',size:'large',text:'continue_with',shape:'pill',locale:'ar',width:300});
  $('#gwrap').hidden=false;$('#ts').hidden=true}catch(x){}})();
let gt=0;$('#guu').oninput=()=>{clearTimeout(gt);const v=$('#guu').value.trim(),m=$('#gunmsg');m.className='';if(!v){m.textContent='';return}
  gt=setTimeout(async()=>{try{const d=await api('/username?u='+encodeURIComponent(v));if($('#guu').value.trim()!==v)return;m.textContent=d.msg;m.className=d.ok?'good':'bad'}catch(x){m.textContent=x.message}},400)};
$('#gu').onsubmit=async e=>{e.preventDefault();const f=e.target;
  try{await api('/google/username','POST',{ticket:gtk,username:f.username.value.trim(),adult:f.adult.checked});await enter()}catch(x){$('#gumsg').textContent=x.message}};
$('#gux').onclick=()=>location.reload();

/* طلبات الدعم */
let sk='';try{sk=localStorage.getItem('tk')||''}catch(e){}
const saveTk=c=>{sk=c;try{if(c)localStorage.setItem('tk',c);else localStorage.removeItem('tk')}catch(e){}};
function spShow(w){['#lg','#su','#cd','#rc','#gu','#sp','#spt'].forEach(x=>$(x).hidden=true);$('#tabs').hidden=true;$(w).hidden=false}
async function loadTk(){try{const d=await api('/support/'+sk);$('#spc').textContent=sk;
  $('#sps').textContent=d.status==='closed'?'الطلب مسكّر':'الطلب مفتوح. ارجع وحدّث لتشوف رد الإدارة';
  $('#spm').replaceChildren(...d.msgs.map(m=>{const e=el('div','sm'+(m.from_admin?' adm':''),m.body);e.append(el('small','',(m.from_admin?'الإدارة':'أنت')+' - '+tm(m.created_at)));return e}));
  $('#sprb').disabled=d.status==='closed';$('#sptm').textContent=''}
  catch(x){saveTk('');spShow('#sp');$('#spmsg').textContent=x.message}}
$('#hp').onclick=()=>{if(sk){spShow('#spt');loadTk()}else spShow('#sp')};
$('#spx').onclick=()=>tab('l');$('#sptx').onclick=()=>tab('l');
$('#spn').onclick=()=>{saveTk('');spShow('#sp')};
$('#spo').onclick=()=>{const c=(prompt('اكتب كود الطلب')||'').trim().toUpperCase();if(!c)return;saveTk(c);spShow('#spt');loadTk()};
$('#sp').onsubmit=async e=>{e.preventDefault();const f=e.target;
  try{const d=await api('/support','POST',{username:f.username.value.trim(),message:f.message.value});saveTk(d.code);f.message.value='';spShow('#spt');await loadTk()}catch(x){$('#spmsg').textContent=x.message}};
$('#sprb').onclick=async()=>{const v=$('#spr').value.trim();if(!v)return;try{await api('/support/'+sk+'/reply','POST',{body:v});$('#spr').value='';await loadTk()}catch(x){$('#sptm').textContent=x.message}};
$('#spre').onclick=loadTk;

const row=(c,act,h)=>{const tr=el('tr');c.forEach(x=>tr.append(el(h?'th':'td','',x)));if(act)tr.append(act);return tr};
async function adm(){const d=await api('/admin/data');$('#cnt').textContent='('+d.accounts.length+' من '+d.max+' - أونلاين: '+d.online+' - ملفات: '+d.mb+' ميغا)';
  const rp=$('#reps');rp.replaceChildren(row(['من','على','السبب',''],null,true));
  d.reports.forEach(x=>{const t=el('td'),b=el('button','',x.banned?'محظور':'حظر'),k=el('button','','حذف');
    b.onclick=safe(async()=>{await api('/admin/ban/'+x.to_id,'POST',{on:true});await adm()});
    k.onclick=safe(async()=>{await api('/admin/reports/'+x.id,'DELETE');await adm()});t.append(b,k);
    if(x.ev){const v=el('button','','الأدلة');v.onclick=safe(()=>showEv(x.id));t.append(v)}
    rp.append(row([x.fname,x.tname,x.reason||'-'],t))});
  const ac2=$('#accs');ac2.replaceChildren(row(['المستخدم','الاسم','الحالة',''],null,true));
  d.accounts.forEach(x=>{const t=el('td'),b=el('button','',x.banned?'فك الحظر':'حظر'),rs=el('button','','إعادة ضبط');
    b.onclick=safe(async()=>{await api('/admin/ban/'+x.id,'POST',{on:!x.banned});await adm()});
    rs.onclick=safe(async()=>{if(!confirm('إعادة ضبط '+x.username+'؟'))return;const r=await api('/admin/reset/'+x.id,'POST');alert(x.username+' : '+r.pass);await adm()});
    const dv2=el('button','',x.dban?'فك حظر الجهاز':'حظر الجهاز');
    dv2.onclick=safe(async()=>{if(!confirm((x.dban?'فك حظر':'حظر')+' جهاز '+x.username+'؟ بيشمل كل الحسابات على نفس الجهاز'))return;
      const r=await api('/admin/device/'+x.id,'POST',{on:!x.dban});alert('تم. عدد الحسابات على الجهاز: '+r.accounts);await adm()});
    t.append(b,rs,dv2);ac2.append(row([x.username,x.name,x.banned?(x.dban?'محظور (الجهاز)':'محظور'):(x.claimed_at?'مستخدم':'متاح')],t))});
  await loadTks()}
async function showEv(id){const d=await api('/admin/report/'+id),b=$('#evbox');b.replaceChildren(el('h3','','الأدلة'),el('pre','',d.evidence));
  for(const f of d.files||[]){const r=await fetch('/api/admin/file/'+f,{headers:{Authorization:'Bearer '+token}});
    if(!r.ok){b.append(el('p','mut','الملف '+f+' غير موجود (انحذف)'));continue}
    const bl=await r.blob(),u=URL.createObjectURL(bl),t=bl.type.split('/')[0],w=el('div'),m=t==='image'?el('img','pic'):t==='video'?el('video','vid'):el('audio');
    m.src=u;if(t!=='image')m.controls=true;const x=el('button','','حذف الملف');
    x.onclick=safe(async()=>{if(!confirm('حذف هالملف نهائياً؟'))return;await api('/admin/file/'+f,'DELETE');w.remove()});w.append(m,x);b.append(w)}
  const c=el('button','alt','إغلاق');c.onclick=()=>{b.hidden=true};b.append(c);b.hidden=false;b.scrollIntoView()}
async function loadTks(){const d=await api('/admin/tickets'),t=$('#tkt');
  $('#tcnt').textContent='('+d.filter(x=>x.waiting&&x.status==='open').length+' بانتظار ردك)';
  t.replaceChildren(row(['المستخدم','الجهاز','الحالة','آخر نشاط',''],null,true));
  d.forEach(x=>{const td=el('td'),b=el('button','','فتح');b.onclick=safe(()=>showTk(x.id));td.append(b);
    t.append(row([x.username||'-',x.acct_id?(x.dev_match?'نفس جهاز الحساب':'جهاز مختلف'):'-',x.status==='closed'?'مغلق':(x.waiting?'بانتظار ردك':'تم الرد'),ago(x.updated_at)],td))})}
async function showTk(id){const d=await api('/admin/ticket/'+id),b=$('#tkbox');
  b.replaceChildren(el('h3','','طلب من: '+(d.username||'بدون اسم')),
    el('p','hintp',d.acct_id?(d.dev_match?'الطلب جاء من نفس الجهاز المسجّل للحساب':'الطلب جاء من جهاز مختلف عن المسجّل للحساب (تأكد إنه صاحب الحساب)'):'الاسم مو موجود أو ما انكتب'));
  const box=el('div','spm');d.msgs.forEach(m=>{const e=el('div','sm'+(m.from_admin?' adm':''),m.body);e.append(el('small','',(m.from_admin?'الإدارة':'المستخدم')+' - '+ago(m.t)+' مضت'));box.append(e)});
  const ta=el('textarea');ta.rows=3;ta.maxLength=1000;ta.placeholder='اكتب الرد';
  const done=async()=>{await showTk(id);await loadTks()};
  const s1=el('button','','إرسال الرد'),s2=el('button','alt','إرسال وإغلاق'),cl=el('button','alt','إخفاء'),dl=el('button','alt','حذف الطلب');
  s1.onclick=safe(async()=>{if(!ta.value.trim())return;await api('/admin/ticket/'+id+'/reply','POST',{body:ta.value});await done()});
  s2.onclick=safe(async()=>{await api('/admin/ticket/'+id+'/reply','POST',{body:ta.value,close:true});await done()});
  dl.onclick=safe(async()=>{if(!confirm('حذف الطلب؟'))return;await api('/admin/ticket/'+id,'DELETE');b.hidden=true;await loadTks()});
  cl.onclick=()=>{b.hidden=true};
  b.append(box,ta,s1,s2);
  if(d.acct_id){const rs=el('button','alt','إعادة ضبط الحساب');
    rs.onclick=safe(async()=>{if(!confirm('إعادة ضبط حساب '+d.username+'؟ بتتغير كلمة سره وبيطلع من كل الأجهزة'))return;
      const r=await api('/admin/reset/'+d.acct_id,'POST');ta.value='تم إعادة ضبط حسابك. كلمة السر المؤقتة: '+r.pass+' - ادخل فيها وغيّرها من الإعدادات.'});b.append(rs)}
  b.append(dl,cl);b.hidden=false;b.scrollIntoView()}
let clicks=0,timer;
$('#dot').addEventListener('click',()=>{clearTimeout(timer);timer=setTimeout(()=>clicks=0,3000);if(++clicks>=10){clicks=0;$('#admin').showModal()}});
$('#alogin').addEventListener('submit',async e=>{e.preventDefault();
  try{token=(await api('/admin/login','POST',{password:$('#pw').value})).token;$('#pw').value='';$('#alogin').hidden=true;$('#panel').hidden=false;await adm()}
  catch(x){$('#amsg').textContent=x.message}});`;

app.get('/', (_q, r) => r.type('html').send(HTML));
app.get('/style.css', (_q, r) => r.type('css').send(CSS));
app.get('/app.js', (_q, r) => r.type('js').send(JS));
app.get('/sw.js', (_q, r) => r.type('js').set('Cache-Control', 'no-cache').send(SW));
app.get('/manifest.json', (_q, r) => r.type('application/manifest+json').send(MANIFEST));
app.get('/logo.svg', (_q, r) => r.type('image/svg+xml').set('Cache-Control', 'public, max-age=86400').send(LOGO));

/* ---------- ملفات جوجل: التحقق + robots + sitemap (إضافة) ---------- */
const SITE = 'https://bdllh-nqws-1.onrender.com';
app.get('/google420c58aff5210570.html', (_q, r) => r.type('html').send('google-site-verification: google420c58aff5210570.html'));
app.get('/robots.txt', (_q, r) => r.type('text/plain').send('User-agent: *\nAllow: /\nDisallow: /api/\n\nSitemap: ' + SITE + '/sitemap.xml\n'));
app.get('/sitemap.xml', (_q, r) => r.type('application/xml').send(
  '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n  <url><loc>' + SITE + '/</loc><changefreq>weekly</changefreq><priority>1.0</priority></url>\n</urlset>\n'));

app.use((e, _q, r, _n) => {
  console.error(e); const s = e.status >= 400 && e.status < 500 ? e.status : 500;
  if (!r.headersSent) r.status(s).json({ error: s === 413 ? 'الملف كبير' : s === 500 ? 'خطأ في الخادم' : 'طلب غير صالح' });
});

init()
  .then(() => server.listen(process.env.PORT || 3000, () => console.log('أربكس الدردشة شغّال')))
  .catch(e => { console.error('فشل التشغيل:', e.message); process.exit(1); });
