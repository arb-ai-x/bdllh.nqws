const $ = s => document.querySelector(s);
const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
let token = '';

async function api(path, method = 'GET', body) {
  const r = await fetch('/api' + path, {
    method, headers: { 'Content-Type': 'application/json', ...(token && { Authorization: 'Bearer ' + token }) },
    body: body && JSON.stringify(body)
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || (r.status === 429 ? 'محاولات كثيرة، انتظر شوي' : 'صار خطأ'));
  return d;
}

async function load() {
  const [board, posts] = await Promise.all([api('/board'), api('/posts')]);
  $('#board').replaceChildren(...board.map(p => {
    const li = el('li'); const w = el('div', 'w');
    li.append(el('b', '', p.name), el('small', '', p.game), el('span', 'lv', 'LV ' + p.lv)); return li;
  }));
  if (!board.length) $('#board').append(el('li', '', 'ما في لاعبين بعد. كن أول واحد!'));
  $('#posts').replaceChildren(...posts.map(p => {
    const d = el('article', 'post ' + p.tpl); d.style.fontFamily = `'${p.font}', sans-serif`;
    d.append(el('h3', '', p.title), el('p', '', p.body), el('time', '', new Date(p.created_at).toLocaleDateString('ar')));
    return d;
  }));
}

$('#reg').addEventListener('submit', async e => {
  e.preventDefault();
  try {
    await api('/register', 'POST', Object.fromEntries(new FormData(e.target)));
    e.target.reset(); $('#msg').textContent = 'تم التسجيل. بالتوفيق!'; load();
  } catch (x) { $('#msg').textContent = x.message; }
});

let clicks = 0, timer;
$('#dot').addEventListener('click', () => {
  clearTimeout(timer); timer = setTimeout(() => clicks = 0, 3000);
  if (++clicks >= 10) { clicks = 0; $('#admin').showModal(); }
});

$('#login').addEventListener('submit', async e => {
  e.preventDefault();
  try {
    token = (await api('/admin/login', 'POST', { password: $('#pw').value })).token;
    $('#pw').value = ''; $('#login').hidden = true; $('#panel').hidden = false; players();
  } catch (x) { $('#lmsg').textContent = x.message; }
});

async function players() {
  const rows = await api('/admin/players');
  const t = $('#players'); t.replaceChildren();
  const h = el('tr'); ['الاسم', 'اللعبة', 'تواصل', 'LV', ''].forEach(x => h.append(el('th', '', x))); t.append(h);
  rows.forEach(p => {
    const tr = el('tr'), lv = el('input'); lv.type = 'number'; lv.min = 1; lv.max = 99; lv.value = p.lv;
    const save = el('button', '', 'حفظ'), del = el('button', '', 'حذف');
    save.onclick = async () => { await api('/admin/players/' + p.id, 'PATCH', { lv: lv.value }); load(); };
    del.onclick = async () => { if (confirm('حذف ' + p.name + '؟')) { await api('/admin/players/' + p.id, 'DELETE'); players(); load(); } };
    const act = el('td'); act.append(save, del); const l = el('td'); l.append(lv);
    tr.append(el('td', '', p.name), el('td', '', p.game), el('td', '', p.contact || '-'), l, act); t.append(tr);
  });
}

$('#newpost').addEventListener('submit', async e => {
  e.preventDefault();
  try { await api('/admin/posts', 'POST', Object.fromEntries(new FormData(e.target))); e.target.reset(); load(); }
  catch (x) { alert(x.message); }
});

load();
