// pwa-extra.js: أيقونات PNG + manifest + assetlinks لتحويل الموقع إلى تطبيق APK
const zlib = require('zlib');
const CRCT = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
const crc32 = b => { let c = -1; for (const x of b) c = CRCT[(c ^ x) & 255] ^ (c >>> 8); return (c ^ -1) >>> 0; };
const chunk = (t, d) => { const h = Buffer.alloc(4), f = Buffer.alloc(4), td = Buffer.concat([Buffer.from(t), d]);
  h.writeUInt32BE(d.length); f.writeUInt32BE(crc32(td)); return Buffer.concat([h, td, f]); };
const mix = (a, b, t) => a.map((v, i) => Math.round(v + (b[i] - v) * t));
const makeIcon = n => {
  const w = n * 4 + 1, raw = Buffer.alloc(w * n), C = [25, 227, 255], M = [255, 46, 136], G = [255, 200, 61];
  for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) {
    const d = Math.hypot(x + .5 - n / 2, y + .5 - n / 2) / (n / 2), t = (x + y) / (2 * n);
    let px = [7, 5, 15];
    if (d > .5 && d < .62) px = t < .5 ? mix(C, M, t * 2) : mix(M, G, (t - .5) * 2);
    else if (Math.abs(x + .5 - n / 2) < n * .035 && Math.abs(y + .5 - n / 2) < n * .13) px = G;
    raw.set([...px, 255], y * w + 1 + x * 4);
  }
  const ih = Buffer.alloc(13); ih.writeUInt32BE(n, 0); ih.writeUInt32BE(n, 4); ih[8] = 8; ih[9] = 6;
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ih), chunk('IDAT', zlib.deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]);
};
const MANIFEST = JSON.stringify({ name: 'أربكس الدردشة', short_name: 'أربكس', id: '/', start_url: '/', scope: '/', display: 'standalone',
  dir: 'rtl', lang: 'ar', background_color: '#07050f', theme_color: '#07050f',
  icons: [{ src: '/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any' },
    { src: '/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any' },
    { src: '/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' }] });
module.exports = app => {
  const icons = { 192: makeIcon(192), 512: makeIcon(512) };
  for (const s of [192, 512]) app.get('/icon-' + s + '.png', (_q, r) => r.type('png').set('Cache-Control', 'public, max-age=86400').send(icons[s]));
  app.get('/manifest.json', (_q, r) => r.type('application/manifest+json').send(MANIFEST));
  app.get('/.well-known/assetlinks.json', (_q, r) => r.type('application/json').send(process.env.ASSETLINKS || '[]'));
};
