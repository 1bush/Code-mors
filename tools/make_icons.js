// Gjeneron ikonat PNG të CODE MORS (PWA Android/iOS) — pa dependenca.
// Dizajni: sfond i zi-ushtarak, kornizë e gjelbër, simboli "M" morse + pika.
'use strict';
const fs = require('fs'), path = require('path'), zlib = require('zlib');

const CRC_T = (() => { const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) { let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0; } return t; })();
const crc32 = b => { let c = 0xffffffff;
  for (const x of b) c = CRC_T[(c ^ x) & 255] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0; };
const chunk = (type, data) => {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]); };

function render(size) {
  const px = Buffer.alloc(size * size * 4);
  const BG = [2, 6, 4], GRN = [61, 255, 136], DIM = [20, 60, 38];
  const set = (x, y, c) => { if (x < 0 || y < 0 || x >= size || y >= size) return;
    const i = (y * size + x) * 4; px[i] = c[0]; px[i + 1] = c[1]; px[i + 2] = c[2]; px[i + 3] = 255; };
  const rect = (x0, y0, w, h, c) => { for (let y = y0; y < y0 + h; y++) for (let x = x0; x < x0 + w; x++) set(x, y, c); };
  const u = size / 100; // njësi
  // sfond
  for (let i = 0; i < size * size; i++) { px[i * 4] = BG[0]; px[i * 4 + 1] = BG[1]; px[i * 4 + 2] = BG[2]; px[i * 4 + 3] = 255; }
  // kornizë e jashtme (safe për maskable: margin 12%)
  const m = Math.round(u * 9);
  const t = Math.max(2, Math.round(u * 2.2));
  rect(m, m, size - 2 * m, t, GRN); rect(m, size - m - t, size - 2 * m, t, GRN);
  rect(m, m, t, size - 2 * m, GRN); rect(size - m - t, m, t, size - 2 * m, GRN);
  // korniza e brendshme e hollë
  const m2 = Math.round(u * 13), t2 = Math.max(1, Math.round(u * 0.9));
  rect(m2, m2, size - 2 * m2, t2, DIM); rect(m2, size - m2 - t2, size - 2 * m2, t2, DIM);
  rect(m2, m2, t2, size - 2 * m2, DIM); rect(size - m2 - t2, m2, t2, size - 2 * m2, DIM);
  // simboli M (bosht i trashë) — zona qendër 20..80
  const s = u;
  const x0 = Math.round(u * 20), x1 = Math.round(u * 50), x2 = Math.round(u * 80);
  const y0 = Math.round(u * 27), y1 = Math.round(u * 73);
  const w = Math.max(4, Math.round(u * 8.5));
  // këmbët e M
  rect(x0, y0, w, y1 - y0, GRN); rect(x2 - w, y0, w, y1 - y0, GRN);
  // maje e M (dy diagonalë si shkallë)
  for (let i = 0; i <= 10; i++) {
    const t = i / 10;
    const xa = Math.round(x0 + (x1 - x0) * t) - w / 2;
    const xb = Math.round(x1 + (x2 - x1) * t) - w / 2;
    const yy = Math.round(y0 + (y1 - y0) * t * 0.55);
    rect(Math.round(xa), yy, w, Math.max(3, Math.round(u * 2.4)), GRN);
    rect(Math.round(xb), yy, w, Math.max(3, Math.round(u * 2.4)), GRN);
  }
  // pika morse nën M
  const dy = Math.round(u * 82), dr = Math.max(3, Math.round(u * 3.4));
  for (const fx of [0.5, 0.62, 0.74]) {
    const cx = Math.round(u * 100 * fx);
    for (let y = dy - dr; y <= dy + dr; y++) for (let x = cx - dr; x <= cx + dr; x++)
      if ((x - cx) ** 2 + (y - dy) ** 2 <= dr * dr) set(x, y, GRN);
  }
  // PNG encode
  const sig = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; ihdr[9] = 6; // 8-bit RGBA
  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0;
    px.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  }
  const idat = zlib.deflateSync(raw, { level: 9 });
  return Buffer.concat([sig, chunk('IHDR', ihdr), chunk('IDAT', idat), chunk('IEND', Buffer.alloc(0))]);
}

const out = path.join(__dirname, '..');
for (const [name, s] of [['icon-192.png', 192], ['icon-512.png', 512], ['apple-touch-icon.png', 180]]) {
  fs.writeFileSync(path.join(out, name), render(s));
  console.log('wrote', name, s + 'x' + s);
}
