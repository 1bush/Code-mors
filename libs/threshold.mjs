/**
 * threshold.mjs — Shamir Secret Sharing mbi GF(256) + RBSR
 * (Ratchet-Bound Share Rotation).
 *
 * PERDORIMI: ndarja e nje sekreti (p.sh. nje çelës sesioni) ne pjese, ku asnje
 * pjese e vetme nuk jep informacion dhe bashkimi kerkon prag-un (t). Kjo eshte
 * alternativa e sakte ndaj idese "3 çelësa ne server": serveri mbart SHARE
 * (te padobishme vetjake), jo çelësa te plote.
 *
 * RBSR (shtese e re, e paperdorur nga Signal/SimpleX/PQ3 sa dime ne):
 *   y'_i = y_i XOR mask(ratchetKey, epoch)
 * ku mask-i nxirret nga gjendja e ratchet-ut. Konsekuenca:
 *   - te dyja anet e aplikojne mask-in lokalisht (s'ka komunikim shtese);
 *   - nje share i vjedhur ne epoken k nuk ndihmon ne epoken k+1 pa mask-in
 *     e ri, i cili vjen vetem nga ratchet-i (forward secrecy);
 *   - perzjerja e share-ve te epokave te ndryshme nuk rinderton asgje te dobishme.
 *
 * KUFRZIM I SINQERTE: pa auditim kriptografik te pavarur; GF(256) + Shamir
 * klasik eshte i provuar, por RBSR-ja si konstruksion i re kerkon analize
 * formale para perdorimit ne prodhim. Nuk zevendeson TLS-kanalin e transportit.
 */

const REDUCE = 0x1b; // x^8+x^4+x^3+x+1 pa bitin e larte (polinomi i AES-it)

/** Shumezim ne GF(256). */
export function gmul(a, b) {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= REDUCE;
    b >>= 1;
  }
  return p & 0xff;
}

/** Invers multiplikativ ne GF(256) (a^254 per a != 0). */
export function ginv(a) {
  if (a === 0) throw new Error('ginv(0) e papercaktuar');
  let r = 1, base = a, e = 254;
  while (e) {
    if (e & 1) r = gmul(r, base);
    base = gmul(base, base);
    e >>= 1;
  }
  return r;
}

const evalPoly = (coeffs, x) => {
  let acc = 0;
  for (let i = coeffs.length - 1; i >= 0; i--) acc = gmul(acc, x) ^ coeffs[i];
  return acc;
};

/**
 * Ndan `secret` ne `n` share me prag `t` (nevojiten t per rikonstruksion).
 * @returns {{x:number, y:Uint8Array}[]}
 */
export function split(secret, n, t, rand = (len) => globalThis.crypto.getRandomValues(new Uint8Array(len))) {
  if (!(secret instanceof Uint8Array) || !secret.length) throw new Error('sekret i pavlefshem');
  if (t < 1 || n < t || n > 255) throw new Error('prag/ numer i pavlefshem (1<=t<=n<=255)');
  const shares = [];
  for (let i = 0; i < n; i++) shares.push({ x: i + 1, y: new Uint8Array(secret.length) });
  for (let j = 0; j < secret.length; j++) {
    const coeffs = new Uint8Array(t);
    coeffs[0] = secret[j];
    if (t > 1) {
      const r = rand(t - 1);
      for (let k = 1; k < t; k++) coeffs[k] = r[k - 1];
    }
    for (let i = 0; i < n; i++) shares[i].y[j] = evalPoly(coeffs, shares[i].x);
  }
  return shares;
}

/** Rinderton sekretin nga saktësisht t (ose me shume) share. */
export function combine(shares) {
  if (!Array.isArray(shares) || shares.length < 2) throw new Error('duhen te pakten 2 share');
  for (const s of shares) if (!s || typeof s.x !== 'number' || !(s.y instanceof Uint8Array)) throw new Error('share i pavlefshem');
  const len = shares[0].y.length;
  if (shares.some((s) => s.y.length !== len)) throw new Error('gjatesi te ndryshme');
  if (new Set(shares.map((s) => s.x)).size !== shares.length) throw new Error('x te perseritur');
  const out = new Uint8Array(len);
  for (let i = 0; i < shares.length; i++) {
    let num = 1, den = 1;
    for (let j = 0; j < shares.length; j++) {
      if (i === j) continue;
      num = gmul(num, shares[j].x);            // (0 - x_j) = x_j ne GF(2^n)
      den = gmul(den, shares[i].x ^ shares[j].x);
    }
    const li = gmul(num, ginv(den));
    for (let k = 0; k < len; k++) out[k] ^= gmul(shares[i].y[k], li);
  }
  return out;
}

/** Mask-i determinist i epokes, i nxjerre nga gjendja e ratchet-ut. */
export async function epochMask(ratchetKey, epoch, len = 32) {
  if (!(ratchetKey instanceof Uint8Array) || !ratchetKey.length) throw new Error('ratchetKey i pavlefshem');
  const ikm = await globalThis.crypto.subtle.importKey('raw', ratchetKey, 'HKDF', false, ['deriveBits']);
  const info = new TextEncoder().encode('CM-RBSR-v1|epoch=' + Number(epoch) + '|len=' + len);
  const bits = await globalThis.crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info }, ikm, len * 8);
  return new Uint8Array(bits);
}

/**
 * RBSR: rotacion i share-ve i lidhur me ratchet-in. Te dyja anet e nxjerrin
 * te njejtin mask nga ratchetKey+epoch, pa komunikim shtese.
 */
export async function rotateShares(shares, ratchetKey, epoch) {
  const len = shares[0].y.length;
  const mask = await epochMask(ratchetKey, epoch, len);
  const out = shares.map((s) => ({ x: s.x, y: new Uint8Array(s.y) }));
  for (const s of out) for (let k = 0; k < len; k++) s.y[k] ^= mask[k];
  return out;
}

/* ---- transporti (QR/link) ---- */
export const sharesToB64 = (shares) =>
  shares.map((s) => s.x.toString(36) + '.' + btoa(String.fromCharCode(...s.y))).join('~');

export const sharesFromB64 = (str) =>
  str.split('~').map((part) => {
    const [x, b64] = part.split('.');
    const bin = atob(b64);
    const y = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) y[i] = bin.charCodeAt(i);
    return { x: parseInt(x, 36), y };
  });