/**
 * CODE MORS — cm-protocol.js v1 (CM-RR hybrid client crypto)
 * ------------------------------------------------------------------
 * Double Ratchet "dy-drejtimësh" + Ratchet-Bound Queue Rotation (RBQR)
 * mbi WebCrypto (ECDH P-256, HKDF-SHA256, HMAC-SHA256, AES-256-GCM).
 *
 * Arkitektura:
 *  - Një lidhje = DY drejtime të pavarura (A->B dhe B->A), si radhët
 *    njëdrejtimëshe të SMP. Secili drejtim ka veten RK + chain.
 *  - Çdo drejtim ka DH break-in recovery: kur dërguesi avançon çelësin e ri
 *    ephemeral (ECDH me çelësin afatgjatë të marrësit), RK + chain rillogët.
 *  - Çdo mesazh merr një key të freskët prej zinxhirit -> forward secrecy.
 *  - RBQR: token-i i radhës del prej RK-së së drejtimët -> token-i i vjetër
 *    bëhet i pavlefshëm sapo ratchet-i avançon (forward secrecy i metadata-s).
 *
 * Pa varësi të jashtme (Node 18+ / browser WebCrypto).
 */

'use strict';
const crypto = globalThis.crypto;
const subtle = crypto.subtle;

const b = {
  toHex: (u) => Buffer.from(u).toString('hex'),
  fromHex: (h) => Buffer.from(h, 'hex'),
  toB64: (u) => Buffer.from(u).toString('base64'),
  fromB64: (s) => Buffer.from(s, 'base64'),
};
const TE = new TextEncoder();
const TD = new TextDecoder();
const randBytes = (n) => { const a = new Uint8Array(n); crypto.getRandomValues(a); return a; };

/* ---------------- kripto bazë ---------------- */

async function generateKeyPair() {
  return subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
}
async function exportPub(kp) {
  const j = await subtle.exportKey('raw', kp.publicKey);
  return b.toB64(new Uint8Array(j));
}
async function importPub(b64) {
  return subtle.importKey('raw', new Uint8Array(b.fromB64(b64)), { name: 'ECDH', namedCurve: 'P-256' }, true, []);
}
async function ecdhDerive(priv, pub) {
  const bits = await subtle.deriveBits({ name: 'ECDH', public: pub }, priv, 256);
  return new Uint8Array(bits);
}
async function hmacSHA(key, data) {
  const k = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  return new Uint8Array(await subtle.sign('HMAC', k, data));
}
async function hkdf(ikm, salt, info, len) {
  const km = await subtle.importKey('raw', ikm, { name: 'HKDF' }, false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, km, len * 8));
}

/* ---------------- chain / AES ---------------- */
async function kdfChain(ck) {
  const mk = await hmacSHA(ck, new Uint8Array([0x01]));
  const next = await hmacSHA(ck, new Uint8Array([0x02]));
  return { mk, next };
}
async function aeadEncr(key, plain) {
  const iv = randBytes(12);
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, plain));
  return { iv, ct };
}
async function aeadDecr(key, iv, ct) {
  return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, ct));
}

/* ---- padding (Code-mors / SimpleX-style) ---- */
function pad(raw, block = 256) {
  const total = Math.max(block, Math.ceil((raw.length + 4) / block) * block);
  const out = new Uint8Array(total);
  new DataView(out.buffer).setUint32(0, raw.length);
  out.set(raw, 4);
  return out;
}
function unpad(buf) {
  const len = new DataView(buf.buffer).getUint32(0);
  return buf.slice(4, 4 + len);
}
function toAesKey(u) {
  return subtle.importKey('raw', u, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/* ---------------- CM-RR: Double Ratchet dy-drejtimësh + RBQR ---------------- */

const DH_EVERY = 16;          // sa mesazhe para çdo DH break-in ratchet
const SALT32 = () => new Uint8Array(32);

/** Rrënja e lidhjes: DH(çelës LT Priv, çelës LT i palit) -> HKDF -> RK (32B). */
async function linkRootFromDH(myPriv, peerPub) {
  const dh = await ecdhDerive(myPriv, peerPub);
  return hkdf(dh, SALT32(), TE.encode('CM-RR-v1-link'), 32);
}

/**
 * Një DREJTIM i vetëm (A->B ose B->A).
 *   role 'out'  -> e mira jonë, dërgon; zotëron çelësin ephemeral.
 *   role 'in'   -> pranon; pret çelësin ephemeral të palit në header.
 * RBQR: token-i i radhës rrjedh nga RK; ndryshon sa herë bëhet DH ratchet.
 */
class Channel {
  constructor({ role, myKP, peerKP, initialRK }) {
    this.role = role;               // 'out' | 'in'
    this.myKP = myKP;               // çelës afatgjatë (private+public)
    this.peerKP = peerKP;           // çelës afatgjatë i palit (pub)
    this.rk = initialRK;            // Root Key për këtë drejtim
    this.chain = null;
    this.seq = 0;
    this.eph = null;                // çelës ephemeral (vetëm për 'out')
  }

  _parse(peer) { return { priv: this.myKP, pub: peer }; }

  /** DH break-in: rilloget RK + chain nga DH e s re. Rezultati është i njëjtë
   *  për të dy palët sepse përdor çelësin ephemeral të dërguesit. */
  async _dhStep(ephPriv, peerPub) {
    const dh = await ecdhDerive(ephPriv, peerPub);
    const newChain = await hkdf(dh, this.rk, TE.encode('CM-RR-chain'), 32);
    this.rk = await hkdf(dh, this.rk, TE.encode('CM-RR-rail'), 32);
    this.chain = newChain;
    this.seq = 0;
  }

  /** Dërgo një mesazh. Kthe { mk, ephPub, seq } — ephPub jo-null kur ka pasur
   *  DH ratchet (marrësi DUHET ta përdorë për të rimëkëmbur gjendjen). */
  async send() {
    const doDh = this.eph === null || this.seq % DH_EVERY === 0;
    let ephPub = null;
    if (doDh) {
      this.eph = await generateKeyPair();
      await this._dhStep(this.eph.privateKey, this.peerKP);
      ephPub = await exportPub(this.eph);
    }
    const { mk } = await kdfChain(this.chain);
    const { next } = await kdfChain(this.chain);
    this.chain = next;
    this.seq += 1;
    return { mk, ephPub, seq: this.seq };
  }

  /** Pranoj një mesazh nga pali. Pasi ftohen send() me radhë (seq i njëjtë),
   *  zinxhiri është i njëjtë edhe këtu. */
  async recv(ephPubB64) {
    if (ephPubB64) {
      const peerEph = await importPub(ephPubB64);
      await this._dhStep(this.myKP.privateKey, peerEph);
    }
    const { mk } = await kdfChain(this.chain);
    const { next } = await kdfChain(this.chain);
    this.chain = next;
    this.seq += 1;
    return mk;
  }

  /** RBQR token: rrjedh nga RK e drejtimët. Ndryshon me çdo DH ratchet. */
  async rbqrToken(epoch = this.seq) {
    const t = await hkdf(this.rk, SALT32(), TE.encode('CM-RR-rbqr|' + String(epoch)), 32);
    return b.toHex(t);
  }
}

/**
 * Firmë publike: lidh çelësat afatgjatë, ndan rrënjën me DH, dhe krijon dy
 * drejtimet (dërgim 'out' + marrje 'inr') në mënyrë simetrike për të dy palët.
 */
async function makeSession(myKP, peerPubB64) {
  const peerPub = await importPub(peerPubB64);
  const root = await linkRootFromDH(myKP.privateKey, peerPub);
  return {
    out: new Channel({ role: 'out', myKP, peerKP: peerPub, initialRK: root }),
    inr: new Channel({ role: 'in', myKP, peerKP: peerPub, initialRK: root }),
  };
}

module.exports = {
  generateKeyPair, exportPub, importPub, ecdhDerive, hmacSHA, hkdf,
  kdfChain, aeadEncr, aeadDecr, pad, unpad, toAesKey, b, TE, TD, randBytes,
  linkRootFromDH, Channel, makeSession, DH_EVERY,
};