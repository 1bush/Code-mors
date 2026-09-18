/**
 * test-pq.js — verifikim i PQ HARDENING (ML-KEM-768 hibrid) mbi kanalin ekzistues.
 *
 * Kontrollon vetem matematiken e shtreses PQ:
 *  1) encap/decap japin te njejtin sekret (A dhe B pajtohen);
 *  2) pqRekey mbi te njejtin root dhe te njejtin ssPQ -> root identik ne te dyja anet;
 *  3) CT i ndryshuar -> sekret i ndryshem (pa deshtim, implicit rejection i ML-KEM);
 *  4) pa PQ (ssPQ i ndryshem) -> root i ndryshem (desinkronizimi detektohet).
 *
 * NUK teston transportin/UI-ne — per ate: npm run test:pairing / tools/test_pairing_browser.py
 */
'use strict';
const crypto = require('crypto');
const { pathToFileURL } = require('url');
const path = require('path');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { console.log('  PASS  ' + m); pass++; } else { console.log('  FAIL  ' + m); fail++; } };

const hkdf = (ikm, salt, info, len) => new Promise((res, rej) =>
  crypto.hkdf ? crypto.hkdf('sha256', ikm, salt, info, len, (e, d) => e ? rej(e) : res(new Uint8Array(d)))
    : (() => { try { res(new Uint8Array(crypto.hkdfSync('sha256', ikm, salt, info, len))); } catch (e) { rej(e); } })());

// Kopia e pqRekey() nga mors-app.html (e njejta formule) — pa S/zeroize te browserit.
async function pqRekey(rk, ssPQ) {
  const ikm = new Uint8Array(rk.length + ssPQ.length);
  ikm.set(rk, 0); ikm.set(ssPQ, rk.length);
  return hkdf(ikm, new Uint8Array(32), new TextEncoder().encode('GHOST-PQ-v1-hybrid'), 32);
}

(async () => {
  console.log('========== PQ (ML-KEM-768) HARDENING: verifikim ==========');
  const M = await import(pathToFileURL(path.join(__dirname, 'libs', 'mlkem.mjs')).href);
  const kem = await M.createMlKem768();

  // 1) PAJTUESI BAZE
  const [pkA, skA] = kem.generateKeyPair();
  const [ct, ssSender] = kem.encap(pkA);
  const ssRecv = kem.decap(ct, skA);
  ok(pkA.length === 1184 && skA.length === 2400 && ct.length === 1088, `madhësitë: pk=${pkA.length} sk=${skA.length} ct=${ct.length}`);
  ok(Buffer.from(ssSender).equals(Buffer.from(ssRecv)), 'encap/decap: sekret i njëjtë në të dyja anët');

  // 2) REKEY I NJEJTE NE TE DYJA ANET
  const rk0 = crypto.getRandomValues(new Uint8Array(32));
  const rkA = await pqRekey(rk0, ssSender);
  const rkB = await pqRekey(rk0, ssRecv);
  ok(Buffer.from(rkA).equals(Buffer.from(rkB)), 'pqRekey: root identik (A dhe B)');
  ok(!Buffer.from(rkA).equals(Buffer.from(rk0)), 'pqRekey: root ndryshoi nga ai i vjetri');

  // 3) CT I NDRYSHUAR -> sekret i ndryshem (implicit rejection, pa exception)
  const bad = new Uint8Array(ct); bad[0] ^= 1;
  const ssBad = kem.decap(bad, skA);
  ok(!Buffer.from(ssBad).equals(Buffer.from(ssSender)), 'ct i ndryshuar: sekret i ndryshëm (pa crash)');
  const rkBad = await pqRekey(rk0, ssBad);
  ok(!Buffer.from(rkBad).equals(Buffer.from(rkA)), 'root: desinkronizimi detektohet si GCM FAIL');

  // 4) PA PQ -> gjendja klasike mbetet e paprekur
  const rkNoPQ = await pqRekey(rk0, new Uint8Array(0));
  ok(!Buffer.from(rkNoPQ).equals(Buffer.from(rkA)), 'pa ssPQ: root ndryshon (PQ nuk aplikohet në heshtje)');

  console.log(`\n========== PQ: ${pass}/${pass + fail} PASS ==========`);
  process.exit(fail ? 1 : 0);
})();
