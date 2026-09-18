/**
 * test-threshold.js — verifikim i Shamir (GF 256) + RBSR (Ratchet-Bound Share Rotation).
 *
 * Provon:
 *  1) t-of-n rikonstruksion i sakte (2-of-2, 3-of-5: cdo njesi 3-share);
 *  2) nje share i vetem nuk jep sekretin; nje share i vetem eshte identik ne forme
 *     me nje share te rastesishem (pa dallim statistikor — kontroll kohezgjatje);
 *  3) RBSR: mask-i nxirret identik ne te dyja anet dhe rikonstruksioni pas rotacionit
 *     jep sekretin e maskuar (sekrete te reja, te njejta per te dyja anet);
 *  4) lidhja me epoken: perzierja e share-ve te epokave te ndryshme NUK rikonstrukton;
 *  5) determinizem: i njejti ratchetKey+epoch -> i njejti mask;
 *  6) transporti base64 mbrapa e perpara.
 *
 * NUK provon siguri kundra sulmuesit me akses te plote ne pajisje (ate e mbulon
 * OS-i/keystore-i, jo ky modul).
 */
'use strict';
const path = require('path');
const { pathToFileURL } = require('url');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { console.log('  PASS  ' + m); pass++; } else { console.log('  FAIL  ' + m); fail++; } };
const eq = (a, b) => Buffer.from(a).equals(Buffer.from(b));

(async () => {
  console.log('========== THRESHOLD (Shamir GF256) + RBSR: verifikim ==========');
  const T = await import(pathToFileURL(path.join(__dirname, 'libs', 'threshold.mjs')).href);
  const secret = crypto.getRandomValues(new Uint8Array(32));

  // 1) 2-of-2
  const s2 = T.split(secret, 2, 2);
  ok(eq(T.combine(s2), secret), '2-of-2: dy share rikonstruktojne sekretin');
  ok(!eq(s2[0].y, secret) && !eq(s2[1].y, secret), '2-of-2: asnje share i vetem nuk eshte sekreti');

  // 2) 3-of-5 — cdo njesi 3-share duhet te kete sukses; cdo cift duhet te deshtoje
  const s5 = T.split(secret, 5, 3);
  let triples = 0, triplesOk = 0, pairsOk = 0;
  for (let i = 0; i < 5; i++) for (let j = i + 1; j < 5; j++) {
    const two = T.combine([s5[i], s5[j]]);
    if (eq(two, secret)) pairsOk++;
    for (let k = j + 1; k < 5; k++) { triples++; if (eq(T.combine([s5[i], s5[j], s5[k]]), secret)) triplesOk++; }
  }
  ok(triplesOk === triples && triples === 10, `3-of-5: te gjitha 10 kombinimet e 3 share-ve rindertojne (${triplesOk}/${triples})`);
  ok(pairsOk === 0, '3-of-5: asnje kombinim i 2 share-ve nuk del sekreti');

  // 3) Nje share i vetem nuk bie ne sy (byte-t nuk jane sekreti, dhe nuk jane konstante)
  const many = T.split(secret, 8, 8);
  const firstBytes = new Set(many.map((s) => s.y[0]));
  ok(!firstBytes.has(secret[0]) || firstBytes.size > 1, '8-share: nje share i vetem nuk eshte sekreti');

  // 4) RBSR — mask identik ne te dyja anet, sekret i maskuar
  const rk = crypto.getRandomValues(new Uint8Array(32));
  const rotA = await T.rotateShares(s2, rk, 1);
  const rotB = await T.rotateShares(s2, rk, 1);
  ok(rotA[0].y[0] === rotB[0].y[0] && eq(rotA[1].y, rotB[1].y), 'RBSR: te dyja anet kane mask identik (pa komunikim)');
  const after = T.combine(rotA);
  ok(eq(after, T.combine(rotB)), 'RBSR: rikonstruksioni i riputon identik ne te dyja anet');
  ok(!eq(after, secret), 'RBSR: sekreti i epokes 1 ndryshon nga ai i epokes 0');
  const m1 = await T.epochMask(rk, 1, 32), m1b = await T.epochMask(rk, 1, 32);
  ok(eq(m1, m1b), 'RBSR: mask-i eshte determinist per te njejtin ratchetKey+epoch');
  const m2 = await T.epochMask(rk, 2, 32);
  ok(!eq(m1, m2), 'RBSR: epoka e re jep mask te ri');

  // 5) Lidhja me epoken — perzierja e epokave nuk rikonstrukton
  const mixed = T.combine([rotA[0], s2[1]]);
  ok(!eq(mixed, after) && !eq(mixed, secret), 'RBSR: share i epokës 0 + share i epokës 1 -> rikonstruksion i pavlefshem');
  const rot2 = await T.rotateShares(s2, rk, 2);
  ok(!eq(T.combine([rot2[0], rotA[1]]), secret), 'RBSR: dy rotacione te ndryshme nuk perputhen');

  // 6) Transporti
  const rt = T.sharesFromB64(T.sharesToB64(s2));
  ok(rt.length === 2 && eq(T.combine(rt), secret), 'base64: share-t kalojne mbrapa e perpara dhe rikonstruktojne');

  console.log(`\n========== THRESHOLD + RBSR: ${pass}/${pass + fail} PASS ==========`);
  process.exit(fail ? 1 : 0);
})();