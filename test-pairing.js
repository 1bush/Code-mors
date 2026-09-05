'use strict';
/* test-pairing.js — simulon SAKË rrjedhën e UI-së së ghost-relay-chat.html:
   ① A krijon Link A  →  ② B bashkohet + Reply B  →  ③ A përfundon  →  chat E2E + RBQR. */
const { makeSession, generateKeyPair, exportPub, toAesKey, aeadEncr, aeadDecr, pad, unpad, TE, TD, hkdf, ecdhDerive, importPub } = require('./cm-protocol.js');
const { Relay } = require('./relay/server.js');

(async () => {
  const relay = new Relay({ logging: false });
  const base = `http://127.0.0.1:${await relay.listen(0, '127.0.0.1')}`;
  const results = [];
  const ok = (n, c, x = '') => { results.push(!!c); console.log(`${c ? '✅ PASS' : '❌ FAIL'}  ${n}${x ? '  — ' + x : ''}`); };
  const j2c = (o) => Buffer.from(JSON.stringify(o)).toString('base64');
  const c2j = (s) => JSON.parse(Buffer.from(s, 'base64').toString());
  const api = async (p, o) => (await (await fetch(base + p, o)).json());
  const mkQueue = () => api('/v1/queue', { method: 'POST' });
  const push = (id, t, blob) => api(`/v1/queue/${id}/msg?t=${encodeURIComponent(t)}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ blob }) });
  const pull = (id, t, e, s) => api(`/v1/queue/${id}/msg?token=${encodeURIComponent(t)}&epoch=${e}&since=${s}`);
  const rot = (id, t, e) => api(`/v1/queue/${id}/rotate?token=${encodeURIComponent(t)}&epoch=${e}`, { method: 'POST' });
  const enc = async (ch, m) => {
    const { mk, ephPub, seq } = await ch.send();
    const { iv, ct } = await aeadEncr(await toAesKey(mk), pad(TE.encode(m)));
    return JSON.stringify({ v: 1, seq, eph: ephPub, body: { iv: Buffer.from(iv).toString('base64'), ct: Buffer.from(ct).toString('base64') } });
  };
  const dec = async (ch, blob) => {
    const h = JSON.parse(blob); const mk = await ch.recv(h.eph);
    return TD.decode(unpad(await aeadDecr(await toAesKey(mk), new Uint8Array(Buffer.from(h.body.iv, 'base64')), new Uint8Array(Buffer.from(h.body.ct, 'base64')))));
  };

  // identitetet
  const aKP = await generateKeyPair(), bKP = await generateKeyPair();

  // ① A krijon Link A
  const qAB = await mkQueue();
  const linkA = j2c({ t: 'GHOST-RELAY-LINK-A', v: 1, pub: await exportPub(aKP), ghost: 'VOID-01', queueId: qAB.queueId, pullToken: qAB.pullToken, epoch: qAB.pullEpoch });
  ok('① Link A i gjeneruar', linkA.length > 40 && qAB.ok !== false);

  // ② B bashkohet
  const L = c2j(linkA);
  const bSess = await makeSession(bKP, L.pub);
  let bPullTok = L.pullToken, bEpoch = L.epoch, bSince = 0;
  // RBQR: B rotullon token-in e pull në atë të vetin (nga gjendja e ratchet)
  const tokB = await bSess.inr.rbqrToken();
  const rb = await rot(L.queueId, bPullTok, bEpoch);
  ok('② B: RBQR rotacion i token-it pas bashkimit', rb.ok && rb.pullEpoch === 1);
  bPullTok = rb.pullToken; bEpoch = rb.pullEpoch;
  const qBA = await mkQueue();
  const linkB = j2c({ t: 'GHOST-RELAY-REPLY-B', v: 1, pub: await exportPub(bKP), ghost: 'RAVEN-02', queueId: qBA.queueId, pullToken: qBA.pullToken, epoch: qBA.pullEpoch });

  // ③ A përfundon me Reply B
  const RP = c2j(linkB);
  const aSess = await makeSession(aKP, RP.pub);
  let aPullTok = RP.pullToken, aEpoch = RP.epoch, aSince = 0;
  const tokA = await aSess.inr.rbqrToken();
  const ra = await rot(RP.queueId, aPullTok, aEpoch);
  ok('③ A: RBQR rotacion në radhën B→A', ra.ok && ra.pullEpoch === 1);
  aPullTok = ra.pullToken; aEpoch = ra.pullEpoch;

  // CHAT: A → B
  const r1 = await push(qAB.queueId, qAB.pushToken, await enc(aSess.out, 'përshëndetje nga ana A'));
  const p1 = await pull(L.queueId, bPullTok, bEpoch, bSince);
  bSince = p1.msgs[p1.msgs.length - 1].seq;
  ok('CHAT A→B: dërguar + marrë + deshifruar', r1.ok && p1.ok && (await dec(bSess.inr, p1.msgs[0].blob)) === 'përshëndetje nga ana A');
  const rb2 = await rot(L.queueId, bPullTok, bEpoch); bPullTok = rb2.pullToken; bEpoch = rb2.pullEpoch;

  // CHAT: B → A
  const r2 = await push(qBA.queueId, qBA.pushToken, await enc(bSess.out, 'përgjigje nga ana B'));
  const p2 = await pull(RP.queueId, aPullTok, aEpoch, aSince);
  aSince = p2.msgs[p2.msgs.length - 1].seq;
  ok('CHAT B→A: dërguar + marrë + deshifruar', r2.ok && p2.ok && (await dec(aSess.inr, p2.msgs[0].blob)) === 'përgjigje nga ana B');

  // multi-message + RBQR pas secilit batch
  let allok = true;
  for (let i = 0; i < 10; i++) { allok = allok && (await push(qAB.queueId, qAB.pushToken, await enc(aSess.out, 'burst-' + i))).ok; }
  const pb = await pull(L.queueId, bPullTok, bEpoch, bSince);
  for (const m of pb.msgs) { if (!(await dec(bSess.inr, m.blob)).startsWith('burst-')) allok = false; bSince = m.seq; }
  ok('CHAT: 10 mesazhe burst A→B me ratchet + RBQR', allok && pb.msgs.length === 10);
  const rb3 = await rot(L.queueId, bPullTok, bEpoch); bPullTok = rb3.pullToken; bEpoch = rb3.pullEpoch;
  const stale = await pull(L.queueId, qAB.pullToken, 0, 0);
  ok('RBQR: token fillestar tani REFUZOHET', !stale.ok);

  relay.stop();
  console.log(`\n========== PAIRING-FLOW: ${results.filter(Boolean).length}/${results.length} PASS ==========`);
  process.exitCode = results.every(Boolean) ? 0 : 1;
})().catch(e => { console.error('TEST ERROR:', e); process.exit(2); });