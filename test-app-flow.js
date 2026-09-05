'use strict';
/* test-app-flow.js — rrjedha NJE-HAPI e chat-app.html:
   ① A: 2 radhë + ftesë → ② B: ftesë + connect automatik → chat E2E + RBQR. */
const { Relay } = require('./relay/server.js');
const { makeSession, generateKeyPair, exportPub, toAesKey, aeadEncr, aeadDecr, pad, unpad, TE, TD } = require('./cm-protocol.js');

(async () => {
  const relay = new Relay({ logging: false });
  const base = `http://127.0.0.1:${await relay.listen(0, '127.0.0.1')}`;
  const results = [];
  const ok = (n, c, x = '') => { results.push(!!c); console.log(`${c ? '✅ PASS' : '❌ FAIL'}  ${n}${x ? '  — ' + x : ''}`); };
  const j2c = o => Buffer.from(JSON.stringify(o)).toString('base64');
  const c2j = s => JSON.parse(Buffer.from(s, 'base64').toString());
  const api = async (p, o) => (await (await fetch(base + p, o)).json());
  const mkQ = () => api('/v1/queue', { method: 'POST' });
  const push = (id, t, b) => api(`/v1/queue/${id}/msg?t=${encodeURIComponent(t)}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ blob: b }) });
  const pull = (id, t, e, s) => api(`/v1/queue/${id}/msg?token=${encodeURIComponent(t)}&epoch=${e}&since=${s}`);
  const rot = (id, t, e) => api(`/v1/queue/${id}/rotate?token=${encodeURIComponent(t)}&epoch=${e}`, { method: 'POST' });
  const enc = async (ch, m) => { const { mk, ephPub, seq } = await ch.send();
    const { iv, ct } = await aeadEncr(await toAesKey(mk), pad(TE.encode(m)));
    return JSON.stringify({ v: 1, seq, eph: ephPub, body: { iv: Buffer.from(iv).toString('base64'), ct: Buffer.from(ct).toString('base64') } }); };
  const dec = async (ch, blob) => { const h = JSON.parse(blob); const mk = await ch.recv(h.eph);
    return TD.decode(unpad(await aeadDecr(await toAesKey(mk), new Uint8Array(Buffer.from(h.body.iv, 'base64')), new Uint8Array(Buffer.from(h.body.ct, 'base64'))))); };

  const aKP = await generateKeyPair(), bKP = await generateKeyPair();

  /* ① ana A: 2 radhë + ftesë (si btnNew) */
  const qAB = await mkQ(), qBA = await mkQ();
  const invite = j2c({ v: 1, pub: await exportPub(aKP), ghost: 'VOID-01',
    pull: { id: qAB.queueId, token: qAB.pullToken, epoch: qAB.pullEpoch },
    push: { id: qBA.queueId, token: qBA.pushToken } });
  ok('① Ftesa një-hapi e gjeneruar (A)', invite.length > 40);

  /* ② ana B: ngjit ftesën → session + RBQR + connect automatik (si onJoin) */
  const inv = c2j(invite);
  const bSess = await makeSession(bKP, inv.pub);
  let bTok = inv.pull.token, bEph = inv.pull.epoch, bSince = 0;
  const tb = await bSess.inr.rbqrToken();
  const rb = await rot(inv.pull.id, bTok, bEph);
  bTok = rb.pullToken; bEph = rb.pullEpoch;
  const conn = await push(inv.push.id, inv.push.token, JSON.stringify({ type: 'connect', pub: await exportPub(bKP), ghost: 'RAVEN-02' }));
  ok('② B: RBQR + connect automatik përmes kanalit', rb.ok && conn.ok);

  /* ③ ana A: poll → kap connect → hap chat (si poll/onConnect) */
  const pr = await pull(qBA.queueId, qBA.pullToken, qBA.pullEpoch, 0);
  const ci = pr.msgs.findIndex(m => { try { return JSON.parse(m.blob).type === 'connect'; } catch { return false; } });
  const connMsg = ci >= 0 ? JSON.parse(pr.msgs[ci].blob) : null;
  let aSince = ci >= 0 ? pr.msgs[ci].seq : 0;
  const aSess = connMsg ? await makeSession(aKP, connMsg.pub) : null;
  ok('③ A: connect i kapur automatikisht, chat hapet', !!aSess && connMsg.ghost === 'RAVEN-02');
  const ta = await aSess.inr.rbqrToken();
  const ra = await rot(qBA.queueId, qBA.pullToken, qBA.pullEpoch);
  ok('③ A: RBQR rotacion pas lidhjes', ra.ok && ra.pullEpoch === 1);
  let aTok = ra.pullToken, aEph = ra.pullEpoch;

  /* CHAT A→B */
  await push(qAB.queueId, qAB.pushToken, await enc(aSess.out, 'tungjatjeta'));
  const p1 = await pull(inv.pull.id, bTok, bEph, bSince);
  bSince = p1.msgs[p1.msgs.length - 1].seq;
  ok('CHAT A→B E2E', p1.ok && (await dec(bSess.inr, p1.msgs[0].blob)) === 'tungjatjeta');
  const rb2 = await rot(inv.pull.id, bTok, bEph); bTok = rb2.pullToken; bEph = rb2.pullEpoch;

  /* CHAT B→A */
  await push(inv.push.id, inv.push.token, await enc(bSess.out, 'përgjigje'));
  const p2 = await pull(qBA.queueId, aTok, aEph, aSince);
  aSince = p2.msgs[p2.msgs.length - 1].seq;
  ok('CHAT B→A E2E', p2.ok && (await dec(aSess.inr, p2.msgs[0].blob)) === 'përgjigje');
  const ra2 = await rot(qBA.queueId, aTok, aEph); aTok = ra2.pullToken; aEph = ra2.pullEpoch;

  /* burst + RBQR pas çdo batch */
  for (let i = 0; i < 12; i++) await push(qAB.queueId, qAB.pushToken, await enc(aSess.out, 'msg-' + i));
  const pb = await pull(inv.pull.id, bTok, bEph, bSince);
  let all = pb.ok && pb.msgs.length === 12;
  for (const m of pb.msgs) { if (!(await dec(bSess.inr, m.blob)).startsWith('msg-')) all = false; }
  ok('CHAT: 12 mesazhe burst me ratchet', all);
  const rb3 = await rot(inv.pull.id, bTok, bEph);
  const stale = await pull(inv.pull.id, inv.pull.token, inv.pull.epoch, 0);
  ok('RBQR: token fillestar REFUZOHET pas rotacioneve', rb3.ok && !stale.ok);

  relay.stop();
  console.log(`\n========== APP-FLOW (nje-hapi): ${results.filter(Boolean).length}/${results.length} PASS ==========`);
  process.exitCode = results.every(Boolean) ? 0 : 1;
})().catch(e => { console.error('TEST ERROR:', e); process.exit(2); });