'use strict';
/* CODE MORS — test-hybrid.js | verifikim e2e i hibridit GHOST-RELAY.
   E2E Double Ratchet përmes relay + RBQR (i vjetri refuzohet) + privacy. */
const { Relay } = require('./relay/server.js');
const { makeSession, generateKeyPair, exportPub, toAesKey,
        aeadEncr, aeadDecr, pad, unpad, TE, TD } = require('./cm-protocol.js');

async function main() {
  const relay = new Relay({ logging: false });
  const port = await relay.listen(0, '127.0.0.1');
  const base = `http://127.0.0.1:${port}`;
  const results = [];
  const ok = (n, c, x = '') => { results.push({ name: n, ok: !!c }); console.log(`${c ? '✅ PASS' : '❌ FAIL'}  ${n}${x ? '  — ' + x : ''}`); };

  const create = async () => (await (await fetch(base + '/v1/queue', { method: 'POST' })).json());
  const push = async (id, t, blob) => (await (await fetch(`${base}/v1/queue/${id}/msg?t=${t}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ blob }) })).json());
  const pull = async (id, t, epoch, since = 0) => (await (await fetch(`${base}/v1/queue/${id}/msg?token=${t}&epoch=${epoch}&since=${since}`)).json());
  const rotate = async (id, t, epoch) => (await (await fetch(`${base}/v1/queue/${id}/rotate?token=${t}&epoch=${epoch}`, { method: 'POST' })).json());

  // 1) lidhje: çelësa LT + session-e dy-drejtim
  const aliceKP = await generateKeyPair(), bobKP = await generateKeyPair();
  const alice = await makeSession(aliceKP, await exportPub(bobKP));
  const bob = await makeSession(bobKP, await exportPub(aliceKP));
  const enc = async (ch, m) => {
    const { mk, ephPub, seq } = await ch.send();
    const { iv, ct } = await aeadEncr(await toAesKey(mk), pad(TE.encode(m)));
    return JSON.stringify({ v: 1, seq, eph: ephPub, body: { iv: Buffer.from(iv).toString('base64'), ct: Buffer.from(ct).toString('base64') } });
  };
  const dec = async (ch, blob) => {
    const h = JSON.parse(blob);
    const mk = await ch.recv(h.eph);
    const a = new Uint8Array(Buffer.from(h.body.iv, 'base64'));
    const c = new Uint8Array(Buffer.from(h.body.ct, 'base64'));
    return TD.decode(unpad(await aeadDecr(await toAesKey(mk), a, c)));
  };
// 2) radhët njëdrejtimëshe
  const qAB = await create(), qBA = await create();
  let bobTok = qAB.pullToken, bobEph = qAB.pullEpoch, bobSince = 0;
  let aliTok = qBA.pullToken, aliEph = qBA.pullEpoch, aliSince = 0;

  // 3) Alisa -> Bob (e para, përmban eph DH ratchet)
  const text1 = 'SALUT-TIRANA-TOTAL-TOP-SEKRET-123';
  const blobAB1 = await enc(alice.out, text1);
  const pushRes = await push(qAB.queueId, qAB.pushToken, blobAB1);
  ok('Alisa dërgoi në radhën A->B', pushRes && pushRes.ok, 'seq=' + (pushRes && pushRes.seq));

  const p1 = await pull(qAB.queueId, bobTok, bobEph);
  ok('Bob tërhoqi mesazhin', p1 && p1.ok && p1.msgs && p1.msgs.length === 1);
  bobSince = p1.msgs[0].seq;   // gjurmo pikën e konsumimit (pull jo-destruktiv)
  ok('Serveri ruan vetëm ciphertext (s\'përmban plaintext)', !p1.msgs[0].blob.includes('SALUT-TIRANA'));
  ok('Bob deshifroi mesazhin e Alisë (E2E Double Ratchet)', (await dec(bob.inr, p1.msgs[0].blob)) === text1);

  // 5) padding
  const plen = pad(TE.encode(text1)).length;
  ok('Padding: madhësia e plaintext-it me padding është shumëfish i bllokut', plen % 256 === 0, plen + 'B');

  // 6) RBQR: rrotullo token; i vjetri refuzohet
  const rot0 = await rotate(qAB.queueId, bobTok, bobEph);
  ok('RBQR: token-i rrotullohet me gjendjen e ratchet', rot0 && rot0.ok, 'epoch=' + (rot0 && rot0.pullEpoch));
  bobTok = rot0.pullToken; bobEph = rot0.pullEpoch;
  const stale = await pull(qAB.queueId, qAB.pullToken, qAB.pullEpoch);
  ok('RBQR: token-i i vjetër REFUZOHET (forward secrecy i metadata-s)',
     stale && !stale.ok && (stale.err === 'bad_pull_token' || stale.err === 'stale_epoch'), JSON.stringify(stale));

  // 7) Bob -> Alisa (drejtimi i kundërt)
  const text2 = 'PËRGJIGJE-mbrapa-mbi-relay-9876';
  ok('Bob dërgoi në radhën B->A', (await push(qBA.queueId, qBA.pushToken, await enc(bob.out, text2))).ok);
  const pBA = await pull(qBA.queueId, aliTok, aliEph);
  ok('Alisa tërhoqi mesazhin B->A', pBA && pBA.ok && pBA.msgs && pBA.msgs.length === 1);
  aliSince = pBA.msgs[0].seq;
  ok('Alisa deshifroi mesazhin e Bob-it', (await dec(alice.inr, pBA.msgs[0].blob)) === text2);

  // 8) 40 mesazhe radhë + DH break-in
  let okSend = true, ephSeen = 0, okDec = true;
  for (let i = 0; i < 40; i++) {
    okSend = okSend && (await push(qAB.queueId, qAB.pushToken, await enc(alice.out, 'PLAIN-' + i + '-SECRET-' + (i * 7)))).ok;
  }
  const pb = await pull(qAB.queueId, bobTok, bobEph, bobSince);
  okSend = okSend && pb.ok && pb.msgs && pb.msgs.length === 40;
  for (const mm of pb.msgs) { const h = JSON.parse(mm.blob); if (h.eph) ephSeen++; if (!(await dec(bob.inr, mm.blob)).startsWith('PLAIN-')) okDec = false; }
  ok('40 mesazhe radhë: dërgimi/deshifrimi i konsistent', okSend && okDec, 'eph=' + ephSeen);
  ok('DH break-in: pat riduktime çelësi (eph në header)', ephSeen >= 2, ephSeen + ' eph');

  // 9) RBQR avancon sërish me ratchet-in e ri
  const rot1 = await rotate(qAB.queueId, bobTok, bobEph);
  ok('RBQR avancon sërish me ratchet-in e ri', rot1 && rot1.ok, 'epoch=' + (rot1 && rot1.pullEpoch));

  //@@PART2
  relay.stop();
  const failed = results.filter((r) => !r.ok).length;
  console.log('\n==================== PËRMBLEDHJE ====================');
  console.log(`  TOTAL: ${results.length}   PASS: ${results.length - failed}   FAIL: ${failed}`);
  if (failed === 0) console.log('  🟢 HYBRID GHOST RELAY v1: GJITHÇKA E VERIFIKUAR OK');
  else console.log('  🔴 Ka dështime!');
  console.log('=====================================================');
  process.exit(failed === 0 ? 0 : 1);
}
main().catch((e) => { console.error('TEST ERROR:', e); process.exit(2); });