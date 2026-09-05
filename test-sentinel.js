'use strict';
/* CODE MORS — test-sentinel.js
   Simulon 3 sulme reale dhe verifikon detektimin + reagimin e Sentinel-it:
   [S1] Tamper i ciphertext-it → AES-GCM auth fail → 🚨 CRYPTO breach
   [S2] Rollback i epoch-it + replay i seq-t → ⚠️/🚨 RELAY breach
   [S3] Tamper i ruajtjes lokale → 🚨 ENV breach
   + panic() → zeroize/wipe hook thirret + niveli mbetet BREACH.
   Përdor komponentët e vërtetë: relay + cm-protocol + cm-sentinel. */
const { Relay } = require('./relay/server.js');
const { Sentinel } = require('./cm-sentinel.js');
const { makeSession, generateKeyPair, exportPub, toAesKey,
        aeadEncr, aeadDecr, pad, TE } = require('./cm-protocol.js');

async function main() {
  const relay = new Relay({ logging: false });
  const port = await relay.listen(0, '127.0.0.1');
  const base = `http://127.0.0.1:${port}`;
  const results = [];
  const ok = (n, c, x = '') => { results.push(!!c); console.log(`${c ? '✅ PASS' : '❌ FAIL'}  ${n}${x ? '  — ' + x : ''}`); };

  const alerts = [];
  let wiped = false;
  const sentinel = new Sentinel({
    onAlert: (a) => alerts.push(a.text),
    onPanic: () => { wiped = true; },
  });

  const create = async () => (await (await fetch(base + '/v1/queue', { method: 'POST' })).json());
  const push = async (id, t, blob) => (await (await fetch(`${base}/v1/queue/${id}/msg?t=${t}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ blob }) })).json());
  const pull = async (id, t, epoch, since = 0) => (await (await fetch(`${base}/v1/queue/${id}/msg?token=${t}&epoch=${epoch}&since=${since}`)).json());
  const rotate = async (id, t, epoch) => (await (await fetch(`${base}/v1/queue/${id}/rotate?token=${t}&epoch=${epoch}`, { method: 'POST' })).json());

  // lidhja e vërtetë A->B
  const aliceKP = await generateKeyPair(), bobKP = await generateKeyPair();
  const alice = await makeSession(aliceKP, await exportPub(bobKP));
  const bob = await makeSession(bobKP, await exportPub(aliceKP));
  const q = await create();
  let bobTok = q.pullToken, bobEph = q.pullEpoch, bobSince = 0;
  const seen = new Set();

  sentinel.learnRelay(base, 'v1/queue');
  const state0 = JSON.stringify({ contacts: 1, keys: 'A1B2' });
  sentinel.learnStorage(state0);

  // dërgim normal
  const enc = async (ch, m) => {
    const { mk, ephPub, seq } = await ch.send();
    const { iv, ct } = await aeadEncr(await toAesKey(mk), pad(TE.encode(m)));
    return JSON.stringify({ v: 1, seq, eph: ephPub, body: { iv: Buffer.from(iv).toString('base64'), ct: Buffer.from(ct).toString('base64') } });
  };
  const push1 = await push(q.queueId, q.pushToken, await enc(alice.out, 'MSG-OK-1'));
  const p1 = await pull(q.queueId, bobTok, bobEph, bobSince);
  bobSince = p1.msgs[0].seq; seen.add(p1.msgs[0].seq);
  const dec = async (ch, blob) => {
    const h = JSON.parse(blob);
    const mk = await ch.recv(h.eph);
    const a = new Uint8Array(Buffer.from(h.body.iv, 'base64'));
    const c = new Uint8Array(Buffer.from(h.body.ct, 'base64'));
    return new TextDecoder().decode((await import('./cm-protocol.js')).unpad(await aeadDecr(await toAesKey(mk), a, c)));
  };
  ok('Baza: mesazh normal i dërguar dhe i deshifruar', push1.ok && p1.ok && (await dec(bob.inr, p1.msgs[0].blob)).startsWith('MSG-OK'));
  ok('Baza: Sentinel OK para sulmeve', sentinel.summary().level === 0);
// ---------- SULMI 1 (S1-CRYPTO): tamper i ciphertext-it në rrjet ----------
  const blob2 = await enc(alice.out, 'MSG-SECRET-2');
  const h2 = JSON.parse(blob2);
  // sulmuesi ndryshon 1 bajt të ciphertext-it (bit-flip në transit)
  const ctBytes = Buffer.from(h2.body.ct, 'base64');
  ctBytes[0] ^= 0x01;
  h2.body.ct = ctBytes.toString('base64');
  await push(q.queueId, q.pushToken, JSON.stringify(h2));
  const p2 = await pull(q.queueId, bobTok, bobEph, bobSince);
  bobSince = p2.msgs[p2.msgs.length - 1].seq;
  let s1detected = false;
  try { await dec(bob.inr, p2.msgs[0].blob); } catch (e) {
    sentinel.reportCryptoFailure('AES-GCM auth fail — mesazh i ndryshuar në transit (tamper/MITM)');
    s1detected = true;
  }
  ok('S1: tamper i ciphertext-it DETEKTOHET (GCM auth fail)', s1detected);
  // rizinxhiro: Bob-i humbi 1 hap të zinxhirit për shkak të mesazhit të prishur
  // (protokolli i plotë do të mbushte me skipped-keys; këtu e raportojmë si desync)
  await push(q.queueId, q.pushToken, await enc(alice.out, 'MSG-3-RESYNC'));
  const p3 = await pull(q.queueId, bobTok, bobEph, bobSince);
  bobSince = p3.msgs[p3.msgs.length - 1].seq;
  ok('S1: Sentinel niveli = BREACH pas tamper-it', sentinel.summary().level === 2, 'score=' + sentinel.summary().score);

  // ---------- SULMI 2 (S2-RELAY): rollback epoch + replay ----------
  const ephBefore = bobEph;
  const rot = await rotate(q.queueId, bobTok, bobEph);
  bobTok = rot.pullToken; bobEph = rot.pullEpoch;
  // sulmuesi (server i komprometuar) ofron epoch më të vjetër:
  const rb = sentinel.checkEpoch(bobEph, ephBefore);
  ok('S2: epoch rollback DETEKTOHET', rb === false, `known=${bobEph} offered=${ephBefore}`);
  // replay: sulmuesi ridërgon seq të konsumuar
  const rep = sentinel.checkReplay(1, seen);
  ok('S2: replay i seq-t DETEKTOHET', rep === false, 'seq=1 i ripërpunuar');
  // fingerprint i ndryshëm i relay-it (server i zëvendësuar)
  sentinel.learnRelay(base, 'v1/queue');
  sentinel.checkRelay('http://evil-mitm.example:9999', 'v1/queue');
  ok('S2: fingerprint i ndryshëm i relay DETEKTOHET', alerts.some(a => a.includes('RELAY_FINGERPRINT_CHANGED')));

  // ---------- SULMI 3 (S3-ENV): tamper i ruajtjes lokale ----------
  const tampered = JSON.stringify({ contacts: 1, keys: 'HACKED-BY-PEGASUS' });
  const s3 = sentinel.verifyStorage(tampered);
  ok('S3: tamper i ruajtjes lokale DETEKTOHET (checksum)', s3 === false);

  // hook native (si DeepGuard/PrmGuard nga Java bridge)
  ok('S3: native guard (DeepGuard FAIL) raportohet', sentinel.reportNativeGuard('DEEPGUARD', false, 'APK hash mismatch') === false);

  // ---------- Reagimi: panic wipe ----------
  const before = sentinel.summary();
  sentinel.panic('auto: BREACH score ' + before.score);
  ok('PANIC: wipe hook u ekzekutua (zeroize çelësa)', wiped === true);
  ok('PANIC: niveli mbetet BREACH', sentinel.summary().level === 2);
  ok('Alerts: u prodhuan sinjalizime 🚨 për UI (trekëndësh/banner)', alerts.length >= 5, alerts.length + ' alerts');
  console.log('\n--- ALERT LOG (siç do ta shfaqe UI) ---');
  for (const a of alerts.slice(-8)) console.log('   ' + a);

  relay.stop();
  const passed = results.every(Boolean);
  console.log(`\n========== SENTINEL: ${results.filter(Boolean).length}/${results.length} PASS ==========`);
  process.exitCode = passed ? 0 : 1;
}
main().catch((e) => { console.error('TEST ERROR:', e); process.exit(2); });