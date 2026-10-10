/**
 * CODE MORS — test-hardlava.js
 * Verifikon HARD LAVA: detektim code-swap/debugger/exfil/integritet +
 * zeroize + orchestrated wipe + KILL.
 */
'use strict';
const { HardLava, zeroize, fnDigest } = require('./cm-hardlava');

let pass = 0, fail = 0;
const ok = (cond, msg, extra = '') => {
  if (cond) { pass++; console.log(`✅ PASS  ${msg}${extra ? '  — ' + extra : ''}`); }
  else { fail++; console.log(`❌ FAIL  ${msg}${extra ? '  — ' + extra : ''}`); }
};

/* --- 0: zeroize --- */
{
  const buf = new Uint8Array([1, 2, 3, 4, 5]);
  zeroize(buf);
  ok(buf.every(b => b === 0), 'zeroize: Uint8Array mbishkruhet me zero');
}

/* --- 1: pin/verify zbulon monkey-patch --- */
{
  const hl = new HardLava({ threshold: 50 });
  const orig = function secret() { return 42; };
  hl.pin('secret', orig);
  ok(hl.verify('secret', orig) === true, 'HL1: funksion i pathyktruar verifikohet OK');
  const tampered = function secret() { return 43; };
  const res = hl.verify('secret', tampered);
  ok(res === false, 'HL1: monkey-patch zbulohet (CODE_SWAP)', `score=${hl.score}`);
}

/* --- 2: debugger/exfil/eval shtojnë score --- */
{
  const hl = new HardLava({ threshold: 200 }); // i lartë që të mos shpërthejë vetë
  hl.reportDebugger(); hl.reportSourceFetch('evil.com'); hl.reportDynamicEval();
  ok(hl.score >= 90, 'HL2/3/4: debugger+exfil+eval shtojnë score', `score=${hl.score}`);
}

/* --- 3: integritet build --- */
{
  const hl = new HardLava({ threshold: 200 });
  ok(hl.verifyIntegrity('abc', 'abc') === true, 'HL5: hash i saktë kalon');
  ok(hl.verifyIntegrity('abc', 'xyz') === false, 'HL5: hash i modifikuar zbulohet');
}

/* --- 4: detonation -> onWipe + onLava + pa kthim --- */
{
  let wiped = false, lavaFired = false;
  const hl = new HardLava({ threshold: 50, onWipe: () => { wiped = true; }, onLava: () => { lavaFired = true; } });
  hl.reportSourceFetch('evil.com');   // 35
  hl.reportDebugger();                // +30 = 65 >= 50 -> shpërthim
  ok(hl.detonated === true, 'HARD LAVA: shpërthej kur score kalon pragun');
  ok(wiped === true, 'HARD LAVA: onWipe (zeroize+wipe+kill) u thirr');
  ok(lavaFired === true, 'HARD LAVA: onLava (alarm) u thirr');
  // pa kthim: një hit i mëpasshëm nuk e ndryshon (mbetet i detonuar)
  const s2 = hl.score;
  hl.reportDynamicEval();
  ok(hl.detonated === true && hl.score === s2, 'HARD LAVA: nuk ka kthim — mbet i detonuar');
}

/* --- 5: manual detonate me trigër specifik --- */
{
  let fired = null;
  const hl = new HardLava({ threshold: 999, onWipe: (ev) => { fired = ev; } });
  hl.detonate('integrity-check-boot');
  ok(fired && /integrity-check-boot/.test(fired.detail), 'HARD LAVA: detonate manual regjistron shkaktarin');
}

/* --- 6: threshold i ulët = çdo signal kritik shpërthejë --- */
{
  let fired = false;
  const hl = new HardLava({ threshold: 25, onWipe: () => { fired = true; } });
  hl.reportDebugger(); // 30 >= 25
  ok(fired === true, 'HARD LAVA: një signal i vetëm mjafton kur pragu është i ulët');
}

console.log(`\n========== HARD LAVA: ${pass}/${pass + fail} PASS ==========`);
process.exit(fail ? 1 : 0);
