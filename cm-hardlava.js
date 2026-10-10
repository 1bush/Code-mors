/**
 * CODE MORS — cm-hardlava.js v1 (HARD LAVA — autonomous self-destruct)
 * ---------------------------------------------------------------------
 * Shtresë mbi Sentinel: kur aplikacioni SHEH që dikush mundohet të
 * kopjojë kodin / të debug-ojë / të injektojë (anomali), drejtpërdrejt
 * pastron çelësat NË MEMORI dhe vriste vetë aplikacionin + ruajtjen —
 * pa prisje, pa konfirmim. Emer: "HARDened Lethal Autonomous VAult
 * Annihilation".
 *
 * SI VETËM DETEKTOHET (heuristika + integritet):
 *   [HL1] CODE SWAP      — funksion kritik i ndryshëm (monkey-patch / injection)
 *   [HL2] DEBUGGER       — debugger timing trap / devtools heuristika
 *   [HL3] SOURCE EXFIL   — burimi i app-it tërhequr nga origin i panjohur
 *   [HL4] DYNAMIC EVAL   — eval/injection në kontekstin e app-it
 *   [HL5] INTEGRITY      — SRI/manifest hash nuk përputhet (build i vjedhur)
 *
 * REAGIMI (pa kthim): zeroize çelësat (Uint8Array.fill(0)) → wipe storage
 * (localStorage/session/IndexedDB) → fshi Service Worker + cache → KILL.
 *
 * KUFIZ TË SINQERTË: në JS "zeroize" është best-effort (GC mund të ketë
 * kopjuar). Kundra spyware-it në nivel OS mbrohet OS-i + DeepGuard native.
 * Kjo shtresë rrit shumë koston e një sulmi "kopjo kodin / rrëmbej çelësat
 * nga një sesion debug", nuk e bën të pamundshëm.
 */

'use strict';
const crypto = require('crypto');

/** Zeroize best-effort: mbishkruaj një Uint8Array me zero. */
function zeroize(buf) {
  if (buf instanceof Uint8Array) { buf.fill(0); return true; }
  if (ArrayBuffer.isView(buf) && buf.buffer instanceof ArrayBuffer) {
    new Uint8Array(buf.buffer).fill(0); return true;
  }
  return false;
}

/** Fingerprint SHA-256 i burimit të një funksioni (zbulon monkey-patch). */
function fnDigest(fn) {
  return crypto.createHash('sha256').update(String(fn)).digest('hex');
}

class HardLava {
  constructor(opts = {}) {
    this.armed = opts.armed !== false;   // i armatur nga fillimi
    this.threshold = opts.threshold ?? 50;
    this.hitWeight = opts.hitWeight ?? 25;
    this.onLava = opts.onLava || (() => {});   // thirret kur shpëthet (përshkallëzim)
    this.onWipe = opts.onWipe || (() => {});   // orchestrator i pastrimit (injektuar)
    this.pins = new Map();               // name -> digest i funksionit kritik
    this.score = 0;
    this.detonated = false;
    this.log = [];
  }

  _record(code, detail) {
    const ev = { ts: Date.now(), code, detail, score: this.score };
    this.log.push(ev);
    return ev;
  }

  _hit(code, detail, weight) {
    if (this.detonated) return false;   // i shpërthur: sinjalet e mëvonshëm injorohen
    this.score += (weight == null ? this.hitWeight : weight);
    this._record(code, detail);
    if (this.armed && !this.detonated && this.score >= this.threshold) {
      this.detonate(code);
    }
    return false;
  }

  /* ---- HL1: integriteti i funksioneve kritike ---- */
  pin(name, fn) { this.pins.set(name, fnDigest(fn)); return true; }
  verify(name, fn) {
    const base = this.pins.get(name);
    if (!base) return true;                       // i pa-pin-uar: nuk verifikohet
    if (fnDigest(fn) !== base) {
      return this._hit('HL1_CODE_SWAP', `funksioni '${name}' u ndryshua (monkey-patch/injection)`, 40);
    }
    return true;
  }

  /* ---- HL2: debugger / devtools ---- */
  reportDebugger(detail = 'debugger timing trap') {
    return this._hit('HL2_DEBUGGER', detail, 30);
  }

  /* ---- HL3: exfil i burimit ---- */
  reportSourceFetch(origin, detail = 'burimi i app-it tërhequr nga origin i panjohur') {
    return this._hit('HL3_SOURCE_EXFIL', `${detail} [${origin}]`, 35);
  }

  /* ---- HL4: eval / injeksion dinamike ---- */
  reportDynamicEval(detail = 'eval/injection në kontekstin e app-it') {
    return this._hit('HL4_DYNAMIC_EVAL', detail, 35);
  }

  /* ---- HL5: build/SRI hash ---- */
  verifyIntegrity(expectedHash, actualHash, label = 'build') {
    if (expectedHash && actualHash && expectedHash !== actualHash) {
      return this._hit('HL5_INTEGRITY', `${label} hash nuk përputhet (build i vjedhur/modifikuar)`, 50);
    }
    return true;
  }

  /** Shpërthim: zeroize + wipe + kill. Pa kthim. */
  detonate(trigger = 'manual') {
    if (this.detonated) return;
    this.detonated = true;
    const ev = this._record('HARD_LAVA_DETONATION', `shkaktar: ${trigger} | score=${this.score}`);
    // 1) zeroize + wipe + kill përmes orchestrator-it të injektuar
    try { this.onWipe(ev); } catch (e) { /* pastrimi nuk e ndalon shpërthimin */ }
    // 2) sinjal për UI/alarm
    try { this.onLava(ev); } catch (e) {}
    return ev;
  }

  status() {
    return { armed: this.armed, detonated: this.detonated, score: this.score, hits: this.log.length };
  }

  reset() { this.score = 0; this.detonated = false; this.log = []; }
}

module.exports = { HardLava, zeroize, fnDigest };
