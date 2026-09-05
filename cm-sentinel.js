/**
 * CODE MORS — cm-sentinel.js v1 (Breach Sentinel)
 * ------------------------------------------------------------------
 * Shtresë detektimi kundër ndërhyrjes (Pegasus/spyware/server i komprometuar).
 *
 * 3 SHTRESA DETEKTIMI:
 *  [S1] CRYPTO BREACH  — dështim AES-GCM (mesazh i ndryshuar / MITM),
 *                        desinkronizim ratchet (spyware po injekton mesazhe),
 *                        ndryshim Safety-Number (këmbim çelësash i dyshimtë).
 *  [S2] RELAY BREACH   — epoch regression (rollback), refuzim token-i,
 *                        replay i seq-t, ndryshim fingerprint-i i relay-it.
 *  [S3] ENV BREACH     — tamper i ruajtjes lokale (checksum), hook për
 *                        DeepGuard/PrmGuard në build-in native.
 *
 * REAGIMI: OK → ⚠️ WARNING → 🚨 BREACH + panic() (zeroize çelësa + wipe).
 *
 * KUFIJ TË SINQERTË: kjo është DETEKTIM + REAGIM, jo imunitet. Spyware në
 * nivel kernel-i (Pegasus) lexon ekranin/çelësat para çdo logjike app —
 * kundër tij mbrohen vetëm OS-i/patch-et (Lockdown Mode, GrapheneOS) +
 * DeepGuard/PrmGuard native që detektojnë tamper pas faktit.
 */

'use strict';
const crypto = require('crypto');

const LEVELS = { 0: 'OK', 1: 'WARNING', 2: 'BREACH' };
const TAGS = { 0: '✅', 1: '⚠️', 2: '🚨' };

class Sentinel {
  constructor(opts = {}) {
    this.thresholdBreach = opts.thresholdBreach ?? 100;
    this.onAlert = opts.onAlert || (() => {});
    this.onPanic = opts.onPanic || (() => {});
    this.score = 0;
    this.level = 0;                 // 0 OK | 1 WARNING | 2 BREACH
    this.events = [];
    this.relayFingerprint = null;
    this.storageChecksum = null;
  }

  _hash(d) { return crypto.createHash('sha256').update(String(d)).digest('hex'); }

  _raise(level, layer, code, detail) {
    const ev = { ts: Date.now(), layer, code, detail, level };
    this.events.push(ev);
    if (level >= this.level) this.level = level;
    this.onAlert({ ...ev, tag: TAGS[level], text: `${TAGS[level]} [${layer}] ${code}: ${detail}` });
    return ev;
  }

  /* ---------- S1: CRYPTO BREACH ---------- */
  reportCryptoFailure(detail) { this.score += 40; return this._raise(2, 'S1-CRYPTO', 'GCM_AUTH_FAIL', detail); }
  reportRatchetDesync(detail) { this.score += 60; return this._raise(2, 'S1-CRYPTO', 'RATCHET_DESYNC', detail); }
  reportSafetyNumberChange(oldSn, newSn) {
    this.score += 80;
    return this._raise(2, 'S1-CRYPTO', 'SAFETY_NUMBER_CHANGED', `old=${oldSn.slice(0, 12)}… new=${newSn.slice(0, 12)}…`);
  }

  /* ---------- S2: RELAY BREACH ---------- */
  learnRelay(relayAddr, queuePrefix) { this.relayFingerprint = this._hash(`${relayAddr}|${queuePrefix}`); return this.relayFingerprint; }
  checkRelay(relayAddr, queuePrefix) {
    const fp = this._hash(`${relayAddr}|${queuePrefix}`);
    if (!this.relayFingerprint) { this.relayFingerprint = fp; return true; }
    if (fp !== this.relayFingerprint) {
      this.score += 70;
      this._raise(2, 'S2-RELAY', 'RELAY_FINGERPRINT_CHANGED', 'server u zëvendësua ose MITM i rrjetit');
      return false;
    }
    return true;
  }
  checkEpoch(currentKnown, serverOffered) {
    if (Number(serverOffered) < Number(currentKnown)) {
      this.score += 50;
      this._raise(2, 'S2-RELAY', 'EPOCH_ROLLBACK', `${serverOffered} < ${currentKnown}`);
      return false;
    }
    return true;
  }
  checkReplay(seq, seenSeqs) {
    if (seenSeqs.has(seq)) {
      this.score += 45;
      this._raise(1, 'S2-RELAY', 'REPLAY_SEQ', `seq=${seq} konsumohet përsëri`);
      return false;
    }
    seenSeqs.add(seq);
    return true;
  }
  reportTokenRejection(detail) { this.score += 35; return this._raise(1, 'S2-RELAY', 'TOKEN_REJECTED', detail); }

  /* ---------- S3: ENV BREACH ---------- */
  learnStorage(stateJson) { this.storageChecksum = this._hash(stateJson); return this.storageChecksum; }
  verifyStorage(stateJson) {
    if (this.storageChecksum === null) return this.learnStorage(stateJson);
    const now = this._hash(stateJson);
    if (now !== this.storageChecksum) {
      this.score += 55;
      this._raise(2, 'S3-ENV', 'STORAGE_TAMPERED', 'gjendja lokale u ndryshua jashtë app-it');
      return false;
    }
    return true;
  }
  reportNativeGuard(guardName, passed, detail = '') {
    if (!passed) {
      this.score += 90;
      this._raise(2, 'S3-ENV', `${guardName}_FAIL`, detail || 'native guard raportoi komprometim');
      return false;
    }
    return true;
  }

  /* ---------- Vlerësim + reagim ---------- */
  evaluate() {
    // ngjarjet e forta (raporte direkte BREACH) mbeten edhe nëse score-i është i ulët
    const computed = this.score >= this.thresholdBreach ? 2 : (this.score > 0 ? 1 : 0);
    const level = Math.max(this.level, computed);
    if (level >= 2 && this.level < 2) {
      this.level = 2;
      this.onAlert({ level: 2, tag: TAGS[2], text: '🚨 BREACH DETECTED — ndërhyrje në sistem! Nis panic wipe.' });
    } else if (level === 1 && this.level < 1) {
      this.level = 1;
    }
    return { level, tag: TAGS[level], text: LEVELS[level], score: this.score };
  }

  /** Butoni BREACH / reagim automatik: zeroize + wipe + alarm. */
  panic(reason = 'manual') {
    const ev = this._raise(2, 'PANIC', 'PANIC_WIPE', `arsyeja: ${reason}`);
    try { this.onPanic(ev); } catch (e) { /* wipe hook s'e ndalon alarmin */ }
    this.score = 0; this.level = 2; // mbetet BREACH derisa app rifillon
    return ev;
  }

  summary() {
    const l = this.evaluate();
    return { ...l, events: this.events.length, log: this.events.slice(-10) };
  }

  reset() { this.score = 0; this.level = 0; this.events = []; }
}

module.exports = { Sentinel, LEVELS, TAGS };