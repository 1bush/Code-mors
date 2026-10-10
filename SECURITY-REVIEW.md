# CODE MORS — Rishikim Sigurie & Ide për Zhvillim

_Data: 2026-10-11 · Teste: 60/60 PASS (Hybrid 13, Sentinel 12, Pairing 7, App-flow 8, PQ 7, Threshold 13)_

## Përmbledhje
Kriptografia është **reale dhe e verifikuar**: ML-KEM-768 (noble), Double Ratchet mbi WebCrypto,
AES-256-GCM, Shamir GF(256) + RBSR. Serveri ruan vetëm SHA-256 hash + ciphertext. Sentinel
zbulon tamper/replay/rollback. XSS është i mbrojtur (`esc()` në të dyja build-et).
Më poshtë: vrima reale (të renditura) + ide për ta bërë top-tier.

---

## 🔴 Vrima reale (të renditura sipas rrezikut)

### 1. Relay — pa rate-limit / krijim i pakufizuar i radhëve (MEDIUM, DoS)
`POST /v1/queue` krijon radhë pa auth, pa limit per-IP, pa kap total radhësh.
Sweeper heq vetëm radhë bosh pas 7 ditë. Sulm: memory-exhaustion me spam radhësh.
**Fix:** kap total radhësh (p.sh. 50k) + rate-limit per-IP (p.sh. 10/min) + sweep idle 1h.

### 2. Relay — krahasim token-i jo constant-time (LOW)
`q.pushHash !== hashToken(pushToken)` — timing side-channel. Token-at është 192-bit random
(brute-force i pamundur), por për defense-in-depth:
**Fix:** `crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))` në `pushMessage`/`pullMessages`.

### 3. Relay — pull token në query string GET (LOW)
`GET /v1/queue/:id/msg?token=...` — token-at bie në access-logs / referer / history.
Push tashmë pranon header `x-push-token`; pull vetëm query.
**Fix:** prano `x-pull-token` header (e barabartë me push).

### 4. Relay — `access-control-allow-origin: *` (LOW/INFO)
Çdo origin web mund të drejtojë relay. Me token high-entropy rreziku i kufizuar, por
kombinuar me #3 një faqe e keqja mund të ekfiltrojë token nëse e kap.
**Fix:** kufizo origin-at e njohur, ose dokumentoje qartë si "relay publik pa sekret".

### 5. `libs/mlkem.mjs` — vendored pa integrity pin (LOW-MEDIUM, supply-chain)
I marrë nga esm.sh/mlkem@2.7.0, pa SRI/commit-hash. Rizvendoring = rrisk injektimi.
**Fix:** regjistro commit/burimin + shto integrity check në CI.

### 6. Double Ratchet custom — pa audit të pavarur (INFO / inherent)
Kodi e pranon ndermisht (threshold.mjs). Është rreziku më i madh kriptografik por jo "bug".
**Fix (strategjik):** migro te X3DH + libsignal për audit të pavarur, ose financo audit formal.

---

## ✅ Verifikuar OK (jo vrima)
- **XSS:** `esc()` (textContent→innerHTML në index; regex-replace në v4) — mesazhet/emrat escape-on.
- **Body cap:** 128KB limit në `msg` dhe `invite` endpoints (`req.destroy()` mbi kap).
- **Input validation:** `pub` (base64 88-char) + `ghost` (regex) të validuara në `/v1/invite/:id/claim`.
- **Server storage:** vetëm SHA-256 hash + ciphertext — zero plaintext/çelës.
- **AEAD:** AES-256-GCM IV random 12B, tag 128 — autentifikim integriteti.
- **Sentinel:** tamper/replay/rollback/fingerprint + panic wipe — 12/12.
- **PQ hybrid + RBSR + Shamir:** 20/20, madhësitë ML-KEM-768 sakta (pk 1184 / sk 2400 / ct 1088).

---

## 💡 Ide për ta bërë një nga më të mirat

### Siguri (prioritet)
1. **Rate-limit + anti-spam relay** (zgjidh #1) — pa këtë, relay-i është i ekspozuar ndaj DoS.
2. **Message-key skipping cache** — Double Ratchet aktual kërkon mesazhe radhës; out-of-order
   (rrjet i përzier) dështon. Signal ruan skipped keys. Rrit besueshmërinë në LAN të dobët.
3. **Build-e të riprodhueshme + APK e nënshkruar** — ke `certs/`; shto checksum publik që
   përdoruesi ta verifikojë (anti-tamper i instalimit).
4. **Repin mlkem** me commit-hash + SRI (zgjidh #5).

### Produkt / UX
5. **Safety-number re-verification** — ke VERIFY; bëje UI që ri-detekton ndryshimin e numrit
   (MITM i vërtetë) me alert të qartë, jo vetëm shfaqje statike.
6. **Sealed-sender i plotë** — Ghost Noise ekziston; shto konstante trafiqe (fixed-size padding
   + decoy intervals) që të mburojë edhe timing-analysis, jo vetëm size.
7. **Multi-device me PCS** (Post-Compromise Security) — sinkronizo sesionin ndërmjet telefonit
   dhe desktop-it pa humbur forward-secrecy (Signal PCS / device-transfer QR).
8. **Deniable metadata** — Deniable Vault ekziston; shto "fake chat" realisik që hapet me
   duress-PIN të dytë (duress vs panic të ndarë).

### Operacion
9. **Relay HA + metrics** — health endpoint + Prometheus counters (radhë aktive, memory) për
   monitorim DoS.
10. **Threat-model i publik i azhurnuar** — dokument/i ke; shto version + "audited by" kur/
    nëse financohet audit (rrit besimin për një security-app).

---

## Rekomandim i menjëhershëm
Fillo me **#1 (rate-limit relay)** dhe **#2 (timingSafeEqual)** — janë diff-e të vogla,
rrezik i lartë (DoS) / defense-in-depth. Testet ekzistuese (test-hybrid) mbulojnë regresionin.
