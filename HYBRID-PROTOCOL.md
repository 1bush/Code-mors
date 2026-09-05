# CODE MORS — GHOST RELAY v1 (Code-Mors Ratchet Relay) — Hybrid Protocol

> **Ndryshe nga çdo gjë tjetër e njohur:** kombinon modelin e serverit *SMP
> relay* (radhë njëdrejtimëshe pa identifikues — nga SimpleX) me *Double
> Ratchet* (forward secrecy / break-in recovery — nga Signal), dhe i shton një
> shtresë të re që asnjëri nuk e ka: **Ratchet-Bound Queue Rotation (RBQR)** —
> ku token-i që i lejon serverit të pranojë/dorëzojë një mesazh rrjedh nga
> gjendja e zinxhirit të ratchet-ut. Në këtë mënyrë edhe **metadata e radhës
> ka forward secrecy**, jo vetëm përmbajtja e mesazhit.

---

## Pse hibridi

| Cilësi | SMP relay (SimpleX) | Double Ratchet (Signal) | **GHOST RELAY v1 (hibrid)** |
|---|---|---|---|
| Dorëzim në offline (store-and-forward) | ✅ | ❌ | ✅ |
| Pa identifikues përdoruesi | ✅ | ❌ (ka identitete) | ✅ |
| Forward secrecy e përmbajtjes | ❌ (vetëm transport) | ✅ | ✅ |
| Break-in recovery | ❌ | ✅ | ✅ |
| Forward secrecy e **metadata-s së radhës** | ❌ (radhë statike) | ❌ | ✅ (**RBQR**) |
| Radhë të verbëruara (blinded queues) | Pjesshëm | ❌ | ✅ |

---

## Arkitektura

```
  Alice (PWA/Java)                 Relay (Node, dependency-free)              Bob
      |                                      |                                |
      | 1. ECDH P-256 out-of-band (QR)       |                                |
      |------------------------------------->|-------------------------------->|
      |  (ndajnë publikun → root RK)         |                                |
      |                                      |                                |
      | 2. POST /v1/queue  (push A→B)        |                                |
      |------------------------------------->|  krijon radhë, kthen           |
      |   pushToken_A, queueId_AB            |  token-a (hash-e në server)    |
      |<-------------------------------------|                                |
      | 3. Bob POST /v1/queue (push B→A)     |                                |
      |<-------------------------------------|  queueId_BA, pushToken_B       |
      |                                      |                                |
      | 4. Alice ratchetEncrypt(m)           |  vetëm ciphertext+padding      |
      |    POST /v1/queue/AB/msg             |                                |
      |------------------------------------->|  ruan blob opak + seq          |
      | 5. Bob GET /v1/queue/AB/msg?token=   |                                |
      |<-------------------------------------|  kthen blob-et + seq           |
      |    Bob ratchetDecrypt(blob) → m      |                                |
      | 6. SI MASHTI: secili side derivon    |  RBQR: token-i rrotullohet     |
      |    pullToken_n = HMAC(RK,"RR|"+n)    |  sipas ratchet ✓; token-i vjetër |
      |------------------------------------->|  REFUZOET ✓                    |
```

Pikat kyçe:
- **Dy radhë njëdrejtimëshe** për lidhje (A→B dhe B→A), ashtu si SMP.
- **Serveri nuk di kush komunikon me kë**: ruaj vetëm `queueId` të rastësishëm,
  **hash-e SHA-256 të token-ave** (jo plaintext), dhe blob-e opake (të koduara
  nga klienti). S'ka llogari, s'ka IP-logging të detyrueshëm, s'ka identifikues.
- **Content E2E** nga Double Ratchet i plotë (zinxhirë të veçantë dërgim/pranim +
  DH-ratchet periodik për break-in recovery).
- **RBQR** — risia: token-i pranimit/dorëzimit rrjedh nga gjendja e ratchet-ut;
  pasi konsumohet, token-i i vjetër është i pavlefshëm. Serveri i komprometuar
  në kohën t nuk mund të lidhë/lexojë as token-at e kaluar.

---

## Shtresa kriptografike

| Shtresë | Algoritëm |
|---|---|
| Qësh e çelësave (key agreement) | **ECDH P-256** + HKDF-SHA256 → Root Key (RK) |
| Forward secrecy per-message | **Double Ratchet**: `CK_s` / `CK_r`, përparojnë me HMAC-SHA256 |
|S Hamnik mssä ke | HMACSHA256 per-message → **AES-256-GCM** (IV 12B) |
| Padding / traffic| padding bllok 256B-4KB, bllok i fiksuar |
| Mitm | Safety Number = SHA-512(preitur çelës publik), krahasim ball për ball |
| RBQR token derivim | `token_n = HMAC-SHA256(RK, "GHOST-RELAY-token" ‖ n)` |
| Header ratchet | version, chainIdx, (DH pub nëse ratchet) |

> **Kujdes i sinqertë:** ky është protokoll i ri, i pareviewer nga ekspertë
> kriptografikë ashtu si Double Ratchet i SimpleX/Signal (Trail of Bits). Për
> përdorim real duhet auditim i pavarur. Cili është qëllimi: prototip i
> fuqishtë e i kombinueshëm që mund të verifikohet në mënyrë lokale (test-e2e).

---

## Përdorimi

```
# 1. Nis relay
node relay/server.js --port 7000

# 2. Test e2e (Alisë↔Bob përmes relay + RBQR)
node test-hybrid.js
```

## Qëlllueshëm
- **`relay/server.js`** — server SMP-stil (module, mund t³ importohet ose niset)
- **`cm-protocol.js`** — klient kripto (WebCrypto) me Double Ratchet + RBQR
- **`test-hybrid.js`** — verifikim e2e end-to-end (encript/decript, RBQR, privacy)