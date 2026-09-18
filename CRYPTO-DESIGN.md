# CODE MORS — Dizajn kriptografik: pse jo "3 çelësa në server", dhe çfarë ndërtojmë në vend

**Data:** 18 shtator 2026 · **Statusi:** dokument dizajni + regjistër provash. Nuk është auditim sigurie.

---

## 1. Pyetja: a mund të bëhet kriptimi me 4 çelësa?

> *"1 çelës në secilin telefon, 3 në server, dhe i 4-ti i ndarë në 2 pjesë — pa njërin dhe tjetrin nuk dekriptohet."*

Përgjigja e sinqertë, në dy pjesë:

**A) Si ide e përgjithshme — jo.** Nëse serveri mban 3 nga 4 çelësat, atëherë:

| Pasoja | Pse |
|---|---|
| **E2EE humbet** | Serveri (ose kushdo që e komprometon, e sekuestron ose merr urdhër ligjor) ka pjesën më të madhe të sekretit → mund të dekriptojë. Ky quhet *kriptim me server të besuar*, jo *end-to-end*. |
| **Prish modelin e kërcënimit** | Code Mors është ndërtuar mbi parimin "relay-i nuk di asgjë": ruan vetëm hash-e token-ash dhe blob-e ciphertext. Vendosja e çelësave në server e kthen relay-in në *pikën më të dobët*. |
| **Prish deniability** | Pa çelësa në server, të dyja palët mund të mohojnë transkriptin (MAC simetrik). Me çelësa serveri krijohet një dëshmitar i tretë që mund të prodhojë prova. |
| **Shtim kompleksiteti = ulje sigurie** | Historia e kripto-kuletave (SSS i keqpërdorur) tregon raste ku "më shumë çelësa" e uli sigurinë në praktikë. |

**B) Si intuitë — po, dhe ka një mënyrë të saktë.** Ajo që kërkon (askush i vetëm të mos dekriptojë) arrihet me **SHARE, jo me çelësa të plotë**:

1. **Ndarje sekreti (Shamir/threshold) — 2-of-2 midis telefonave.** Asnjë telefon nuk mban çelësin; secili mban një share. Bashkimi bëhet vetëm në RAM, vetëm për atë sesion. Nën prag, informacioni është **zero** (perfect secrecy, informacion-teorikisht i sigurt).
2. **Në server: asnjë çelës, as share i dobishëm.** Forma e vetme e shëndoshë është ajo që kemi: ai ruan *ciphertext + hash-e token-ash*, dhe opsionalisht një *certifikatë anonimiteti* për rate-limiting (modeli Sealed Sender).
3. **Çelësi i 4-t i ndarë: ky është hapi i saktë** — por jo "gjysma në telefon, gjysma në server", sepse serveri do t'i bashkojë. Ndarja e mirë shtë **midis pajisjeve/ruajtjeve që s'komunikojnë automatikisht** (share i dytë në QR/letër, ose pajisje e dytë), dhe **i fshehur si share**, jo si gjysmë çelësi (gjysma e një çelësi simetrik nuk mbron asgjë).

**Përfundim:** kriptimi "me 4 çelësa" me çelësa në server nuk është më i fortë se Signal i sotëm — është më i dobët. E forta e vërtetë vjen nga **forward secrecy + ratchet + PQ hibrid + pa besim në server**.

---

## 2. Çfarë është "më e forta në botë" sot (me burime)

| Sistemi | Çfarë shton | Statusi |
|---|---|---|
| **Signal PQXDH** | Hibrid X25519 + ML-KEM-768 në handshake fillestar; forward secrecy post-kuantike, deniability; i analizuar formalisht (ProVerif/CryptoVerif) | Në prodhim ([spec](https://signal.org/docs/specifications/pqxdh/)) |
| **Apple iMessage PQ3** | "Level 3": PQ në hyrje **dhe** PQ-ratchet i vazhdueshëm (3 ratchet për vetë-shërim; rekyç ~çdo 50 mesazhe), **firma ECDSA P-256 nga Secure Enclave** për çdo mesazh | Në prodhim; Apple e quan "vetitë më të forta në shkallë botërore" ([blog](https://security.apple.com/blog/imessage-pq3/)) |
| **Triple Ratchet** (Eurocrypt 2025) | Kodet e fshirjes + KEM-i i re "Katana" (1416B vs 2272B) → PQ-ratchet me kosto të balancuar komunikimi; Signal po e vlerëson | Punim akademik ([ePrint 2025/078](https://eprint.iacr.org/2025/078)) |
| **MLS (RFC 9420)** | Kriptim grupi me pemë + forward secrecy/PCS për grupe deri në mijëra anëtarë | Standard IETF ([RFC 9420](https://datatracker.ietf.org/doc/rfc9420/)) |
| **Sealed Sender (Signal)** | Fsheh *kush i dërgon kujt*: certifikatë afatshkurtër + delivery token i nxjerrë nga profile key | Në prodhim ([blog](https://signal.org/blog/sealed-sender/)) |
| **Shamir / threshold** | Ndarje me siguri informacion-teorikisht të plotë nën prag; bazë për MPC | Klasik ([Wikipedia](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing)) |

## 3. Çfarë u ndërtua në Code Mors (18 shtator 2026) — me prova

### 3.1 PQ HARDENING (ML-KEM-768 hibrid) — ✅ e provuar E2E
- `libs/mlkem.mjs` (v2.7.0, TS i pastër, testuar me KAT-et e NIST/ML-KEM; pk 1184B, sk 2400B, ct 1088B).
- Rrjedha: pas `connect`, ftesëdhënësi enkapsulon (ML-KEM) drejt claimuesit → dërgon ciphertext-in **brenda kanalit E2EE ekzistues** (`{type:'pq',ct}`) → të dyja anët bëjnë `rk' = HKDF(rk ‖ ssPQ, 'GHOST-PQ-v1-hybrid')` për `new` dhe `inr`.
- Mesazhet gjatë handshake-ut **radhiten** dhe dërgohen automatikisht (pa humbje).
- Prova: `npm run test:pq` → **7/7**; diagnostika në browser real → A: `[PQ] upgrade derguar`, B: `[PQ] kanal hibrid aktiv (ML-KEM-768)`, mesazhi u dorëzua; E2E `tools/test_pairing_browser.py` → **4/4 PASS** (round-trip A→B→A, zero gabime JS).
- **Niveli i arritur = PQXDH-i i Signal-it** (PQ vetëm në hyrje), *jo* PQ3-i i Apple-it (PQ-ratchet i vazhdueshëm).

### 3.2 MEMORY WIPE ON CLOSE — ✅ (vetëm web tani)
- `pagehide` → zeroize i `S.myPQsk` + `panicWipe('close')` (fshin çelësat, kontaktet, gjendjen, `localStorage`/`sessionStorage`).
- Butoni në Settings: **WIPE ON CLOSE** (i ndezur by default; `cm_woc` ruhet për ta respektuar).
- Kufizim i sinqertë: JS nuk garanton zeroizim fizik të memories (GC/kopje); reduktim gjurmësh, jo fshirje forensike e garantuar.
- Android native: **e pabërë ende** (hapi tjetër).

### 3.3 THRESHOLD + RBSR — ✅ primitiva e re, e testuar (jo ende e lidhur në chat)
`libs/threshold.mjs`: Shamir mbi GF(256) + **RBSR (Ratchet-Bound Share Rotation)**:
```
y'_i = y_i XOR HKDF(ratchetKey, 'CM-RBSR-v1|epoch=k')
```
- Të dyja anët e nxjerrin mask-in **lokalisht** nga gjendja e ratchet-ut (pa komunikim shtesë).
- Një share i vjedhur në epokën *k* nuk ndihmon në epokën *k+1* (mask-i vjen vetëm nga ratchet-i → forward secrecy).
- Përzierja e share-ve të epokave të ndryshme nuk rikonstrukton asgjë.
- Prova: `npm run test:threshold` → **13/13** (2-of-2, 3-of-5 me të gjitha 10 kombinimet, asnjë çift 2-share nuk del sekreti, mask determinist, refuzim i epokave të përziera, transporti b64).
- **Sa dimë**, kombinimi "share Shamir të rotuara nga gjendja e ratchet-ut" nuk është pjesë e protokolleve të njohura (Signal/SimpleX/PQ3 rotuhen radhë/token-a — RBQR-i i yni — por jo *share*). **Nuk pretendojmë** se është e paprecedentë pa kërkim sistematik literature; pa analizë formale nuk është gati për prodhim.

---

## 4. Rruga përpara (sipas vlerës/riskut)

| # | Hapi | Vlera | Kosto | Shenim |
|---|---|---|---|---|
| 1 | **PQ-ratchet periodik** (jo vetëm një herë): ML-KEM çdo N mesazhe; shqyrto Triple Ratchet/Katana | Kalon PQXDH → PQ3 | E mesme/lartë | 1088B/mesazh; pa kodime fshirjeje, jo i balancuar |
| 2 | **Wipe on close në Android** (zeroize në `onDestroy`/`onTrimMemory`, Store me keystore) | Barazon web/native | E ulët | Kërkon build e test në pajisje |
| 3 | **Key transparency** (log append-only i relay-it + verifikim klienti) | Anti-MITM në pairing | E mesme | Modeli WhatsApp AKD / iMessage CKV |
| 4 | **Sealed-sender style token** për rate-limiting pa identitet | Metadata | E ulët | Relay ruan vetëm hash-e (tashmë) |
| 5 | **Lidhja e RBSR në sesion** (share 2-of-2 për root-in, rotacion çdo epokë) | Plotëson idenë "4 çelësa" në mënyrë të sigurt | E lartë | Kërkon teste desinkronizimi + analizë |
| 6 | **Skipped-message keys** (mesazhet e humbura) | Korrektësi | E mesme | Kufizim i pranuar në README |
| 7 | **Auditim i pavarur** | Besueshmëri | E lartë | Pa të, "military-grade" mbetet marketing |

---

## 5. Kufizime që nuk duhen fshehur
1. **Pa auditim kriptografik të pavarur.** Konstruksionet e reja (RBQR, RBSR, PQ-upgrade) janë vetëm të testuara funksionalisht.
2. **PQ vetëm në hyrje**, jo PQ-ratchet. (AES-GCM 256 mbetet i sigurt kundër kuantikëve; pika e vetme PQ është handshake-u.)
3. **Relay në RAM** (pa persistim); rikuperim idempotent i claim-it të humbur mungon.
4. **Zeroizimi në JS** nuk shtë garanci fizike.
5. **Kamera/Share/deep-link** nuk janë provuar në pajisje reale.
6. **RBSR** nuk është e lidhur ende në chat — primitivë e testuar, jo veçori e aktivizuar.

## 6. Komandat e provave
```bash
npm test               # 13/13  GHOST RELAY hybrid + RBQR
npm run test:sentinel  # 12/12  BREACH SENTINEL
npm run test:pairing   # 7/7    rrjedha një-hapi
npm run test:app       # 8/8    app-flow
npm run test:pq        # 7/7    ML-KEM-768 hibrid            <-- e re
npm run test:threshold # 13/13  Shamir + RBSR                <-- e re
npm run test:all       # të gjitha me radhë
python tools/test_pairing_browser.py   # 4/4 browser real (web :5173 + relay :7000)
```
```bash
# nisja lokale
node _serve.js                          # web :5173
node relay/server.js --port 7000 --no-log
```