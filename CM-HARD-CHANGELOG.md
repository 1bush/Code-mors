# CODE MORS — CM-HARD CHANGELOG (v5.3 i konsoliduar)
# E gjitha arma e sigurisë në NJË FILE:
# v5 (bazë) + v5.1 + v5.2 + v5.3

> Të gjitha ndryshimet e CM-HARD — nga versioni bazë deri tek v5.3, të bashkuara në një dokument të vetëm.

---

## 🧬 v5 — Shtresa bazë (7 veçori unike)

Shtatë veçori unike sigurie mbi protokollin ekzistues (ECDH P-256 + Double Ratchet + AES-256-GCM). Asnjë mesazher tjetër nuk i ka të gjitha bashkë.

:

| # | Veçoria | Çfarë sulmi zmbraps | PWA (v4.html) | Native Java |
|---|---|---|---|---|
| 1 | **Ghost Noise** 🫥 | Timing/traffic analysis — vëzhguesi nuk dallon kur dërgohet mesazh real | `toggleGhostNoise()` — butoni 👻 | `GhostNoise.java` (auto ON në chat) |
| 2 | **Duress PIN** 🔫 | Detyrim fizik (coercion) — PIN-i dytësor fshin çelësat menjëherë | `setupDuress(pin)` — butoni 🔫 | `Duress.java` |
| 3 | **Whisper Zeroize** 🧠 | Memory forensics — materiali i çelësave/plaintextit zeroizohet pas përdorimit | `zeroize()` në burn/decrypt paths | `Crypto.zeroize()` |
| 4 | **Time-Lock Pairing (TLP)** ⏳ | Kopjimi i QR nga foto/video — QR-i mbrohet me PBKDF2(600k)+AES-GCM | butoni ⏳ | (për shtuar) |
| 5 | **Rotating Epoch** 🎭 | Correlation afatgjatë — çelësat e kanalit riduhen me HKDF çdo 100 mesazhe / buton 🎭 | `rotateEpoch()` | `Crypto.epochKey()` |
| 6 | **Deniable Vault (Snowden)** ❄️ | Inspektim fizik — të dhënat vulosen me passphrase, mbetet decoy; s'ka provë se biseda ekziston | butoni ❄️ | `DeniableStore.java` |
| 7 | **Optical v2** 📡 | Çdo transfer optik me çelës HKDF per-transfer nga zinxhir i ratchet-uar (`CMO2` frames) | automatik | (PWA only) |

**Përdorimi (PWA):** 👻 Ghost Noise · ⏳ TLP · 🎭 Epoch · 🔫 Duress · ❄️ Snowden.

**Kufij të sinqertë:** TLP kërkon marrëveshje passphrase-je; Vault varet nga forca e passphrase-it; device i kompromentuar lexon çdo gjë në ekran; Optical v2 kërkon sess të palidhur.



---
<!--PLACEHOLDER_V51-->

## 🆕 v5.1 — Deep-hardening (PRM + GrapheneOS + Briar)

### ⛔ PRM — Pegasus Resistance Module (Anti-hacking / vetë-mbrojtje)

Zbulim mjedisi + politikë e zbatimit kundra instrumentimit ( jailbreak/emulator/malware)..) Kufizat e sinqerta: PRM zbulon shenjat e MJEDISIT të komprometuar — nuk mund ta ndalojë një 0-click exploit; qëllimi: refuzo operacionet dhe fshi çelësat para se të ekspozohen.:

| Dosja | Çfarë bën |
|---|---|
| `PrmCheck.java` | **Scanner mjedisi**: ROOT(su paths, magisk, root apps), ADB, emulator(Build heuristics), SELinux permissive, test-keys, debuggable). Risk  0–100 |
| `PrmGuard.java` | **Anti-instrumentation**: debugger + TracerPid, Frida(port 27042, /data/local/tmp, /proc/self/maps)ir, Xposed/Substrate(Class.forName, libs, stack trace), signature verification(tamper APK) |
| `PrmPolicy.java` | **Politika**: score≥35 lockdown operacionesh; score≥60 self-destruct në  3s; counter PIN → fshirje pas  5 tentativash |
| `code-mors-v4.html` | `prmAssess()`: WEBDRIVER, EMULATOR_UA, FRIDA_LIKE, HTTP_INSECURE(PWA light; butoni ⛔ — report risk) |
| `MainActivity.java` | `PrmPolicy.gate(this)` në `onCreate` + para çdo hapjeje kanali |

### 🧩 Ide të përshtatura nga GrapheneOS + Briar + Signal
| Burimi | Koncepti | Implementimi |
|---|---|---|
| GrapheneOS | **PIN Scrambling** | Tastierë e kyçjes me shifra random (Fisher–Yates, RNG kriptografik) — kundër shoulder-surfing & smudge |
|---|---|---|
| GrapheneOS | **Auto Reboot / Clear memory** | **Auto-Lock**: pas N minutash inaktiviteti (butoni 🔒) app vuloset, plaintext-i zeroizohet nga RAM |
|---|---|---|
| Briar | **Panic App integration** | **Panic Gesture**: 7 klikime të shpejta mbi Ghost Name → nuclear wipe |
|---|---|---|
| GrapheneOS | **Duress PIN** | Konfirmuar best-practice — e implementuar |
|---|---|---|
| Signal | **PQXDH / hybrid post-quantum** | Roadmap: ML-KEM (Kyber) — kërkon KEM të vërtetë, stub `kyber.js` bosh. |

---
<!--PLACEHOLDER_V52-->

## 🆕 v5.2 — Research i thelluar (Signal, SimpleX, Tinfoil, Briar)

Pas kërkimit të krahasuar të aplikacioneve më të mirë të sigurt, shtova 3 veçori e reja:

| Veçoria | Burimi | Implementimi |
|---|---|---|
| **ENCRYPTED BACKUP / RESTORE** (CODE RECOVERY) | SimpleX | Butonat `BK`/`RS`: e gjithë gjendja (kontakte+çelësa+mesazhe) vuloset me passphrase(PBKDF2-SHA512, 600k) në skedar `code-mors-recovery.cmrec` (salt+IV+ciphertext.) Restore me passphrase. |
| **INCOGNITO KEYBOARD** | Signal | `cmhIncognitoKeys()`: çaktivizon autocomplete, autocorrect, capitalize, spellcheck — s'mbetet gjurmë te tastiera e sistemit(OEM) |
| **LOCAL-ONLY MODE** | SimpleX | Butoni `LO`: toggle për izolim të plotë rrjeti, me badge vizuel në statusbar. |

**E konfirmuar në këtë version:** Double Ratchet ✅ · Safety Numbers ✅ · Ghost Noise (=SimpleX decoy queues) ✅ · Panic gesture (=Briar panic button) ✅ · Duress PIN ✅ · deniability ✅ · Post-quantum (ML-KEM) roadmap.

---
<!--PLACEHOLDER_V53-->

## 🛡️ v5.3 — DeepGuard (Anti-tamper / Anti-duplicate) + Tor Roadmap

### 🔐 DeepGuard — vetë-mbrojtje kundra RIPAKETIMIT/DUPLIKIMIT
`DeepGuard.java` (e re native): kur app-i instalohet, llogarit **hash-e SHA-256 për çdo entry** (dex, resources, manifest, cert) dhe i ruan në Keystore. Në **çdo hapje + kanal**, ri-verifikon; nëse një hash mospërputhet (APK i ndryshuar ose i duplikuar me kod të shtuar) → **`panicWipe` self-destruct** i menjëhershëm. **Ky është përgjigja e "kur mundohen ta hackerojnë → wipe ose mbylle"**:

| Mbrojtja | Çfarë bën |
|---|---|
| Tampering i APK-së | RIPAKETA me kod të shtuar/trojan → hash-et nuk përputhen → gjithçka fshihet. |
| Duplikimi | Kopje e modifikuar → e njëjta logjikë. |
| Re-verifikimi | Ri-skanon në çdo hapje kanali, jo vetëm nisje. |
| `MainActivity.java` | `DeepGuard.verify(this)` në `onCreate` + para çdo hapjeje kanali (bashkë me PRM). |

### 🌐 Tor — Roadmap i qartë (opsion, jo default)
Tor-i e fsheh IP-në dhe e bën trafikun invizible, por:
- APK-të standard Android nuk mund të përdorin Tor-in në nivel OS-i (kërkon **Orbot** + proxy)).
- Integrim si opsion në CodeMors: `PROXY_SOCKET` me `127.0.0.1:9050` (Orbot listener)).
- **Rrezik sigurie**: nëse lidhja e Tor-it bëhet keq(DNS leak, transport i pasigurt)të gjitha mbrojtjet mund të bien). → **duhet testim përpara aktivizimit**, prandaj opsion i dokumentuar, jo default.

---
<!--PLACEHOLDER_FINAL-->

## 📦 Përmbledhja FINALE — e gjithë arma e CodeMors

| Shtresa | Versioni | Çfarë mbron |
|---|---|---|
| Crypto bazë | v5 | ECDH P-256 + Double Ratchet + AES-256-GCM + Safety Numbers |
| Ghost Noise | v5 | Traffic analysis (decoy i padallueshëm) |
| Duress + Vault + TLP + Epoch + Optical v2 | v5 | coercion / inspektim fizik / QR kopjim / correlation / offline |
| PRM (PrmCheck/PrmGuard/PrmPolicy) | v5.1 | Anti-hacking(root/Frida/Xposed/emulator) → lockdown ose self-destruct |
| Scrambled keypad + Auto-lock + Panic gesture | v5.1 | Shoulder-surfing / memory / coercion |
| Code Recovery + Incognito keyboard + Local-only | v5.2 | Backup i sigurt / OEM keyboard leakage / network isolation |
| **DeepGuard** | **v5.3** | **Anti-tamper / anti-duplicate → vetë-shkatërrim menjehere** |

**⚠️ E vërteta e sinqertë (e vlefshme për të gjitha versionet):** asnjë software nuk është 100% e pathyeshme; një device me root/malware lexon çdo gjë që shfaqet në ekran. Kjo armë e bën eksploatimin **dukshëm më të vështirë dhe të paguar** (çelësat fshihen përpara se të ekspozohen).)

**Build:** `cd android-native && ./gradlew assembleDebug` — klasat e reja pa varësi të reja, vetëm JCE + Android framework.