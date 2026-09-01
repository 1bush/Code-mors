# CODE MORS — CM-HARD v5 HARDENING LAYER

Shtatë veçori unike sigurie, të implementuara si shtresë mbi protokollin ekzistues
(ECDH P-256 + Double Ratchet + AES-256-GCM). Asnjë mesazher tjetër nuk i ka të gjitha bashkë.

| # | Veçoria | Çfarë sulmi zmbraps | PWA (v4.html) | Native Java |
|---|---|---|---|---|
| 1 | **Ghost Noise** 🫥 | Timing/traffic analysis — vëzhguesi nuk dallon kur dërgohet mesazh real | `toggleGhostNoise()` — butoni 👻 | `GhostNoise.java` (auto ON në chat) |
| 2 | **Duress PIN** 🔫 | Detyrim fizik (coercion) — PIN-i dytësary fshin çelësat menjëherë | `setupDuress(pin)` — butoni 🔫 | `Duress.java` |
| 3 | **Whisper Zeroize** 🧠 | Memory forensics — materiali i çelësave/plaintextit zeroizohet pas përdorimit | `zeroize()` në burn/decrypt paths | `Crypto.zeroize()` |
| 4 | **Time-Lock Pairing (TLP)** ⏳ | Kopjimi i QR nga foto/video — QR-i mbrohet me PBKDF2(600k)+AES-GCM | butoni ⏳ | (për shtuar) |
| 5 | **Rotating Epoch** 🎭 | Correlation afatgjatë — çelëset e kanalit riduhet me HKDF çdo 100 mesazhe / buton 🎭 | `rotateEpoch()` | `Crypto.epochKey()` |
| 6 | **Deniable Vault (Snowden)** ❄️ | Inspektim fizik — të gjitha të dhënat vulososen me passphrase, mbetet decoy; s'ka provë se biseda ekziston | butoni ❄️ | `DeniableStore.java` |
| 7 | **Optical v2** 📡 | Çdo transfer optik tani me çelës HKDF per-transfer nga zinxhir i ratchet-uar (`CMO2` frames) | automatik | (PWA only) |

## Përdorimi (PWA)
- **👻** — aktivizon/ndalon Ghost Noise (decoy ciphertext i padallueshëm, dërgohet çdo 30–120s random)
- **⏳** — vendos passphrase për QR-in tuaj: pa të, skanimi i QR refuzohet
- **🎭** — riduktim i menjëhershëm i çelësave të kanalit për kontaktin aktual
- **🔫** — vendos Duress PIN; kur futet në ekranin e kyçjes → PANIC WIPE i pakthyeshëm
- **❄️** — Snowden mode: vulos gjendjen, fshin plaintextin, rikthen me passphrase në boot

## Kufij të sinqertë
- TLP kërkon që palët të bien dakord për passphrase me kanal tjetër të sigurt.
- Vault-i varet nga forca e passphrase-it (600k PBKDF2-SHA512 iteracione e bën brute-force praktikisht të pamundur, por passphrase e dobët mbetet dobësi).
- Një device i kompromentuar (malware/root) lexon çdo gjë që shfaqet në ekran — asnjë software s'e zgjidh këtë.
- Optica v2 del me çelësin e fituar nga sess-i i kontaktit; transferimi ndërmjet kontakteve të palidhura mbetet one-shot i vjetër.

## Build native
```
cd android-native
./gradlew assembleDebug
```
Klasat e reja: `GhostNoise.java`, `Duress.java`, `DeniableStore.java` — pa varësi të reja, vetëm JCE + Android framework.
Për Duress UI në native, thirrni `Duress.set(...)` nga një dialog settings dhe `Duress.matches()` + `panicWipe()` në ekranin e kyçjes.

## 🆕 v5.1 — Ide të përshtatura nga projekte military-grade

| Burimi | Koncepti | Implementimi në CodeMors |
|---|---|---|
| GrapheneOS | **PIN Scrambling** | Tastiera e kyçjes me shifra të pozicionuara random (Fisher–Yates me RNG kriptografik) — kundër shoulder-surfing & smudge attacks |
| GrapheneOS | **Auto Reboot / Clear data from memory** | **Auto-Lock**: pas N minutash inaktiviteti (default 5, butoni 🔒) app vuloset dhe plaintext-i i bisedës zeroizohet nga RAM |
| Briar | **Panic App integration** | **Panic Gesture**: 7 klikime të shpejta mbi Ghost Name → nuclear wipe i çelësave të gjithë |
| GrapheneOS | **Duress PIN/Password** | Konfirmuar si best-practice — e implementuar që në v5 (butoni 🔫) |
| Signal | **PQXDH / hybrid post-quantum** | Në roadmap: ML-KEM (Kyber) hybrid në ECDH — kërkon KEM të vërtetë, stub-i libs/kyber.js është bosh |
| Briar | **Offline transports (BT/WiFi-Direct)** | Në roadmap për build-in native; optika QR ekzistuese e mbulon rastin e afërsisë |
## ⚔️ PRM — Pegasus Resistance Module

Zbulim mjedisi + politikë e zbatimit kundra eksploatimit të tipit Pegasus (instrumentation/jailbreak/emulator).) Kufizat e sinqerta: PRM zbulon shenjat e MJEDISIT të komprometuar — nuk mund ta ndalojë një 0-click exploit që tashmë kontrollon OS-in. Qëllimi: refuzo operacionet dhe fshi çelësat në mjedis të dyshimtë, para se të ekspozohen.

| Dosja | Çfarë bën |
|---|---|
| PrmCheck.java | Scanner mjedisi: ROOT(su paths, magisk, root apps), ADB, emulator(Build heuristics), SELinux permissive, test-keys, deploygable. Risk 0–100 |
| PrmGuard.java | Anti-instrumentation: debugger + TracerPid, Frida(port 27042, /data/local/tmp binary, /proc/self/maps)ir, Xposed/Substrate(Class.forName, libs, stack trace), signature verification (tamper APK). |
| PrmPolicy.java | Politika: score≥35 lockdown operacionesh; score≥60 self-destruct në 3s; counter PIN-i i pasuksesshëm→ fshteje pas 5 tentativash |
| code-mors-v4.html | prmAssess(): WEBDRIVER, EMULATOR_UA, FRIDA_LIKE, HTTP_INSECURE (PWA light); butoni ⛔ — report risk |

Aktivizoje në MainActivity: thirre PrmPolicy.gate(this) para se të hapësh çdo kanal/bisedë e PrmPolicy.pinOk()/pinFailed() në ekranin e kyçjes.
## 🔌 Integrimi i PRM-së në UI (native)

I lidhur në MainActivity.java:
- PrmPolicy.gate(this) thirret në onCreate (refuzo aksesin në mjedis të komprometuar) dhe **para çdo hapjeje të kanalit** (click në listë).
- Self-destruct/panic wipe aktivizohet automatikisht në risk ≥60; counter-i i PIN-it fshin pas 5 tentativash të dështuara.

Të gjitha dosjet e reja kanë balancim të plotë të kllapave, pa varësi të reja — vetëm JCE + Android framework.
## 🆕 v5.2 — Ide të reja nga research i thelluar (Signal, SimpleX, Tinfoil, Briar)

Pas kërkimit të krahasuar të aplikacioneve më të mirë të sigurt, shtova 3 veçori:

| Veçoria | Burimi | Implementimi |
|---|---|---|
| **ENCRYPTED BACKUP / RESTORE** (CODE RECOVERY) | SimpleX | Butonat BK/RS: e gjithë gjendja (kontakte+çelësa+mesazhe) vuloset me passphrase(PBKDF2-SHA512, 600k) në skedar code-mors-recovery.cmrec (salt+IV+ciphertext). Restore me passphrase. |
| **INCOGNITO KEYBOARD** | Signal | cmhIncognitoKeys(): çaktivizon autocomplete, autocorrect, capitalize, spellcheck — s'mbetet gjurmë te tastiera e sistemit (OEM-i s'e mbl më fjalët tuaja). |
| **LOCAL-ONLY MODE** | SimpleX | Butoni LO: toggle për izolim të plotë të rrjetit, me badge vizuel në statusbar. |

Gjithashtu e konfirmuam: Double Ratchet ✅, Safety Numbers ✅, Ghost Noise (=SimpleX decoy queues) ✅, Panic gesture (=Briar panic button) ✅, Duress PIN ✅ (best-practice nga GrapheneOS/Tinfoil), deniability ✅. Post-quantum (ML-KEM) mbetet roadmap (kërkon KEM të vërtetë, stub kyber.js është bosh).
## 🛡️ v5.3 — DeepGuard (Anti-tamper / Anti-duplicate) + Tor Roadmap

### DeepGuard — vetë-mbrojtje kundra ripaketimit/duplikimit
`DeepGuard.java` (e re native): kur app-i instalohet, llogarit hash-e SHA-256 për çdo entry (dex, resources, manifest, cert) dhe i ruan në Keystore. Në çdo hapje + kanal, ri-verifikon; nëse një hash mospërputhet (APK i ndryshuar ose i duplikuar me kod të shtuar) -> `panicWipe` i menjëhershëm (self-destruct).))

| Mbrojtja | Çfarë bën |
|---|---|
| Tampering i APK-së | RIPAKETA me kod të shtuar/trojan → hash-et nuk përputhen → gjithçka fshihet. |
| Duplikimi | Kopje e modifikuar → e njëjta logjikkë. |
| Re-verifikimi | Ri-skanon në çdo hapje kanali, jog vetëm nisje. |

### Tor — Roadmap i qartë (opsion)
Tor-i e fsheh IP-në dhe e bën trafikun invizible, por:
- APK-të standard Android nuk mund të përdorin Tor-in në nivel OS-i (kërkon **Orbot** + proxy)).
- Integrim si opsion në CodeMors: `PROXY_SOCKET` me `127.0.0.1:9050` (Orbot listener)).
- **Rrezik sigurie**: nëse lidhja e Tor-it bëhet keq ( DNS leak, transport i pasigurt), të gjitha mbrojtjet e mësipërme mund të bien). Prandaj: **Tor = opsion i dokumentuar, jo default**, dhe kërkon testim përpara aktivizimit.
.