# CODE MORS 👻

**Military-grade secure chat app** — zero identity, zero middlemen, zero traces.

E2E encrypted messaging with QR pairing, permanent ghost identities, self-destructing messages, encrypted photos, and fully **offline optical transfer** (screen-to-camera).

---

## 🛡️ Security Stack

| Layer | Protocol | What it defeats |
|---|---|---|
| Key agreement | **ECDH P-256** (per pair) | Passive eavesdropping |
| Message encryption | **AES-256-GCM**, fresh key per message (**Signal Double Ratchet** — HMAC-SHA256 KDF chain) | Forward secrecy / break-in recovery |
| Identity | **SimpleX-style zero identifiers** — no phone, email, or account; permanent *Ghost Name* only | User tracking & correlation |
| Traffic analysis | **Padding**: 256-byte blocks for text, 4 KB random-filled blocks for photos | Size/traffic fingerprinting |
| MITM | **Safety Numbers** (SHA-512 of both public keys), compare in person + QR scanned face-to-face | Man-in-the-middle attacks |
| Photos | **XFTP-style chunked encryption** + EXIF stripping via canvas re-draw | Metadata leaks (GPS, device) |
| Transport (optional) | **Decimen Optical Transfer** — animated QR frames, screen → camera, no network at all | ALL network surveillance |
| Local storage | **Android Keystore AES-256-GCM** sealed database | Forensic recovery (Cellebrite-style) |
| Device surface | `FLAG_SECURE`, cache disabled, no notifications, backup disabled | Screenshot / recents / notification leaks |

## ✨ Features

### Core
- 🔗 **QR Link** — scan another user's code to establish an E2E channel (no server involved)
- 🎭 **Submask names** — you appear as your permanent Ghost Name; each contact gets a unique alias
- ⏱️ **Time Delete** — per-conversation: OFF · READ-ONCE · 10s · 60s
- 📷 **Encrypted photos** — EXIF-stripped, padded, per-photo derived keys
- 📡 **Optical Send/Receive** — transfer photos between devices with **no internet at all**
- ✂️ **END SESSION** — wipes every message from phone **and** database, while keeping the unique names so friends/family can reconnect
- ☠️ Burn-after-read with visible countdown bars

### New in v4.1
- 🔍 **Message Search** — full-text search across all conversations with highlighted results
- 👍 **Emoji Reactions** — react to messages with 8 emojis (👍❤️😂😮😢😡🔥👀)
- ↩️ **Reply to Message** — quote-reply to specific messages
- ➡️ **Message Forwarding** — forward messages to other contacts
- ⭐ **Bookmarks** — save important messages, view in dedicated panel
- 📌 **Contact Pinning** — pin contacts to top of sidebar
- 🎨 **Chat Themes** — 5 color themes (Matrix Green, Amber Terminal, Ice Blue, Blood Red, Purple Haze)
- ⏱️ **Custom Burn Timer** — configurable auto-destroy (OFF, READ-ONCE, 10s, 30s, 60s, custom)
- ⌨️ **Typing Indicators** — shows when contact is typing
- ✓✓ **Read Receipts** — sent/delivered/read status indicators
- 🔒 **Auto-Lock** — auto-lock after inactivity with PIN protection
- ⬇️ **Export Chat** — export conversations as formatted text files

## 📱 Two builds

### 1. Native Java (`android-native/`) — recommended
Pure **Java** Android Studio project.

```
android-native/
├── app/src/main/java/com/codemors/nativeapp/
│   ├── Crypto.java        ECDH + Double Ratchet + AES-GCM + safety numbers
│   ├── Store.java         Keystore-sealed local database
│   ├── MainActivity.java  Ghost identity, contacts, QR pairing, session wipe
│   ├── ChatActivity.java  Chat, burn timers, END SESSION
│   └── QrActivity.java    Your pairing QR code
└── app/build.gradle       AGP 8.13.2 · Gradle 9.3.1 · minSdk 24 · targetSdk 34
```

Build:
```bash
cd android-native
./gradlew assembleDebug
# APK: app/build/outputs/apk/debug/app-debug.apk
```

### 2. Web/PWA (`code-mors-v4.html`)
Single-file app (also bundled as APK). Same protocol stack in JavaScript via WebCrypto.
Open directly in a browser, or install as a PWA. Prebuilt APKs are included in this repo:

- `CodeMors-NATIVE.apk` — native Java build
- `CodeMors-v4.apk` — WebView build

## 🚀 Usage

1. Install the APK on both devices
2. **MY QR** on one phone ↔ **SCAN QR TO LINK** on the other
3. Verify the channel in person (🔒 VERIFY / safety number)
4. Chat — messages burn per your TIME DELETE setting
5. Long-press contact (or END SESSION) to wipe everything — your ghost name survives so you can always reconnect

## 🔒 Threat model & honest limits

✅ Protected against: passive eavesdropping, server-side data collection (there is no server), metadata harvesting, traffic-size analysis, forensic recovery of deleted messages, screenshot/recents leakage.

⚠️ Not magic: a compromised device (malware/root) can read anything shown on screen; "zero-day proof" is impossible for any software. Physical screen-to-camera transfer removes even network observation but requires proximity.

## 📄 License

MIT


## 🧬 CM-HARD v5 — Hardening Layer (unique)

7 shtresa të reja unike: **Ghost Noise** (decoy traffic i padallueshëm), **Duress PIN** (panic wipe), **Whisper Zeroize**, **Time-Lock Pairing** (QR me passphrase), **Rotating Epoch** identities, **Deniable Vault** (Snowden mode), dhe **Optical v2** (kanal optik i ratchet-uar). Detaje: [HARDENING.md](HARDENING.md).

Aktivizohen nga butonat 👻 ⏳ 🎭 🔫 ❄️ në toolbar të PWA-s dhe klasat GhostNoise/Duress/DeniableStore në build-in native.