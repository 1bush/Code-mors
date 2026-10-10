# TEST-SERVER — si ta testosh aplikacionin në telefon (LAN + HTTPS)

Server i vetëm që shërben **faqen (mors-app.html) + relay-in** në të njëjtin port.
Kështu telefoni hap një adresë të vetme dhe app-i e gjen relay-in automatikisht
(i njëjti origin — pa CORS, pa konfigurim).

---

## 1. Nisja (2 hapa)

```powershell
cd C:\Users\roven\Code-mors
node tools\make_cert.js      # vetëm një herë: certifikatë self-signed (për kamera/HTTPS)
node test-server.js          # nis serverin (HTTPS :8443)
```

Ose me një klik: **`start_test_server.bat`** (krijon certifikatën nëse mungon,
shton rregullin e firewall-it, pastaj nis serverin).

Serveri shtyp adresat, p.sh.:

```
  Vendore     : https://localhost:8443
  Ne telefon  : https://10.156.111.19:8443      <-- hape këtë në telefon
```

Komanda alternative (npm):

```bash
npm run cert            # gjenero certifikatën
npm run serve:test      # HTTPS :8443 (ose HTTP nëse certs/ mungon)
npm run serve:test:http # HTTP :8080 (pa TLS — kamera nuk punon)
```

---

## 2. Hapat në telefon

1. Telefoni duhet të jetë **në të njëjtin Wi-Fi** me PC-në.
2. Hap në shfletues (Chrome): **`https://<IP-e-PC>:8443`**.
3. Shfletuesi shfaq **paralajmërim certifikate** (self-signed) → **Advanced → Proceed**.
   Kjo është e pritshme për certifikatë lokale; pa këtë hap kamera nuk hapet.
4. PIN fillestar: **0000** (nëse s'ke PIN të ruajtur në atë shfletues).
5. Në telefonin e dytë: të njëjtat hapa, pastaj **MY QR** në njërin ↔
   **SCAN QR TO LINK** në tjetrin (ose kopjo linkun dhe ngjite manualisht).

> Kamera kërkon **HTTPS ose localhost** (secure context). Me `--http` QR-ja nuk
> lexohet me kamerë, por **lidhja mund të bëhet duke ngjitur linkun**.

---

## 3. Firewall (nëse telefoni nuk lidhet)

```powershell
# si Administrator
netsh advfirewall firewall add rule name="CodeMors Test 8443" dir=in action=allow protocol=TCP localport=8443
```

Hiqja kur mbaron testimi:

```powershell
netsh advfirewall firewall delete rule name="CodeMors Test 8443"
```

---

## 4. Pa certifikatë: tunel HTTPS (opsional)

```powershell
cloudflared tunnel --url https://localhost:8443
# ose
ngrok http 8443
```

⚠️ Me tunel, app-i bëhet **i arritshëm nga interneti**. Vetëm për test të shkurtër,
fike pas provës, mos dërgo ftesa reale; relay-i mban ciphertext në RAM, por nuk është server prodhimi.

---