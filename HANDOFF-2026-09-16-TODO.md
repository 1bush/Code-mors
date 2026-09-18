
## Lista e puneve per neser (ne rend)
1. Lexo kete dokument, git status dhe diff. Mos supozo se cache/graph eshte aktual: MCP graph tools nuk ishin te disponueshme ne kete seance, u lexua kodi direkt.
2. Perfundimi i testit te deep-link: ne tools\test_pairing_browser.py, enter(..., url=BASE) duhet te perdore url ne goto. Krijo ftese, hape URL ne profil te paster, sigurohu se pranohet vetem PAS PIN-it dhe klikimit Add Friend.
3. Testo kameren: leje e refuzuar, mbyllje gjate kerkeses se lejes, tracks ended pas Anulo/ndryshim tab-i, dekodim me video test ose telefon real. QR pixel test nuk eshte prove e kameres fizike.
4. Testo Share me mock te navigator.share/clipboard/window.open dhe prove manuale ne Signal/SimpleX/WhatsApp; mos pretendo se dergimi real eshte testuar nga mock.
5. Teste relay: dy claim njekohesisht duhet te kene vetem nje fitues; skadim; revoke me token te sakte/gabuar; token-a te vjeter; body/keys te pavlefshme; ftesa e re nuk demton chat-in ekzistues. Perdore server test lokal, jo target te jashtem.
6. Shqyrto garen genQr kundrejt pollAll ne momentin e konsumimit/regjenerimit, dhe S.linking qe lirohet ne finally edhe kur nje thirrje e dyte kthehet heret. Kerkohen teste perpara ndryshimit.
7. Hiq debug console.log [CM-DBG], komentet e pasakta SHA-256 te S32hex (nuk eshte SHA-256), kodin e vdekur dhe testet diagnostike te tejkaluara. Mos publiko log-e me ID ftese/token-a.
8. Rishiko renderContacts (innerHTML me emer), klasat me/them ne addBubble (te dy stringjet jane truthy), Safety Numbers qe gjenerohen rastesisht ne showSafety, dhe kufizimet e ruajtjes se kontakteve. Dokumento/rregullo me teste te fokusuara; mos e quaj prodhim te sigurt.
9. Qarteso me perdoruesin: wipe pas NJE PIN-i gabim apo 3 si tani; admin eshte vetem ndryshim PIN-i, jo sistem rolesh. Mos ndrysho pragun ne heshtje.
10. Per perdorim mes pajisjeve: konfigurim HTTPS/relay publik. Aktualisht vetem test lokal. Mos ekspozo serverin e zhvillimit/root e repo-s ne internet dhe mos dergo ftesa reale pa kerkese.
11. Rishiko AntiSpy per false positives, package visibility, burime te listes, dhe formulime jo absolute. Audit sigurie i plote nuk eshte bere.
12. Perditeso README/HARDENING: flow web, afati 15 min, nje perdorim, kufizimet, test commands; dallo native nga web. Kontrollo te drejtat per imazhin kamuflazh para publikimit.
13. Rinderto Android me Gradle offline, verifiko APK/source dhe, nese mundet, ne pajisje. Nuk duhet claim "testuar ne telefon" pa prove.
14. Ekzekuto te gjitha testet + sintaksen inline JS + git diff --check; lexo skedaret final te ndryshuar.
15. Git update qe perdoruesi kerkoi me pare: stage eksplicit vetem source/assets/APK e verifikuar/dokumentacion/teste. Mos git add . pa kontroll; shqyrto staged diff per secrets/log-e. Commit me pershkrim dhe push pa --force. Nese push deshton, raporto sakte.

## Skedare te perkohshem / higjiena git
- .gitignore i ri perjashton .gradle/, build/, node_modules/, log-e, cache Python, .env dhe tools\_mors_js_check.js.
- tools\test_entry.py eshte testi i vjeter print-only, referon fushat e vjetra _myRecv; mos e perdor si prove suksesi.
- tools\test_qr_diagnostic.py ishte vetem diagnostik dhe printon URL te ftesave; mos publiko output-et.
- tools\extract_mors_js.py dhe _mors_js_check.js jane ndihmes/provizore.
- Nje skedar u krijua gabimisht ne C:\Users\roven\navigation-mors\mors-app.html, u lexua dhe u fshi. Nuk eshte pjese e projektit.
- Nuk u krye commit/push gjate kesaj seance. Snapshot lokal shtese planifikohet jashte repo-s ne C:\Users\roven\Code-mors-checkpoint-2026-09-16 (source dhe skedare te modifikuar, jo build caches).

## Si rifillon lokalisht
Kontrollo me pare portat 5173 dhe 7000; mos nis procese te dyfishta.
Ne momentin e ndalimit: web PID 22952 ne :5173, relay PID 8796 ne :7000. PID mund te ndryshoje.
Nga PowerShell:

```powershell
Set-Location C:\Users\roven\Code-mors
node C:\Users\roven\Code-mors\_serve.js
# Ne terminal tjeter:
node C:\Users\roven\Code-mors\relay\server.js --port 7000 --no-log
# Teste ne terminal tjeter:
python C:\Users\roven\Code-mors\tools\check_connect.py
python C:\Users\roven\Code-mors\tools\test_pairing_browser.py
npm test
npm run test:pairing
npm run test:app
```

Browser: http://localhost:5173 — PIN fillestar 0000 vetem kur nuk ka PIN te ruajtur.
Mos pastroni localStorage te perdoruesit per test; perdorni profile te izoluara Playwright.
