#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AntiSpy Scanner (Windows) — pjesë e Code-mors / antispy-scanner
Skaner anti-stalkerware/anti-spyware për PC Windows. Vetëm stdlib, pa varësi.

Kontrollon:
  1. Procese të njohura spyware/keylogger
  2. Programet e instaluara (registry uninstall) vs bazë stalkerware
  3. Startup (Run keys + Startup folder)
  4. Scheduled tasks të dyshimta
  5. Hosts file hijack (phishing banka/google)
  6. Zgjerime browser-i të dyshimta

Kufizim i sinqertë: kap SHENJAT e stalkerware të njohur + heuristika.
Rootkit kernel-mode nuk detektohet nga userland.

Përdorimi:  python antispy_scan.py
"""
import os, sys, re, glob, subprocess, winreg, datetime, ctypes, tempfile

RISK_HIGH, RISK_MED, RISK_LOW, RISK_INFO = 3, 2, 1, 0
findings = []
score = 0

def add(level, title, detail):
    findings.append((level, title, detail))
    global score
    score += {RISK_HIGH: 40, RISK_MED: 15, RISK_LOW: 5, RISK_INFO: 0}[level]

# ============ BAZA: spyware/keylogger desktop të njohur ============
KNOWN_PROCESSES = {
    "pctattletale.exe": "pcTattletale stalkerware",
    "webwatcher.exe": "WebWatcher stalkerware",
    "refog.exe": "REFOG Keylogger",
    "refogkeylogger.exe": "REFOG Keylogger",
    "mpk.exe": "Mipko Personal Monitor (keylogger)",
    "spyagent.exe": "SpyAgent Keylogger",
    "spyanywhere.exe": "SpyAnywhere (remote spy)",
    "ardamax.exe": "Ardamax Keylogger",
    "elitekeylogger.exe": "Elite Keylogger",
    "actualkeylogger.exe": "Actual Keylogger",
    "revealer.exe": "Revealer Keylogger",
    "kidlogger.exe": "KidLogger (kontrollo kush e instaloi)",
    "spyrix.exe": "Spyrix Free Keylogger",
    "spybuddy.exe": "SpyBuddy",
    "win-spy.exe": "WinSpy",
    "spystealth.exe": "SpyStealth",
    "monitorspy.exe": "MonitorSpy",
    "tspynet.exe": "The Spy Net (RAT)",
    "darkcomet.exe": "DarkComet RAT",
    "njrat.exe": "njRAT",
    "njq8.exe": "njRAT variant",
    "quasar.exe": "Quasar RAT",
    "remcos.exe": "Remcos RAT",
    "mspydesktop.exe": "mSpy Desktop",
    "flexispy.exe": "FlexiSPY",
    "hw_server.exe": "Hoverwatch component",
}
KNOWN_INSTALL_NAMES = [
    "pcTattletale", "WebWatcher", "REFOG", "Mipko", "SpyAgent", "SpyAnywhere",
    "Ardamax", "Elite Keylogger", "Actual Keylogger", "Revealer", "Spyrix",
    "SpyBuddy", "Win-Spy", "SpyStealth", "mSpy", "FlexiSPY", "Hoverwatch",
    "DarkComet", "njRAT", "Quasar RAT", "Remcos", "MonitorSpy"
]
SUSPICIOUS_DIRS = [r"\temp\\", r"\users\public\\", r"\windows\temp\\"]
BANK_HOSTS_PAT = re.compile(r"paypal|banka|bank|postashqiptare|cib|bkt|raiffeisen|procredit|credins|unionbank|google|facebook", re.I)
BAD_EXT_KW = ["keylog", "spy", "track", "monitor", "stealth", "record"]

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception: return False

# ============ 1. Proceset ============
def scan_processes():
    try:
        out = subprocess.run(["tasklist", "/fo", "csv", "/nh"],
                             capture_output=True, text=True, timeout=30).stdout
    except Exception as e:
        add(RISK_INFO, "tasklist nuk u ekzekutua", str(e)); return
    for line in out.splitlines():
        if not line.strip(): continue
        parts = line.split('","')
        if not parts: continue
        name = parts[0].strip('"').lower()
        if name in KNOWN_PROCESSES:
            add(RISK_HIGH, "PROCES SPYWARE AKTIV: " + KNOWN_PROCESSES[name],
                "Procesi " + name + " po ekzekutohet TANI — logjon tastet/ekranin.")
        if len(parts) > 1:
            path = parts[1].strip('"').lower()
            if path and any(d in path for d in SUSPICIOUS_DIRS):
                add(RISK_MED, "Proces nga vend jostandard: " + name,
                    "Path: " + path + " — malware shpesh ekzekutohet nga Temp/Public.")
# ============ 2. Programet e instaluara ============
def scan_installed():
    roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    for hive, path in roots:
        try: k = winreg.OpenKey(hive, path)
        except OSError: continue
        i = 0
        while True:
            try: sub = winreg.EnumKey(k, i); i += 1
            except OSError: break
            try:
                sk = winreg.OpenKey(k, sub)
                name, _ = winreg.QueryValueEx(sk, "DisplayName")
                if name and any(s.lower() in str(name).lower() for s in KNOWN_INSTALL_NAMES):
                    add(RISK_HIGH, "SPYWARE I INSTALUAR: " + str(name),
                        "Regjistruar në Uninstall (" + sub + "). Fshije + ndrysho fjalëkalimet.")
            except OSError: pass

# ============ 3. Startup ============
def scan_startup():
    for hive, path, label in [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM Run32"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
    ]:
        try: k = winreg.OpenKey(hive, path)
        except OSError: continue
        i = 0
        while True:
            try:
                name, val, _ = winreg.EnumValue(k, i); i += 1
                v = str(val).lower()
                for proc in KNOWN_PROCESSES:
                    if proc in v:
                        add(RISK_HIGH, "STARTUP SPYWARE: " + name, label + ": " + str(val))
                if any(d in v for d in SUSPICIOUS_DIRS):
                    add(RISK_MED, "Startup nga Temp: " + name, label + ": " + str(val))
            except OSError: break
    startup = os.path.join(os.environ.get("APPDATA", ""),
        r"Microsoft\Windows\Start Menu\Programs\Startup")
    if os.path.isdir(startup):
        for f in os.listdir(startup):
            p = os.path.join(startup, f)
            try:
                with open(p, "rb") as fh:
                    data = fh.read(4096).decode("utf-8", "ignore").lower()
                    if any(proc in data for proc in KNOWN_PROCESSES):
                        add(RISK_HIGH, "Startup folder spyware: " + f, p)
            except OSError: pass

# ============ 4. Scheduled tasks ============
def scan_tasks():
    try:
        out = subprocess.run(["schtasks", "/query", "/fo", "csv", "/nh"],
                             capture_output=True, text=True, timeout=30).stdout
    except Exception: return
    for line in out.splitlines():
        low = line.lower()
        for proc in KNOWN_PROCESSES:
            if proc in low:
                add(RISK_HIGH, "Task i planifikuar SPYWARE", line.strip())

# ============ 5. Hosts file ============
def scan_hosts():
    p = r"C:\Windows\System32\drivers\etc\hosts"
    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"): continue
                if BANK_HOSTS_PAT.search(line):
                    add(RISK_HIGH, "HOSTS HIJACK (phishing/bank): " + line,
                        "Hyrje ridrejton domain legjitime — phishing ose MITM.")
    except OSError as e:
        add(RISK_INFO, "hosts s'u lexua", str(e))
# ============ 6. Zgjerime browser-i ============
def scan_extensions():
    patterns = {
        "Chrome": os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\*\Extensions\*\*\manifest.json"),
        "Edge":   os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\*\Extensions\*\*\manifest.json"),
        "Firefox":os.path.expandvars(r"%APPDATA%\Mozilla\Firefox\Profiles\*\extensions\*.xpi"),
    }
    for b, pat in patterns.items():
        for mf in glob.glob(pat):
            try:
                with open(mf, "r", encoding="utf-8", errors="ignore") as f:
                    data = f.read(8192).lower()
                m = re.search(r'"name"\s*:\s*"([^"]+)"', data)
                name = m.group(1) if m else "?"
                hits = [k for k in BAD_EXT_KW if k in data]
                if hits:
                    add(RISK_MED, "Zgjerim " + b + " i dyshimtë: " + name,
                        mf + " — fjalë kyçe: " + str(hits))
            except OSError: pass

def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    print("=" * 60)
    print("  AntiSpy Scanner (Windows) — Code-mors project")
    print("  " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
    print("  Admin:", is_admin(), "(rekomandohet Run as Administrator)")
    print("=" * 60)
    print("[1/6] Procese ...");          scan_processes()
    print("[2/6] Instalime ...");       scan_installed()
    print("[3/6] Startup ...");         scan_startup()
    print("[4/6] Scheduled tasks ..."); scan_tasks()
    print("[5/6] Hosts file ...");      scan_hosts()
    print("[6/6] Browser extensions ..."); scan_extensions()

    print("\n" + "=" * 60)
    labels = {RISK_HIGH: "HIGH", RISK_MED: "MEDIUM", RISK_LOW: "LOW", RISK_INFO: "INFO"}
    if not findings:
        print("  E PASTËR — s'u gjet asgjë e dyshimtë.")
    for lvl, title, detail in sorted(findings, key=lambda x: -x[0]):
        print("  [" + labels[lvl].ljust(6) + "] " + title)
        print("           " + detail)
    print("\n" + "=" * 60)
    verdict = ("KOMPROMETUAR — VEPRO MENJËHERË" if score >= 60 else
               "RREZIK I LARTË" if score >= 30 else
               "RREZIK MESATAR" if score >= 10 else "E PASTËR")
    print("  VERDIKT: " + verdict + "   (risk " + str(score) + "/100+)")
    print("  Nëse dyshim e lartë: backup → full scan (Malwarebytes/ESET) →")
    print("  ndrysho fjalëkalimet nga pajisje tjetër → aktivizo 2FA.")
    print("=" * 60)
    rpt = os.path.join(tempfile.gettempdir(), "antispy_report.txt")
    with open(rpt, "w", encoding="utf-8") as f:
        for lvl, title, detail in findings:
            f.write("[" + labels[lvl] + "] " + title + "\n  " + detail + "\n")
        f.write("\nVERDIKT: " + verdict + " (risk " + str(score) + ")\n")
    print("  Raporti: " + rpt)

if __name__ == "__main__":
    main()


