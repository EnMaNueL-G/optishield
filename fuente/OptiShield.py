# -*- coding: utf-8 -*-
"""
OptiShield — Escudo de privacidad y seguridad (Windows).  by OptiSuite
Defensivo · reversible · sin debilitar la seguridad (Defender/Firewall/UAC intactos).
Sin dependencias externas: solo Python estándar + tkinter + comandos de Windows.
"""
import os, sys, json, subprocess, threading, ctypes, socket, datetime, webbrowser, tempfile, re

APP = "OptiShield"
VERSION = "1.0.0"
BRAND = "OptiSuite"
WHATSAPP = "+56 9 7832 7863"
WA_URL = "https://wa.me/56978327863"
EMAIL = "support@optisuite.app"
WEB = "optisuite.app"

# ---- rutas de datos (config, backups, logs) ----
DATA_DIR = os.path.join(os.environ.get("PROGRAMDATA", os.path.expanduser("~")), "OptiShield")
BACKUP_DIR = os.path.join(DATA_DIR, "backups")
LOG_DIR = os.path.join(DATA_DIR, "logs")
for d in (DATA_DIR, BACKUP_DIR, LOG_DIR):
    try: os.makedirs(d, exist_ok=True)
    except Exception: pass

CREATE_NO_WINDOW = 0x08000000

# ======================= BASE DE DATOS DE PROXYWARE =======================
# Familias conocidas de "bandwidth sharing" / proxyware / nodos de salida residenciales.
PROXYWARE_DB = {
    "honeygain":     {"name": "Honeygain", "risk": "medium", "proc": ["honeygain.exe"], "svc": ["HoneygainService"], "paths": ["Honeygain"], "reg": ["Honeygain"], "domains": ["honeygain.com", "honeygain.io"]},
    "iproyal_pawns": {"name": "IPRoyal Pawns", "risk": "medium", "proc": ["pawns.exe", "iproyal_pawns.exe", "pawns-cli.exe"], "svc": ["PawnsService"], "paths": ["Pawns", "IPRoyal"], "reg": ["Pawns", "IPRoyal"], "domains": ["pawns.app", "iproyal.com"]},
    "earnapp":       {"name": "EarnApp (Bright Data)", "risk": "medium", "proc": ["earnapp.exe"], "svc": ["EarnApp"], "paths": ["EarnApp", "BrightData"], "reg": ["EarnApp"], "domains": ["earnapp.com", "brightdata.com", "luminati.io"]},
    "packetstream":  {"name": "PacketStream", "risk": "medium", "proc": ["packetstream.exe", "psclient.exe"], "svc": ["PacketStream"], "paths": ["PacketStream"], "reg": ["PacketStream"], "domains": ["packetstream.io"]},
    "peer2profit":   {"name": "Peer2Profit", "risk": "medium", "proc": ["peer2profit.exe", "p2papp.exe"], "svc": [], "paths": ["Peer2Profit"], "reg": ["Peer2Profit"], "domains": ["peer2profit.com"]},
    "traffmonetizer":{"name": "Traffmonetizer", "risk": "medium", "proc": ["Traffmonetizer.exe", "tm.exe"], "svc": [], "paths": ["Traffmonetizer"], "reg": ["Traffmonetizer"], "domains": ["traffmonetizer.com"]},
    "repocket":      {"name": "Repocket", "risk": "medium", "proc": ["repocket.exe", "rpnetwork.exe"], "svc": [], "paths": ["Repocket"], "reg": ["Repocket"], "domains": ["repocket.co"]},
    "packetshare":   {"name": "PacketShare", "risk": "medium", "proc": ["packetshare.exe"], "svc": [], "paths": ["PacketShare"], "reg": ["PacketShare"], "domains": ["packetshare.io"]},
    "proxyrack":     {"name": "Proxyrack / PeerConnect", "risk": "high", "proc": ["peerconnect.exe", "proxyrack.exe"], "svc": [], "paths": ["Proxyrack", "PeerConnect"], "reg": [], "domains": ["proxyrack.com"]},
    "922proxy":      {"name": "922 S5 / 922proxy", "risk": "high", "proc": ["922proxy.exe", "s5.exe", "ip2world.exe"], "svc": [], "paths": ["922proxy", "922 S5", "IP2World"], "reg": [], "domains": ["922proxy.com", "ip2world.com"]},
    "infatica":      {"name": "Infatica", "risk": "high", "proc": ["infatica.exe", "infatica-service.exe"], "svc": ["InfaticaService"], "paths": ["Infatica"], "reg": ["Infatica"], "domains": ["infatica.io"]},
    "asocks":        {"name": "Asocks", "risk": "high", "proc": ["asocks.exe"], "svc": [], "paths": ["Asocks"], "reg": [], "domains": ["asocks.com"]},
    "mysterium":     {"name": "Mysterium (nodo)", "risk": "medium", "proc": ["myst.exe", "mysterium.exe", "mystnodeslauncher.exe"], "svc": ["MysteriumNode"], "paths": ["Mysterium"], "reg": [], "domains": ["mysterium.network"]},
    "smartproxy":    {"name": "Smartproxy SDK", "risk": "high", "proc": ["smartproxy.exe"], "svc": [], "paths": ["Smartproxy"], "reg": [], "domains": ["smartproxy.com"]},
    "oxylabs":       {"name": "Oxylabs SDK", "risk": "high", "proc": [], "svc": [], "paths": ["Oxylabs"], "reg": ["Oxylabs"], "domains": ["oxylabs.io"]},
    "proxycheap":    {"name": "Proxy-Cheap SDK", "risk": "high", "proc": [], "svc": [], "paths": ["ProxyCheap"], "reg": [], "domains": ["proxy-cheap.com"]},
    "grasshopper":   {"name": "Grasshopper SDK", "risk": "high", "proc": [], "svc": [], "paths": ["Grasshopper"], "reg": [], "domains": []},
    "hola":          {"name": "Hola VPN (nodo de salida)", "risk": "high", "proc": ["hola.exe", "hola_svc.exe", "hola_updater.exe"], "svc": ["hola_svc", "hola_updater"], "paths": ["Hola", "hola"], "reg": ["Hola"], "domains": ["hola.org", "holavpn.net"]},
    "netnut_sdk":    {"name": "NetNut SDK (botnet)", "risk": "high", "proc": [], "svc": [], "paths": ["NetNut"], "reg": ["NetNut"], "domains": ["netnut.io", "netnut.net"]},
    "freevpn_p2p":   {"name": "VPN gratis tipo P2P (Betternet/TouchVPN/Psiphon)", "risk": "medium", "proc": ["betternet.exe", "touchvpn.exe", "psiphon.exe", "psiphon3.exe"], "svc": [], "paths": ["Betternet", "TouchVPN", "Psiphon"], "reg": [], "domains": []},
}
# Dominios IOC (check-in de proxyware/botnets residenciales tipo NetNut/Badbox).
IOC_DOMAINS = ["netnut.io", "netnut.net", "brightdata.com", "luminati.io", "packetstream.io",
               "peer2profit.com", "honeygain.com", "iproyal.com", "922proxy.com", "infatica.io",
               "traffmonetizer.com", "repocket.co", "asocks.com"]

def _load_external_db():
    """Amplía PROXYWARE_DB desde data\\proxyware_db.json (junto al ejecutable), sin recompilar."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    for p in (os.path.join(base, "data", "proxyware_db.json"),
              os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "proxyware_db.json")):
        try:
            with open(p, "r", encoding="utf-8") as f:
                sigs = (json.load(f) or {}).get("signatures", {})
            for k, v in sigs.items():
                if isinstance(v, dict) and v.get("name"): PROXYWARE_DB[k] = v
                for d in (v.get("domains", []) if isinstance(v, dict) else []):
                    if d not in IOC_DOMAINS: IOC_DOMAINS.append(d)
            return
        except Exception: continue
_load_external_db()

# ======================= AJUSTES DE PRIVACIDAD =======================
# type reg: (hive, path, name, kind, on_value, off_value). Apply pone off_value (privado).
PRIVACY_TWEAKS = [
    {"id":"telemetry","name":"Telemetría de Windows al mínimo","reg":[("HKLM","SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection","AllowTelemetry","dword",1,0),
                                                                       ("HKLM","SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection","DoNotShowFeedbackNotifications","dword",0,1)],
     "svc":["DiagTrack","dmwappushservice"]},
    {"id":"advid","name":"ID de publicidad (desactivar)","reg":[("HKCU","SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo","Enabled","dword",1,0),
                                                                 ("HKLM","SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo","DisabledByGroupPolicy","dword",0,1)]},
    {"id":"location","name":"Ubicación (servicio + apps + política)","reg":[("HKLM","SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location","Value","sz","Allow","Deny"),
                                                                             ("HKCU","SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location","Value","sz","Allow","Deny"),
                                                                             ("HKLM","SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors","DisableLocation","dword",0,1)],
     "svc":["lfsvc"]},
    {"id":"activity","name":"Historial de actividad (no recopilar/subir)","reg":[("HKLM","SOFTWARE\\Policies\\Microsoft\\Windows\\System","PublishUserActivities","dword",1,0),
                                                                                  ("HKLM","SOFTWARE\\Policies\\Microsoft\\Windows\\System","UploadUserActivities","dword",1,0)]},
    {"id":"tailored","name":"Experiencias personalizadas con diagnóstico","reg":[("HKCU","SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Privacy","TailoredExperiencesWithDiagnosticDataEnabled","dword",1,0)]},
    {"id":"apptrack","name":"Seguimiento de apps abiertas (Inicio)","reg":[("HKCU","SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced","Start_TrackProgs","dword",1,0)]},
    {"id":"consumer","name":"Contenido/anuncios sugeridos de Windows","reg":[("HKLM","SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent","DisableWindowsConsumerFeatures","dword",0,1),
                                                                              ("HKLM","SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent","DisableSoftLanding","dword",0,1)]},
    {"id":"bing","name":"Búsqueda web / Bing en el menú Inicio","reg":[("HKCU","SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search","BingSearchEnabled","dword",1,0),
                                                                        ("HKCU","SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search","CortanaConsent","dword",1,0)]},
    {"id":"langlist","name":"Acceso de webs a tu lista de idiomas","reg":[("HKCU","Control Panel\\International\\User Profile","HttpAcceptLanguageOptOut","dword",0,1)]},
    {"id":"feedback","name":"Notificaciones de comentarios (feedback)","reg":[("HKCU","SOFTWARE\\Microsoft\\Siuf\\Rules","NumberOfSIUFInPeriod","dword",1,0)]},
]

HIVE = {"HKLM": "HKEY_LOCAL_MACHINE", "HKCU": "HKEY_CURRENT_USER"}

# ======================= UTILIDADES DE SISTEMA =======================
def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception: return False

def elevate():
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, '"%s"' % os.path.abspath(sys.argv[0]), None, 1)
    except Exception: pass
    sys.exit(0)

def run(args):
    try:
        p = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="ignore",
                           creationflags=CREATE_NO_WINDOW, timeout=40)
        return p.stdout or ""
    except Exception: return ""

def ps(cmd):
    return run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd])

def psjson(cmd):
    out = ps(cmd + " | ConvertTo-Json -Compress -Depth 4")
    out = out.strip()
    if not out: return []
    try:
        d = json.loads(out)
        return d if isinstance(d, list) else [d]
    except Exception: return []

def log(msg):
    try:
        with open(os.path.join(LOG_DIR, "optishield.log"), "a", encoding="utf-8") as f:
            f.write("[%s] %s\n" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg))
    except Exception: pass

# ---- Registro con backup (para revertir) ----
import winreg
def _hkey(h): return winreg.HKEY_LOCAL_MACHINE if h == "HKLM" else winreg.HKEY_CURRENT_USER
def reg_read(hive, path, name):
    try:
        k = winreg.OpenKey(_hkey(hive), path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        v, _ = winreg.QueryValueEx(k, name); winreg.CloseKey(k); return v
    except Exception: return None
def reg_write(hive, path, name, kind, value):
    t = winreg.REG_DWORD if kind == "dword" else winreg.REG_SZ
    k = winreg.CreateKeyEx(_hkey(hive), path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
    winreg.SetValueEx(k, name, 0, t, value); winreg.CloseKey(k)

def backup_write(entries):
    """entries: list de (hive,path,name). Guarda valores actuales para poder revertir."""
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    data = {"when": stamp, "reg": []}
    for hive, path, name in entries:
        data["reg"].append({"hive": hive, "path": path, "name": name, "old": reg_read(hive, path, name)})
    try:
        with open(os.path.join(BACKUP_DIR, "backup_%s.json" % stamp), "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception: pass

# ======================= ESCÁNERES =======================
def list_processes():
    """dict lower(nombre) -> nombre real (de tasklist)."""
    out = run(["tasklist", "/fo", "csv", "/nh"]); res = {}
    for line in out.splitlines():
        parts = line.split('","')
        if parts:
            nm = parts[0].strip('"').strip()
            if nm: res[nm.lower()] = nm
    return res

def list_services():
    return psjson("Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,PathName")

def program_dirs():
    return [os.environ.get(v, "") for v in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA", "APPDATA", "ProgramData")]

def scan_proxyware():
    findings = []
    procs = list_processes()
    svcs = {(s.get("Name") or "").lower(): s for s in list_services() if isinstance(s, dict)}
    for key, d in PROXYWARE_DB.items():
        hits, why = [], []
        for pn in d.get("proc", []):
            if pn.lower() in procs: hits.append("proceso:" + pn); why.append("proceso en ejecución")
        for sv in d.get("svc", []):
            if sv.lower() in svcs: hits.append("servicio:" + sv); why.append("servicio instalado")
        for pdir in program_dirs():
            for pth in d.get("paths", []):
                try:
                    if pdir and os.path.isdir(os.path.join(pdir, pth)): hits.append("carpeta:" + pth); why.append("carpeta instalada")
                except Exception: pass
        for rp in d.get("reg", []):
            for hv in ("HKLM", "HKCU"):
                if reg_read(hv, "SOFTWARE\\" + rp, None) is not None or _reg_key_exists(hv, "SOFTWARE\\" + rp):
                    hits.append("registro:" + rp); break
        if hits:
            # heurística intencional vs oculto
            hidden = any("Temp" in h or "AppData\\Local" in h for h in hits)
            findings.append({"id": key, "name": d["name"], "risk": d["risk"], "evidence": list(dict.fromkeys(hits)),
                             "hidden": hidden, "domains": d.get("domains", []),
                             "verdict": "Posible instalación NO consentida" if hidden else "Detectado (¿lo instalaste tú?)"})
    # nodos de salida: puertos a la escucha con posible SOCKS5
    for port, pid in _listening_ports():
        if port > 1024 and _is_socks5(port):
            findings.append({"id": "socks5_%d" % port, "name": "Proxy SOCKS5 local (posible nodo de salida)", "risk": "high",
                             "evidence": ["puerto:%d pid:%s" % (port, pid)], "hidden": True, "domains": [],
                             "verdict": "Posible nodo de salida activo"})
    # SDK de proxyware embebido en apps comunes (DLLs cargadas)
    findings.extend(scan_embedded_sdk())
    return findings

# Firmas de SDK de proxyware que se incrustan en apps "normales" (navegadores, Spotify, etc.).
SDK_SIGS = ["netnut", "luminati", "brightdata", "bright_data", "oxylabs", "pawns", "honeygain",
            "packetstream", "peer2profit", "proxyrack", "infatica", "smartproxy", "iproyal", "asocks", "922proxy"]
HOST_PROCS = ["chrome", "msedge", "firefox", "brave", "opera", "spotify", "discord"]
def scan_embedded_sdk():
    findings = []
    for base in HOST_PROCS:
        out = ps("Get-Process %s -ErrorAction SilentlyContinue | ForEach-Object { $_.Modules } | "
                 "Select-Object -ExpandProperty ModuleName -ErrorAction SilentlyContinue" % base)
        for ln in out.splitlines():
            low = ln.strip().lower()
            if not low.endswith(".dll"): continue
            for sig in SDK_SIGS:
                if sig in low:
                    findings.append({"id": "sdk_%s_%s" % (base, sig), "name": "SDK de proxyware embebido en %s.exe" % base,
                                     "risk": "high", "evidence": ["DLL:%s (firma %s)" % (ln.strip(), sig)], "hidden": True,
                                     "domains": [], "verdict": "SDK de proxyware inyectado en una app"})
                    break
    return findings

def _port_open(ip, port, timeout=0.35):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout)
        r = s.connect_ex((ip, port)); s.close(); return r == 0
    except Exception: return False

# Puertos de depuración típicos de dispositivos IoT/TV-box comprometidos (vector Badbox).
DEBUG_PORTS = {5555: "ADB (vector Badbox)", 23: "Telnet", 21: "FTP", 9527: "debug/UART", 7001: "debug", 4444: "backdoor"}
def scan_local_network():
    """Lee la tabla ARP (dispositivos ya vistos en tu red) y sondea SOLO puertos de depuración.
    No hace barrido agresivo de toda la subred (menos intrusivo y no dispara alarmas del router)."""
    devices = []
    out = run(["arp", "-a"])
    seen = []
    for line in out.splitlines():
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{11,17})\s+(\S+)", line)
        if not m: continue
        ip, mac, typ = m.group(1), m.group(2), m.group(3).lower()
        if ip.endswith(".255") or ip.startswith("224.") or ip.startswith("239.") or mac.startswith("ff-ff"): continue
        if "dynamic" in typ or "din" in typ:
            if ip not in seen: seen.append(ip); devices.append({"ip": ip, "mac": mac})
    for dev in devices:
        openp = []
        for port, label in DEBUG_PORTS.items():
            if _port_open(dev["ip"], port): openp.append("%d %s" % (port, label))
        dev["open"] = openp; dev["risk"] = bool(openp)
    return devices

def public_ip():
    try:
        import urllib.request
        return urllib.request.urlopen("https://api.ipify.org", timeout=6).read().decode().strip()
    except Exception: return None

def _reg_key_exists(hive, path):
    try:
        k = winreg.OpenKey(_hkey(hive), path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY); winreg.CloseKey(k); return True
    except Exception: return False

def _listening_ports():
    out = run(["netstat", "-ano", "-p", "TCP"]); res = []
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 4 and p[-2].upper() == "LISTENING":
            try:
                port = int(p[1].rsplit(":", 1)[1]); res.append((port, p[-1]))
            except Exception: pass
    return res

# Puertos de servicios conocidos que NO son proxies (evita falsos positivos: MySQL 33060, etc.).
SAFE_PORTS = {135,139,445,3306,33060,33061,5432,1433,1434,27017,27018,6379,11211,5000,5001,
              7680,8005,9000,49664,49665,49666,49667,49668,49669,3389,5900,1521,2049,25,110,143,993,995}
def _is_socks5(port):
    # Handshake SOCKS5 real: respuesta de EXACTAMENTE 2 bytes = 0x05 + método válido (00/01/02/FF).
    if port in SAFE_PORTS: return False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(0.6)
        s.connect(("127.0.0.1", port)); s.sendall(b"\x05\x01\x00")
        r = s.recv(4)  # un SOCKS5 responde 2 bytes justos; si llegan más (o distinto método), NO es SOCKS5
        s.close()
        return len(r) == 2 and r[0] == 0x05 and r[1] in (0x00, 0x01, 0x02, 0xFF)
    except Exception:
        return False

def scan_network():
    rows = psjson("Get-NetTCPConnection -State Established | Select-Object LocalPort,RemoteAddress,RemotePort,OwningProcess")
    out = []; procs_by_pid = {}
    for pr in psjson("Get-CimInstance Win32_Process | Select-Object ProcessId,Name"):
        if isinstance(pr, dict): procs_by_pid[str(pr.get("ProcessId"))] = pr.get("Name")
    counts = {}
    for r in rows:
        if not isinstance(r, dict): continue
        ra = r.get("RemoteAddress", ""); pid = str(r.get("OwningProcess"))
        if ra in ("127.0.0.1", "::1", "0.0.0.0", "::"): continue
        pn = procs_by_pid.get(pid, "?"); counts[pn] = counts.get(pn, 0) + 1
        out.append({"proc": pn, "remote": "%s:%s" % (ra, r.get("RemotePort")), "lport": r.get("LocalPort"), "pid": pid})
    # marcar procesos con MUCHAS conexiones (posible nodo)
    for o in out: o["flag"] = counts.get(o["proc"], 0) >= 25
    return out

def scan_startup():
    items = []
    for hive, path in [("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
                       ("HKCU", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")]:
        try:
            k = winreg.OpenKey(_hkey(hive), path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(k, i); i += 1
                    susp = any(x in str(val).lower() for x in ["\\temp\\", "\\appdata\\local\\temp", "powershell -e", "-enc "])
                    items.append({"type": "Run", "loc": hive, "name": name, "cmd": str(val), "susp": susp})
                except OSError: break
            winreg.CloseKey(k)
        except Exception: pass
    for t in psjson("Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select-Object TaskName,TaskPath,State")[:200]:
        if isinstance(t, dict):
            items.append({"type": "Tarea", "loc": t.get("TaskPath", ""), "name": t.get("TaskName", ""), "cmd": "", "susp": False})
    return items

def scan_integrity():
    res = {"hosts": [], "proxy": "", "dns": [], "ioc_hits": []}
    hp = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "drivers", "etc", "hosts")
    try:
        with open(hp, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                s = ln.strip()
                if s and not s.startswith("#"):
                    res["hosts"].append(s)
                    for d in IOC_DOMAINS:
                        if d in s and "0.0.0.0" not in s and "127.0.0.1" not in s: res["ioc_hits"].append(s)
    except Exception: pass
    pe = reg_read("HKCU", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "ProxyEnable")
    ps_ = reg_read("HKCU", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "ProxyServer")
    res["proxy"] = ("ACTIVO: " + str(ps_)) if pe else "sin proxy de sistema"
    out = run(["ipconfig", "/all"])
    for ln in out.splitlines():
        if "DNS" in ln and "." in ln:
            res["dns"].append(ln.strip())
    return res

def defender_status():
    d = psjson("Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge")
    if d and isinstance(d[0], dict):
        s = d[0]
        return {"av": s.get("AntivirusEnabled"), "rt": s.get("RealTimeProtectionEnabled"), "age": s.get("AntivirusSignatureAge")}
    return {"av": None, "rt": None, "age": None}

def ip_reputation():
    try:
        import urllib.request
        ip = urllib.request.urlopen("https://api.ipify.org", timeout=6).read().decode().strip()
        return ip
    except Exception:
        return None

# ======================= INTERFAZ =======================
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

BG="#0e1a1c"; BG2="#12282b"; CARD="#0a1416"; LINE="#1c3b3e"; TEAL="#09b1ba"; TEAL2="#33d1a0"; INK="#eafcff"; MUT="#8fc9cd"; RED="#ef4444"; AMBER="#e0a72a"

class OptiShield(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("%s %s · %s" % (APP, VERSION, BRAND))
        self.geometry("1060x720"); self.minsize(920, 620); self.configure(bg=BG)
        self._style()
        self._header()
        self.nb = ttk.Notebook(self); self.nb.pack(fill="both", expand=True, padx=12, pady=(0,10))
        self.tab_dash = self._tab("🏠  Panel")
        self.tab_prox = self._tab("🕵️  Anti-proxyware")
        self.tab_net  = self._tab("🌐  Red")
        self.tab_iot  = self._tab("🏘️  Red local")
        self.tab_priv = self._tab("🔒  Privacidad")
        self.tab_start= self._tab("🧹  Arranque")
        self.tab_integ= self._tab("🛡️  Integridad")
        self.tab_help = self._tab("💬  Apoyo OptiSuite")
        self._build_dashboard(); self._build_proxyware(); self._build_network(); self._build_iot()
        self._build_privacy(); self._build_startup(); self._build_integrity(); self._build_help()
        self._status("Listo. Modo solo-escaneo: nada se cambia sin tu confirmación." + ("" if is_admin() else "  ⚠ Ejecuta como administrador para aplicar cambios."))

    def _style(self):
        s = ttk.Style(self); s.theme_use("clam")
        s.configure("TNotebook", background=BG, borderwidth=0)
        s.configure("TNotebook.Tab", background=BG2, foreground=MUT, padding=(16,9), font=("Segoe UI",10,"bold"))
        s.map("TNotebook.Tab", background=[("selected", BG)], foreground=[("selected", INK)])
        s.configure("TFrame", background=BG)
        s.configure("Card.TFrame", background=CARD)
        s.configure("TLabel", background=BG, foreground=INK, font=("Segoe UI",10))
        s.configure("Mut.TLabel", background=BG, foreground=MUT, font=("Segoe UI",9))
        s.configure("H.TLabel", background=BG, foreground=INK, font=("Segoe UI",13,"bold"))
        s.configure("Teal.TButton", background=TEAL, foreground="#001", font=("Segoe UI",10,"bold"), borderwidth=0, padding=(14,8))
        s.map("Teal.TButton", background=[("active", TEAL2)])
        s.configure("Ghost.TButton", background=BG2, foreground=INK, borderwidth=1, padding=(12,7))
        s.map("Ghost.TButton", background=[("active", LINE)])
        s.configure("Treeview", background=CARD, fieldbackground=CARD, foreground=INK, borderwidth=0, rowheight=24, font=("Segoe UI",9))
        s.configure("Treeview.Heading", background=BG2, foreground=MUT, font=("Segoe UI",9,"bold"))
        s.map("Treeview", background=[("selected", LINE)])
        s.configure("TCheckbutton", background=CARD, foreground=INK, font=("Segoe UI",10))
        s.map("TCheckbutton", background=[("active", CARD)])

    def _header(self):
        h = tk.Frame(self, bg=BG); h.pack(fill="x", padx=14, pady=(12,8))
        tk.Label(h, text="🛡️ OptiShield", bg=BG, fg=INK, font=("Segoe UI",18,"bold")).pack(side="left")
        tk.Label(h, text="  Escudo de privacidad y seguridad · by OptiSuite", bg=BG, fg=MUT, font=("Segoe UI",10)).pack(side="left")
        badge = "ADMIN" if is_admin() else "SIN ADMIN"
        tk.Label(h, text=badge, bg=(BG2 if is_admin() else "#3a2323"), fg=(TEAL2 if is_admin() else "#ffb4b4"),
                 font=("Segoe UI",9,"bold"), padx=10, pady=3).pack(side="right")

    def _tab(self, title):
        f = ttk.Frame(self.nb); self.nb.add(f, text=title); return f

    def _status(self, msg):
        if not hasattr(self, "_sb"):
            self._sb = tk.Label(self, text="", bg=CARD, fg=MUT, anchor="w", font=("Segoe UI",9), padx=12, pady=5)
            self._sb.pack(fill="x", side="bottom")
        self._sb.config(text=msg)

    def _runbg(self, fn, done):
        def wrap():
            try: r = fn()
            except Exception as e: r = e; log("error: %s" % e)
            self.after(0, lambda: done(r))
        threading.Thread(target=wrap, daemon=True).start()

    # ---------- Panel ----------
    def _build_dashboard(self):
        f = self.tab_dash
        ttk.Label(f, text="Estado general del sistema", style="H.TLabel").pack(anchor="w", padx=16, pady=(16,4))
        ttk.Label(f, text="Pulsa «Analizar todo» para un chequeo completo. Nada se cambia sin tu confirmación.", style="Mut.TLabel").pack(anchor="w", padx=16)
        self.cards = tk.Frame(f, bg=BG); self.cards.pack(fill="x", padx=16, pady=14)
        self.card_widgets = {}
        for i,(k,t) in enumerate([("prox","🕵️ Proxyware"),("net","🌐 Red"),("start","🧹 Arranque"),("integ","🛡️ Integridad"),("def","🦠 Defender")]):
            c = tk.Frame(self.cards, bg=CARD, highlightbackground=LINE, highlightthickness=1); c.grid(row=0, column=i, padx=6, ipadx=10, ipady=10, sticky="nsew")
            self.cards.columnconfigure(i, weight=1)
            tk.Label(c, text=t, bg=CARD, fg=INK, font=("Segoe UI",10,"bold")).pack(anchor="w", padx=10, pady=(8,2))
            lbl = tk.Label(c, text="—", bg=CARD, fg=MUT, font=("Segoe UI",16,"bold")); lbl.pack(anchor="w", padx=10, pady=(0,8))
            self.card_widgets[k] = lbl
        actionbar = tk.Frame(f, bg=BG); actionbar.pack(fill="x", padx=16, pady=6)
        ttk.Button(actionbar, text="🔎 Analizar todo", style="Teal.TButton", command=self.scan_all).pack(side="left")
        self.watch_var = tk.BooleanVar(value=False)
        wc = ttk.Checkbutton(actionbar, text="👁 Vigilancia activa (revisa proxyware cada 15 min)", variable=self.watch_var,
                             style="TCheckbutton", command=self.toggle_watch); wc.pack(side="left", padx=16)
        self.dash_log = tk.Text(f, bg=CARD, fg=MUT, height=12, bd=0, font=("Consolas",9), padx=10, pady=8); self.dash_log.pack(fill="both", expand=True, padx=16, pady=(6,16))
        self._watch_job = None

    def _dlog(self, m): self.dash_log.insert("end", m+"\n"); self.dash_log.see("end")

    def scan_all(self):
        self.dash_log.delete("1.0","end"); self._dlog("Analizando…"); self._status("Analizando el sistema…")
        def work():
            r = {}
            r["prox"] = scan_proxyware(); r["net"] = scan_network(); r["start"] = scan_startup()
            r["integ"] = scan_integrity(); r["def"] = defender_status(); return r
        def done(r):
            if isinstance(r, Exception): self._dlog("Error: %s" % r); return
            px = r["prox"]; self._setcard("prox", len([x for x in px if x["hidden"]]), len(px))
            self._setcard("net", len([x for x in r["net"] if x.get("flag")]), None)
            self._setcard("start", len([x for x in r["start"] if x.get("susp")]), None)
            ioc = len(r["integ"]["ioc_hits"]); self._setcard("integ", ioc, None)
            d = r["def"]; self.card_widgets["def"].config(text=("OK" if d.get("av") else "REVISAR"), fg=(TEAL2 if d.get("av") else RED))
            self._dlog("Proxyware detectado: %d (sospechoso: %d)" % (len(px), len([x for x in px if x['hidden']])))
            for x in px: self._dlog("   • %s [%s] — %s" % (x["name"], x["risk"], x["verdict"]))
            self._dlog("Conexiones con muchas salidas (posible nodo): %d" % len([x for x in r['net'] if x.get('flag')]))
            self._dlog("Arranque sospechoso: %d" % len([x for x in r["start"] if x.get("susp")]))
            self._dlog("IOCs en hosts: %d" % ioc)
            self._dlog("Defender: AV=%s RealTime=%s" % (d.get("av"), d.get("rt")))
            self._dlog("\n✔ Análisis terminado. Revisa cada pestaña para actuar.")
            self._status("Análisis terminado.")
            self.refresh_proxyware(px); self.refresh_network(r["net"]); self.refresh_startup(r["start"]); self.refresh_integrity(r["integ"])
        self._runbg(work, done)

    def _setcard(self, k, bad, total):
        lbl = self.card_widgets[k]
        if total is not None: txt = "%d/%d" % (bad, total)
        else: txt = str(bad)
        lbl.config(text=("✔ 0" if bad==0 and total is None else txt), fg=(TEAL2 if bad==0 else (RED if bad>0 else MUT)))

    def toggle_watch(self):
        if self.watch_var.get():
            self._dlog("👁 Vigilancia ACTIVADA (cada 15 min).")
            self._watch_tick()
        else:
            if self._watch_job:
                try: self.after_cancel(self._watch_job)
                except Exception: pass
                self._watch_job = None
            self._dlog("👁 Vigilancia desactivada.")

    def _watch_tick(self):
        if not self.watch_var.get(): return
        def work():
            # chequeo LIGERO: solo procesos/servicios de proxyware (no escaneo completo)
            procs = list_processes(); alerts = []
            for k, d in PROXYWARE_DB.items():
                for pn in d.get("proc", []):
                    if pn.lower() in procs: alerts.append(d["name"])
            return sorted(set(alerts))
        def done(a):
            if isinstance(a, Exception): a = []
            if a:
                self.bell()
                self._dlog("⚠ VIGILANCIA: proceso proxyware activo → %s" % ", ".join(a))
                messagebox.showwarning(APP, "OptiShield detectó proxyware en ejecución:\n\n• " + "\n• ".join(a) + "\n\nVe a la pestaña Anti-proxyware para neutralizarlo.")
            # reprogramar (15 min = 900000 ms)
            if self.watch_var.get():
                self._watch_job = self.after(900000, self._watch_tick)
        self._runbg(work, done)

    # ---------- Anti-proxyware ----------
    def _build_proxyware(self):
        f = self.tab_prox
        top = tk.Frame(f, bg=BG); top.pack(fill="x", padx=16, pady=12)
        ttk.Label(top, text="Anti-proxyware / anti-botnet", style="H.TLabel").pack(side="left")
        ttk.Button(top, text="🔎 Escanear", style="Teal.TButton", command=lambda: self._runbg(scan_proxyware, self.refresh_proxyware)).pack(side="right")
        ttk.Label(f, text="Detecta apps que convierten tu equipo en nodo de proxy (NetNut/Badbox y similares). Marca lo que quieras neutralizar. Lo tuyo (ej. IPRoyal instalado a propósito) déjalo sin marcar.", style="Mut.TLabel", wraplength=980, justify="left").pack(anchor="w", padx=16)
        self.prox_tree = ttk.Treeview(f, columns=("risk","verd","ev"), show="tree headings", selectmode="extended", height=12)
        self.prox_tree.heading("#0", text="Detección"); self.prox_tree.heading("risk", text="Riesgo"); self.prox_tree.heading("verd", text="Veredicto"); self.prox_tree.heading("ev", text="Evidencia")
        self.prox_tree.column("#0", width=230); self.prox_tree.column("risk", width=70); self.prox_tree.column("verd", width=210); self.prox_tree.column("ev", width=420)
        self.prox_tree.pack(fill="both", expand=True, padx=16, pady=10)
        bar = tk.Frame(f, bg=BG); bar.pack(fill="x", padx=16, pady=(0,14))
        ttk.Button(bar, text="🛑 Neutralizar seleccionados (detener + bloquear + cuarentena)", style="Ghost.TButton", command=self.neutralize_proxyware).pack(side="left")
        ttk.Label(bar, text="  (crea copia de seguridad y bloquea sus dominios; no borra archivos)", style="Mut.TLabel").pack(side="left")
        self._prox_data = []

    def refresh_proxyware(self, data):
        if isinstance(data, Exception): return
        self._prox_data = data
        self.prox_tree.delete(*self.prox_tree.get_children())
        if not data:
            self.prox_tree.insert("", "end", text="✔ Sin proxyware detectado", values=("","",""))
            return
        for x in data:
            self.prox_tree.insert("", "end", iid=x["id"], text=x["name"],
                                  values=(x["risk"], x["verdict"], " · ".join(x["evidence"])[:120]))

    def neutralize_proxyware(self):
        if not is_admin(): messagebox.showwarning(APP, "Ejecuta OptiShield como administrador para neutralizar."); return
        sel = self.prox_tree.selection()
        if not sel: messagebox.showinfo(APP, "Selecciona en la lista lo que quieras neutralizar."); return
        if not messagebox.askyesno(APP, "Se detendrán procesos, se deshabilitarán servicios y se bloquearán sus dominios (reversible). ¿Continuar?"): return
        done = 0
        for iid in sel:
            item = next((x for x in self._prox_data if x["id"] == iid), None)
            if not item: continue
            d = PROXYWARE_DB.get(iid, {})
            for pn in d.get("proc", []):
                self._block_firewall_exe(pn)   # regla saliente por ejecutable (antes de matarlo)
                run(["taskkill", "/F", "/IM", pn])
            for sv in d.get("svc", []):
                run(["sc", "stop", sv]); run(["sc", "config", sv, "start=", "disabled"])
            for dom in d.get("domains", []): self._block_domain(dom)
            done += 1; log("neutralizado: %s" % item["name"])
        messagebox.showinfo(APP, "Neutralizados: %d.\nBloqueado en: hosts + firewall saliente. Todo reversible desde 'Integridad'." % done)
        self._runbg(scan_proxyware, self.refresh_proxyware)

    def _block_domain(self, dom):
        # bloqueo por hosts (0.0.0.0) — reversible
        hp = os.path.join(os.environ.get("SystemRoot","C:\\Windows"),"System32","drivers","etc","hosts")
        try:
            with open(hp,"r",encoding="utf-8",errors="ignore") as f: content=f.read()
            if dom not in content:
                with open(hp,"a",encoding="utf-8") as f: f.write("\n0.0.0.0 %s # OptiShield" % dom)
        except Exception as e: log("no pude bloquear %s: %s" % (dom,e))

    def _block_firewall_exe(self, procname):
        # Bloqueo SALIENTE por ruta del ejecutable (regla etiquetada, reversible). No toca reglas del usuario.
        try:
            base = procname[:-4] if procname.lower().endswith(".exe") else procname
            path = ps("(Get-Process %s -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Path)" % base).strip()
            if not path or not os.path.isfile(path): return
            run(["netsh","advfirewall","firewall","add","rule","name=OptiShield block %s" % procname,
                 "dir=out","action=block","program=%s" % path,"enable=yes"])
            log("firewall bloqueado: %s" % path)
        except Exception as e: log("firewall fail %s: %s" % (procname, e))

    # ---------- Red ----------
    def _build_network(self):
        f = self.tab_net
        top = tk.Frame(f, bg=BG); top.pack(fill="x", padx=16, pady=12)
        ttk.Label(top, text="Conexiones de red activas", style="H.TLabel").pack(side="left")
        ttk.Button(top, text="🔎 Escanear", style="Teal.TButton", command=lambda: self._runbg(scan_network, self.refresh_network)).pack(side="right")
        ttk.Label(f, text="Procesos en rojo = muchas conexiones salientes (posible nodo de salida). Revísalos.", style="Mut.TLabel").pack(anchor="w", padx=16)
        self.net_tree = ttk.Treeview(f, columns=("remote","lport","pid"), show="tree headings", height=16)
        self.net_tree.heading("#0", text="Proceso"); self.net_tree.heading("remote", text="Destino"); self.net_tree.heading("lport", text="Puerto local"); self.net_tree.heading("pid", text="PID")
        self.net_tree.column("#0", width=240); self.net_tree.column("remote", width=260); self.net_tree.column("lport", width=100); self.net_tree.column("pid", width=80)
        self.net_tree.tag_configure("flag", foreground=RED)
        self.net_tree.pack(fill="both", expand=True, padx=16, pady=10)

    def refresh_network(self, data):
        if isinstance(data, Exception): return
        self.net_tree.delete(*self.net_tree.get_children())
        for x in data:
            self.net_tree.insert("", "end", text=x["proc"], values=(x["remote"], x["lport"], x["pid"]),
                                 tags=("flag",) if x.get("flag") else ())

    # ---------- Red local (IoT / Badbox) ----------
    def _build_iot(self):
        f = self.tab_iot
        top = tk.Frame(f, bg=BG); top.pack(fill="x", padx=16, pady=12)
        ttk.Label(top, text="Red local — dispositivos y IoT (Badbox)", style="H.TLabel").pack(side="left")
        ttk.Button(top, text="🔎 Escanear red", style="Teal.TButton", command=lambda: (self._status("Escaneando red local…"), self._runbg(scan_local_network, self.refresh_iot))).pack(side="right")
        ttk.Label(f, text="Dispositivos vistos en tu red (tabla ARP). En rojo = puertos de depuración abiertos (5555 ADB, Telnet, FTP…), típico de TV-box/IoT comprometidos por Badbox. OptiShield solo informa: no toca esos equipos.", style="Mut.TLabel", wraplength=980, justify="left").pack(anchor="w", padx=16)
        self.iot_tree = ttk.Treeview(f, columns=("mac","open"), show="tree headings", height=15)
        self.iot_tree.heading("#0", text="IP"); self.iot_tree.heading("mac", text="MAC"); self.iot_tree.heading("open", text="Puertos de depuración abiertos")
        self.iot_tree.column("#0", width=180); self.iot_tree.column("mac", width=180); self.iot_tree.column("open", width=440)
        self.iot_tree.tag_configure("risk", foreground=RED)
        self.iot_tree.pack(fill="both", expand=True, padx=16, pady=10)
        # Reputación de IP pública
        ipbar = tk.Frame(f, bg=BG); ipbar.pack(fill="x", padx=16, pady=(0,14))
        self.ip_lbl = tk.Label(ipbar, text="Tu IP pública: (pulsa Ver)", bg=BG, fg=MUT, font=("Segoe UI",10)); self.ip_lbl.pack(side="left")
        ttk.Button(ipbar, text="🌐 Ver mi IP y reputación", style="Ghost.TButton", command=self.check_ip).pack(side="right")

    def refresh_iot(self, data):
        if isinstance(data, Exception): return
        self.iot_tree.delete(*self.iot_tree.get_children())
        if not data:
            self.iot_tree.insert("", "end", text="(sin dispositivos en la tabla ARP)", values=("","")); return
        for d in data:
            self.iot_tree.insert("", "end", text=d["ip"], values=(d["mac"], " · ".join(d.get("open", [])) or "—"),
                                 tags=("risk",) if d.get("risk") else ())
        self._status("Red local: %d dispositivos, %d con puertos de depuración." % (len(data), len([x for x in data if x.get('risk')])))

    def check_ip(self):
        self.ip_lbl.config(text="Consultando…")
        def done(ip):
            if not ip: self.ip_lbl.config(text="No pude obtener la IP (¿sin internet?)"); return
            self.ip_lbl.config(text="Tu IP pública: %s" % ip)
            if messagebox.askyesno(APP, "Tu IP pública es %s.\n\n¿Abrir su reputación en AbuseIPDB (navegador)?\nSirve para ver si tu IP figura como abusiva (a veces por otro usuario del ISP)." % ip):
                webbrowser.open("https://www.abuseipdb.com/check/%s" % ip)
        self._runbg(public_ip, done)

    # ---------- Privacidad ----------
    def _build_privacy(self):
        f = self.tab_priv
        ttk.Label(f, text="Blindaje de privacidad y telemetría", style="H.TLabel").pack(anchor="w", padx=16, pady=(14,2))
        ttk.Label(f, text="Marca lo que quieras desactivar. NO se toca Defender, Firewall ni UAC. Todo reversible.", style="Mut.TLabel").pack(anchor="w", padx=16)
        wrap = tk.Frame(f, bg=CARD, highlightbackground=LINE, highlightthickness=1); wrap.pack(fill="both", expand=True, padx=16, pady=12)
        self.priv_vars = {}
        for tw in PRIVACY_TWEAKS:
            v = tk.BooleanVar(value=True); self.priv_vars[tw["id"]] = v
            cb = ttk.Checkbutton(wrap, text=tw["name"], variable=v, style="TCheckbutton"); cb.pack(anchor="w", padx=14, pady=4)
        bar = tk.Frame(f, bg=BG); bar.pack(fill="x", padx=16, pady=(0,14))
        ttk.Button(bar, text="🔒 Aplicar seleccionados", style="Teal.TButton", command=lambda: self.apply_privacy(True)).pack(side="left")
        ttk.Button(bar, text="↩ Revertir seleccionados", style="Ghost.TButton", command=lambda: self.apply_privacy(False)).pack(side="left", padx=8)

    def apply_privacy(self, enable_privacy):
        if not is_admin(): messagebox.showwarning(APP, "Ejecuta OptiShield como administrador para cambiar estos ajustes."); return
        chosen = [tw for tw in PRIVACY_TWEAKS if self.priv_vars[tw["id"]].get()]
        if not chosen: messagebox.showinfo(APP, "Marca al menos una opción."); return
        # backup
        entries = []
        for tw in chosen:
            for hv, path, name, kind, on, off in tw.get("reg", []): entries.append((hv, path, name))
        backup_write(entries)
        n = 0
        for tw in chosen:
            for hv, path, name, kind, on, off in tw.get("reg", []):
                try: reg_write(hv, path, name, kind, (off if enable_privacy else on)); n += 1
                except Exception as e: log("reg fail %s: %s" % (name, e))
            for sv in tw.get("svc", []):
                if enable_privacy:
                    run(["sc","stop",sv]); run(["sc","config",sv,"start=","disabled"])
                else:
                    run(["sc","config",sv,"start=","demand"])
        act = "aplicados (privacidad ON)" if enable_privacy else "revertidos"
        messagebox.showinfo(APP, "Ajustes %s: %d valores. Reinicia el PC para que todo quede al 100%%." % (act, n))
        self._status("Privacidad: %d ajustes %s." % (n, act))

    # ---------- Arranque ----------
    def _build_startup(self):
        f = self.tab_start
        top = tk.Frame(f, bg=BG); top.pack(fill="x", padx=16, pady=12)
        ttk.Label(top, text="Auditoría de arranque", style="H.TLabel").pack(side="left")
        ttk.Button(top, text="🔎 Escanear", style="Teal.TButton", command=lambda: self._runbg(scan_startup, self.refresh_startup)).pack(side="right")
        ttk.Label(f, text="Programas, tareas y entradas que arrancan con Windows. En rojo = sospechoso (Temp, comandos ofuscados).", style="Mut.TLabel").pack(anchor="w", padx=16)
        self.start_tree = ttk.Treeview(f, columns=("type","loc","cmd"), show="tree headings", height=16)
        self.start_tree.heading("#0", text="Nombre"); self.start_tree.heading("type", text="Tipo"); self.start_tree.heading("loc", text="Ubicación"); self.start_tree.heading("cmd", text="Comando")
        self.start_tree.column("#0", width=220); self.start_tree.column("type", width=80); self.start_tree.column("loc", width=120); self.start_tree.column("cmd", width=440)
        self.start_tree.tag_configure("susp", foreground=RED)
        self.start_tree.pack(fill="both", expand=True, padx=16, pady=10)

    def refresh_startup(self, data):
        if isinstance(data, Exception): return
        self.start_tree.delete(*self.start_tree.get_children())
        for x in data:
            self.start_tree.insert("", "end", text=x["name"], values=(x["type"], x["loc"], x["cmd"][:120]),
                                   tags=("susp",) if x.get("susp") else ())

    # ---------- Integridad ----------
    def _build_integrity(self):
        f = self.tab_integ
        top = tk.Frame(f, bg=BG); top.pack(fill="x", padx=16, pady=12)
        ttk.Label(top, text="Integridad del sistema", style="H.TLabel").pack(side="left")
        ttk.Button(top, text="🔎 Escanear", style="Teal.TButton", command=lambda: self._runbg(scan_integrity, self.refresh_integrity)).pack(side="right")
        self.integ_txt = tk.Text(f, bg=CARD, fg=INK, bd=0, font=("Consolas",9), padx=10, pady=8); self.integ_txt.pack(fill="both", expand=True, padx=16, pady=10)
        bar = tk.Frame(f, bg=BG); bar.pack(fill="x", padx=16, pady=(0,14))
        ttk.Button(bar, text="🧽 Quitar bloqueos hosts", style="Ghost.TButton", command=self.clean_hosts).pack(side="left")
        ttk.Button(bar, text="🧯 Quitar reglas firewall", style="Ghost.TButton", command=self.clean_firewall).pack(side="left", padx=8)
        ttk.Button(bar, text="📄 Exportar informe", style="Ghost.TButton", command=self.export_report).pack(side="right")

    def refresh_integrity(self, r):
        if isinstance(r, Exception): return
        t = self.integ_txt; t.delete("1.0","end")
        t.insert("end", "PROXY DEL SISTEMA: %s\n\n" % r["proxy"])
        t.insert("end", "DNS:\n" + ("\n".join(r["dns"]) or "  (no leído)") + "\n\n")
        if r["ioc_hits"]:
            t.insert("end", "⚠ DOMINIOS IOC EN HOSTS (revisar):\n" + "\n".join(r["ioc_hits"]) + "\n\n")
        else:
            t.insert("end", "✔ Sin dominios IOC sospechosos en hosts.\n\n")
        t.insert("end", "ENTRADAS ACTIVAS EN HOSTS (%d):\n" % len(r["hosts"]) + ("\n".join(r["hosts"][:60]) or "  (vacío)"))

    def clean_hosts(self):
        if not is_admin(): messagebox.showwarning(APP,"Requiere administrador."); return
        hp = os.path.join(os.environ.get("SystemRoot","C:\\Windows"),"System32","drivers","etc","hosts")
        try:
            with open(hp,"r",encoding="utf-8",errors="ignore") as f: lines=f.readlines()
            keep=[ln for ln in lines if "# OptiShield" not in ln]
            with open(hp,"w",encoding="utf-8") as f: f.writelines(keep)
            messagebox.showinfo(APP,"Bloqueos de OptiShield retirados del archivo hosts.")
        except Exception as e: messagebox.showerror(APP,"No pude editar hosts: %s"%e)

    def clean_firewall(self):
        if not is_admin(): messagebox.showwarning(APP,"Requiere administrador."); return
        # Borra SOLO las reglas creadas por OptiShield (nombre "OptiShield block ..."). Nunca toca otras.
        out = run(["netsh","advfirewall","firewall","show","rule","name=all"])
        names = sorted(set(m.group(1).strip() for m in re.finditer(r"(OptiShield block [^\r\n]+)", out)))
        removed = 0
        for nm in names:
            run(["netsh","advfirewall","firewall","delete","rule","name=%s" % nm]); removed += 1
        messagebox.showinfo(APP,"Reglas de firewall de OptiShield eliminadas: %d." % removed)

    def export_report(self):
        p = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="OptiShield-informe.txt", filetypes=[("Texto","*.txt")])
        if not p: return
        try:
            with open(p,"w",encoding="utf-8") as f:
                f.write("OptiShield %s — informe %s\n\n" % (VERSION, datetime.datetime.now().strftime("%Y-%m-%d %H:%M")))
                f.write("=== Proxyware ===\n")
                for x in (self._prox_data or []): f.write("- %s [%s] %s | %s\n" % (x["name"],x["risk"],x["verdict"]," · ".join(x["evidence"])))
                f.write("\n=== Defender ===\n%s\n" % str(defender_status()))
                f.write("\nGenerado localmente. OptiShield no envía datos a ningún servidor.\n")
            messagebox.showinfo(APP,"Informe guardado.")
        except Exception as e: messagebox.showerror(APP,str(e))

    # ---------- Apoyo OptiSuite ----------
    def _build_help(self):
        f = self.tab_help
        box = tk.Frame(f, bg=CARD, highlightbackground=LINE, highlightthickness=1); box.pack(fill="both", expand=True, padx=40, pady=30)
        tk.Label(box, text="🛡️ OptiShield", bg=CARD, fg=INK, font=("Segoe UI",22,"bold")).pack(pady=(24,2))
        tk.Label(box, text="Una herramienta gratuita de OptiSuite para proteger tu privacidad y seguridad.", bg=CARD, fg=MUT, font=("Segoe UI",11)).pack()
        tk.Label(box, text="Defensiva · reversible · 100%% local (no enviamos tus datos a ningún sitio).", bg=CARD, fg=TEAL2, font=("Segoe UI",10,"bold")).pack(pady=(4,18))
        info = tk.Frame(box, bg=CARD); info.pack(pady=6)
        tk.Label(info, text="📱 WhatsApp soporte:  %s" % WHATSAPP, bg=CARD, fg=INK, font=("Segoe UI",11)).pack(anchor="w", pady=3)
        tk.Label(info, text="✉️  %s" % EMAIL, bg=CARD, fg=INK, font=("Segoe UI",11)).pack(anchor="w", pady=3)
        tk.Label(info, text="🌐 %s" % WEB, bg=CARD, fg=INK, font=("Segoe UI",11)).pack(anchor="w", pady=3)
        btns = tk.Frame(box, bg=CARD); btns.pack(pady=20)
        ttk.Button(btns, text="📱 Abrir WhatsApp", style="Teal.TButton", command=lambda: webbrowser.open(WA_URL)).pack(side="left", padx=6)
        ttk.Button(btns, text="🌐 Visitar OptiSuite", style="Ghost.TButton", command=lambda: webbrowser.open("https://"+WEB)).pack(side="left", padx=6)
        tk.Label(box, text="© OptiSuite · OptiShield es gratuito. Si te ayuda, compártelo.", bg=CARD, fg=MUT, font=("Segoe UI",9)).pack(side="bottom", pady=16)

def main():
    if not is_admin() and "--noelevate" not in sys.argv:
        # intentar elevar para poder aplicar cambios; si el usuario cancela, sigue en modo lectura
        try:
            r = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, '"%s" --noelevate' % os.path.abspath(sys.argv[0]), None, 1)
            if r > 32: sys.exit(0)
        except Exception: pass
    app = OptiShield(); app.mainloop()

if __name__ == "__main__":
    main()
