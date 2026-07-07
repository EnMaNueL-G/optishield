# -*- coding: utf-8 -*-
"""
OptiShield — Escudo de privacidad y seguridad (Windows).  by OptiSuite
Defensivo · reversible · sin debilitar la seguridad (Defender/Firewall/UAC intactos).
Sin dependencias externas: solo Python estándar + tkinter + comandos de Windows.
"""
import os, sys, json, subprocess, threading, ctypes, socket, datetime, webbrowser, tempfile, re

APP = "OptiShield"
VERSION = "1.1.0"
BRAND = "OptiSuite"
WHATSAPP = "+56 9 7832 7863"
WA_URL = "https://wa.me/56978327863"
EMAIL = "support@optisuite.app"
WEB = "optisuite.app"
GITHUB = "https://github.com/EnMaNueL-G/optishield"
KOFI = "https://ko-fi.com/optisuite"
LIBERAPAY = "https://liberapay.com/OptiSuite.app/donate"
BINANCE_ID = "1140153333"
USDT_BSC = "0x0a9a0d8d816ede885d1d4a5c94369a72ef86b3c1"

# ---- rutas de datos (config, backups, logs) ----
DATA_DIR = os.path.join(os.environ.get("PROGRAMDATA", os.path.expanduser("~")), "OptiShield")
BACKUP_DIR = os.path.join(DATA_DIR, "backups")
LOG_DIR = os.path.join(DATA_DIR, "logs")
for d in (DATA_DIR, BACKUP_DIR, LOG_DIR):
    try: os.makedirs(d, exist_ok=True)
    except Exception: pass

CREATE_NO_WINDOW = 0x08000000

# ======================= IDIOMA (i18n ES/EN) =======================
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")
def load_config():
    try:
        with open(CONFIG_FILE, encoding="utf-8") as f: return json.load(f)
    except Exception: return {}
def save_config(c):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f: json.dump(c, f, ensure_ascii=False, indent=2)
    except Exception: pass

def _detect_lang():
    cfg = load_config()
    if cfg.get("lang") in ("es", "en"): return cfg["lang"]
    try:
        import locale
        loc = (locale.getdefaultlocale()[0] or "").lower()
    except Exception:
        loc = ""
    return "en" if loc.startswith("en") else "es"

LANG = _detect_lang()

# Traducciones inglesas indexadas por el texto español EXACTO (mismo string que se ve en la UI).
# Lo que no esté aquí, se queda en español (degradación elegante).
TR = {
    # tabs
    "🏠  Panel": "🏠  Dashboard",
    "🕵️  Anti-proxyware": "🕵️  Anti-proxyware",
    "🌐  Red": "🌐  Network",
    "🏘️  Red local": "🏘️  Local network",
    "📺  Limpiar TV": "📺  Clean TV",
    "🔒  Privacidad": "🔒  Privacy",
    "🧹  Arranque": "🧹  Startup",
    "🛡️  Integridad": "🛡️  Integrity",
    "💬  Apoyo OptiSuite": "💬  Support OptiSuite",
    # header / estado
    "  Escudo de privacidad y seguridad · by OptiSuite": "  Privacy & security shield · by OptiSuite",
    "ADMIN": "ADMIN", "SIN ADMIN": "NO ADMIN",
    "Listo. Modo solo-escaneo: nada se cambia sin tu confirmación.": "Ready. Scan-only mode: nothing changes without your confirmation.",
    "  ⚠ Ejecuta como administrador para aplicar cambios.": "  ⚠ Run as administrator to apply changes.",
    "Analizando el sistema…": "Analyzing the system…",
    "Análisis terminado.": "Analysis complete.",
    "Escaneando red local…": "Scanning local network…",
    "Escaneo profundo en curso (barriendo toda tu subred)…": "Deep scan in progress (sweeping your whole subnet)…",
    "Consultando…": "Checking…",
    # panel
    "Estado general del sistema": "System overview",
    "Pulsa «Analizar todo» para un chequeo completo. Nada se cambia sin tu confirmación.": "Click «Analyze all» for a full check. Nothing is changed without your confirmation.",
    "🔎 Analizar todo": "🔎 Analyze all",
    "👁 Vigilancia activa (revisa proxyware cada 15 min)": "👁 Active monitoring (checks proxyware every 15 min)",
    # anti-proxyware
    "Anti-proxyware / anti-botnet": "Anti-proxyware / anti-botnet",
    "🔎 Escanear": "🔎 Scan",
    "Detecta apps que convierten tu equipo en nodo de proxy (NetNut/Badbox y similares). Marca lo que quieras neutralizar. Lo tuyo (ej. IPRoyal instalado a propósito) déjalo sin marcar.": "Detects apps that turn your PC into a proxy node (NetNut/Badbox and similar). Check what you want to neutralize. Leave your own (e.g. IPRoyal installed on purpose) unchecked.",
    "Detección": "Detection", "Riesgo": "Risk", "Veredicto": "Verdict", "Evidencia": "Evidence",
    "🛑 Neutralizar seleccionados (detener + bloquear + cuarentena)": "🛑 Neutralize selected (stop + block + quarantine)",
    "  (crea copia de seguridad y bloquea sus dominios; no borra archivos)": "  (creates a backup and blocks their domains; does not delete files)",
    "✔ Sin proxyware detectado": "✔ No proxyware detected",
    # red
    "Conexiones de red activas": "Active network connections",
    "En rojo = muchas conexiones salientes (posible nodo) O destino que parece proxy/residencial. La columna Organización viene del DNS inverso (solo DNS, nada sale a terceros).": "Red = many outbound connections (possible node) OR a destination that looks like proxy/residential. The Organization column comes from reverse DNS (DNS only, nothing sent to third parties).",
    "Proceso": "Process", "Destino": "Destination", "Organización (DNS inverso)": "Organization (reverse DNS)", "PID": "PID",
    # red local
    "Red local — dispositivos y IoT (Badbox)": "Local network — devices & IoT (Badbox)",
    "🔎 Escaneo rápido (ARP)": "🔎 Quick scan (ARP)",
    "🔬 Escaneo profundo": "🔬 Deep scan",
    "Rápido = dispositivos ya vistos (tabla ARP). Profundo = barrido activo de TODA tu subred (ping .1-.254 + fabricante por MAC), tarda ~30-60s. En rojo = puertos de depuración abiertos (5555 ADB, Telnet, FTP…) en un equipo NO marcado de confianza — típico de TV-box/IoT comprometidos por Badbox. Selecciona un equipo y pulsa «Detalles» para ver por qué; marca tus propios equipos como «de confianza» para que dejen de salir en rojo.": "Quick = devices already seen (ARP table). Deep = active sweep of your WHOLE subnet (ping .1-.254 + vendor by MAC), takes ~30-60s. Red = open debug ports (5555 ADB, Telnet, FTP…) on a device NOT marked as trusted — typical of TV-boxes/IoT compromised by Badbox. Select a device and click «Details» to see why; mark your own devices as «trusted» so they stop showing in red.",
    "IP": "IP", "MAC": "MAC", "Fabricante": "Vendor", "Nombre / dispositivo": "Name / device",
    "Puertos de depuración abiertos": "Open debug ports",
    "✓ Marcar de confianza": "✓ Mark as trusted", "✕ Quitar de confianza": "✕ Remove trust",
    "🔎 Detalles del equipo": "🔎 Device details", "(doble clic = detalles)": "(double-click = details)",
    "Tu IP pública: (pulsa Ver)": "Your public IP: (click View)",
    "🌐 Ver mi IP y reputación": "🌐 View my IP & reputation",
    "(sin dispositivos)": "(no devices)",
    "No pude obtener la IP (¿sin internet?)": "Couldn't get the IP (no internet?)",
    "Tu IP pública: %s": "Your public IP: %s",
    # limpiar TV
    "Limpiar TV / TV-box Android (ADB)": "Clean Android TV / TV-box (ADB)",
    "Conecta tu TV por USB o por red (habilitando temporalmente la Depuración). OptiShield lista sus apps, marca las sideload/sospechosas (típicas de Badbox), te deja desactivarlas o desinstalarlas y, al terminar, CIERRA la depuración. Todo con tu aprobación.": "Connect your TV by USB or over the network (temporarily enabling Debugging). OptiShield lists its apps, flags the sideloaded/suspicious ones (typical of Badbox), lets you disable or uninstall them and, when finished, CLOSES debugging. All with your approval.",
    "↻ Detectar": "↻ Detect", "IP del TV (red):": "TV IP (network):", "🔌 Conectar por red": "🔌 Connect over network",
    "Paquete (app)": "Package (app)", "Instalador": "Installer", "📋 Listar apps": "📋 List apps",
    "🚫 Desactivar": "🚫 Disable", "🗑 Desinstalar": "🗑 Uninstall", "🔒 Cerrar depuración del TV": "🔒 Close TV debugging",
    "⚠ No encuentro ADB. Pon platform-tools junto al programa o instálalo.": "⚠ ADB not found. Put platform-tools next to the program or install it.",
    "ADB OK. Sin dispositivos. Conecta el TV por USB o pulsa 'Conectar por red'.": "ADB OK. No devices. Connect the TV by USB or click 'Connect over network'.",
    "✅ Conectado: %s  [%s]": "✅ Connected: %s  [%s]", "Conectando a %s…": "Connecting to %s…",
    "No pude conectar. ¿Activaste 'Depuración por red' en el TV y aceptaste el aviso?": "Couldn't connect. Did you enable 'Network debugging' on the TV and accept the prompt?",
    "🔒 Depuración cerrada en el TV.": "🔒 Debugging closed on the TV.",
    # privacidad
    "Blindaje de privacidad y telemetría": "Privacy & telemetry hardening",
    "Marca lo que quieras desactivar. NO se toca Defender, Firewall ni UAC. Todo reversible.": "Check what you want to disable. Defender, Firewall and UAC are NOT touched. Everything is reversible.",
    "🔒 Aplicar seleccionados": "🔒 Apply selected", "↩ Revertir seleccionados": "↩ Revert selected",
    # arranque
    "Auditoría de arranque": "Startup audit",
    "Programas, tareas y entradas que arrancan con Windows. En rojo = sospechoso (Temp, comandos ofuscados). En ámbar = OBSOLETO: apunta a un archivo que ya no existe (típico de algo que desinstalaste). Puedes DESACTIVAR (deja de arrancar pero se conserva) o ELIMINAR lo que no sirva — todo reversible.": "Programs, tasks and entries that start with Windows. Red = suspicious (Temp, obfuscated commands). Amber = ORPHANED: points to a file that no longer exists (typical of something you uninstalled). You can DISABLE (stops starting but is kept) or DELETE what you don't need — all reversible.",
    "Nombre": "Name", "Tipo": "Type", "Ubicación": "Location", "Estado": "Status", "Comando": "Command",
    "⛔ Desactivar": "⛔ Disable", "✅ Activar": "✅ Enable", "🧹 Limpiar obsoletas": "🧹 Clean orphaned", "🗑 Eliminar": "🗑 Delete",
    "Desactivar es reversible (Activar lo devuelve). Requiere administrador.": "Disabling is reversible (Enable brings it back). Requires administrator.",
    # integridad
    "Integridad del sistema": "System integrity",
    "🧽 Quitar bloqueos hosts": "🧽 Remove hosts blocks", "🧯 Quitar reglas firewall": "🧯 Remove firewall rules",
    "📄 Exportar informe": "📄 Export report",
    # apoyo
    "Una herramienta gratuita de OptiSuite para proteger tu privacidad y seguridad.": "A free OptiSuite tool to protect your privacy and security.",
    "Defensiva · reversible · 100%% local (no enviamos tus datos a ningún sitio).": "Defensive · reversible · 100%% local (we never send your data anywhere).",
    "Defensiva · reversible · 100% local (no enviamos tus datos a ningún sitio).": "Defensive · reversible · 100% local (we never send your data anywhere).",
    "Es gratis y sin anuncios. Si te ayuda, una estrella en GitHub o una aportación\nmantienen OptiSuite vivo. ¡Gracias! 🙌": "It's free and ad-free. If it helps you, a GitHub star or a small donation\nkeep OptiSuite alive. Thank you! 🙌",
    "⭐ Estrella en GitHub": "⭐ Star on GitHub", "☕ Ko-fi": "☕ Ko-fi", "♡ Liberapay": "♡ Liberapay", "🌐 Visitar OptiSuite": "🌐 Visit OptiSuite",
    "O con criptomonedas (toca para copiar):": "Or with crypto (tap to copy):",
    "© OptiSuite · OptiShield es gratuito. Si te ayuda, compártelo.": "© OptiSuite · OptiShield is free. If it helps you, share it.",
}

def tr(s):
    return TR.get(s, s) if LANG == "en" else s

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
    t = load_trusted()
    for dev in devices:
        openp = []
        for port, label in DEBUG_PORTS.items():
            if _port_open(dev["ip"], port): openp.append("%d %s" % (port, label))
        dev["open"] = openp
        dev["vendor"] = mac_vendor(dev["mac"]) or "(desconocido)"
        dev["host"] = host_name(dev["ip"])
        dev["trusted"] = is_trusted(t, dev["ip"], dev["mac"])
        dev["risk"] = bool(openp) and not dev["trusted"]
    return devices

# OUI (prefijo MAC) -> fabricante. Lista offline de los más comunes en casa (privado, sin consultar a terceros).
OUI = {
    "fc-fb-fb":"Cisco","00-1a-11":"Google","f4-f5-e8":"Google","d8-6c-63":"Google","1c-f2-9a":"Google",
    "44-65-0d":"Amazon","fc-a1-83":"Amazon","68-37-e9":"Amazon","74-c2-46":"Amazon","0c-47-c9":"Amazon",
    "ac-63-be":"Amazon (Fire TV)","f0-27-2d":"Amazon","cc-f7-35":"Samsung","5c-49-7d":"Samsung","8c-77-12":"Samsung",
    "e8-50-8b":"Samsung","bc-14-85":"Samsung","78-bd-bc":"Samsung","fc-03-9f":"Samsung","00-1e-75":"LG",
    "b8-1d-aa":"LG","2c-59-8a":"LG","10-68-3f":"LG","a8-16-b2":"LG","cc-2d-8c":"LG","70-91-8f":"Sony",
    "fc-0f-e6":"Sony","24-21-ab":"Sony","54-42-49":"Sony","b4-52-7e":"Sony","d0-73-d5":"Xiaomi",
    "64-b4-73":"Xiaomi","28-6c-07":"Xiaomi","f8-a4-5f":"Xiaomi","50-ec-50":"Xiaomi","ac-c1-ee":"Xiaomi",
    "b0-be-76":"TP-Link","50-c7-bf":"TP-Link","a4-2b-b0":"TP-Link","c0-06-c3":"TP-Link","54-af-97":"TP-Link",
    "dc-a6-32":"Raspberry Pi","b8-27-eb":"Raspberry Pi","e4-5f-01":"Raspberry Pi","24-0a-c4":"Espressif (ESP/IoT)",
    "30-ae-a4":"Espressif (ESP/IoT)","a4-cf-12":"Espressif (ESP/IoT)","bc-dd-c2":"Espressif (ESP/IoT)",
    "3c-84-6a":"TP-Link","d8-0d-17":"TP-Link","00-17-88":"Philips Hue","ec-b5-fa":"Philips Hue",
    "b0-c5-54":"D-Link","1c-bd-b9":"D-Link","c8-3a-35":"Tenda","04-d3-b0":"Realme/Oppo","c4-9d-ed":"Microsoft",
    "70-bb-e9":"Microsoft (Xbox)","98-5f-d3":"Microsoft (Xbox)","00-50-56":"VMware","08-00-27":"VirtualBox",
}
def mac_vendor(mac):
    if not mac: return ""
    pref = mac.lower().replace(":", "-")[:8]
    return OUI.get(pref, "")

# ---- Equipos de confianza (para NO marcar en rojo tus propios dispositivos) ----
TRUSTED_FILE = os.path.join(DATA_DIR, "trusted.json")
def _norm_mac(mac): return (mac or "").lower().replace(":", "-")
def load_trusted():
    try:
        import json
        with open(TRUSTED_FILE, encoding="utf-8") as f:
            d = json.load(f)
        return {"ips": set(d.get("ips", [])), "macs": set(_norm_mac(x) for x in d.get("macs", []))}
    except Exception:
        return {"ips": set(), "macs": set()}
def save_trusted(t):
    try:
        import json
        with open(TRUSTED_FILE, "w", encoding="utf-8") as f:
            json.dump({"ips": sorted(t["ips"]), "macs": sorted(t["macs"])}, f, indent=2)
    except Exception: pass
def is_trusted(t, ip, mac):
    return (ip in t["ips"]) or (bool(mac) and _norm_mac(mac) in t["macs"])

def host_name(ip):
    """Nombre del dispositivo por DNS inverso (rápido y local). '' si no resuelve."""
    try:
        socket.setdefaulttimeout(0.7)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(None)

# Explicación de por qué un puerto de depuración abierto es sospechoso (para evitar falsas alarmas y dar contexto).
PORT_INFO = {
    5555: "Depuración ADB de Android expuesta a la red — el vector típico de Badbox. En una TV-box legítima debería estar CERRADO. Si es tu equipo y activaste ADB por red a propósito, márcalo de confianza y ciérralo al terminar.",
    23:   "Telnet: acceso remoto SIN cifrar, muy usado por botnets IoT (Mirai/Badbox). Casi ningún dispositivo doméstico moderno debería tenerlo abierto.",
    21:   "FTP: transferencia de archivos sin cifrar; en un equipo de casa normal no suele estar abierto.",
    9527: "Puerto de depuración/UART común en cámaras IP y TV-box baratas comprometidas.",
    7001: "Puerto de depuración/administración; sospechoso en un dispositivo de consumo.",
    4444: "Puerto asociado a backdoors (p. ej. Metasploit); muy sospechoso.",
}

def _my_subnet():
    """Devuelve (base, mi_ip) p.ej. ('192.168.1.', '192.168.1.34'). Asume /24 (lo típico en casa)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close()
        return ip.rsplit(".", 1)[0] + ".", ip
    except Exception:
        return None, None

def _ping(ip):
    out = run(["ping", "-n", "1", "-w", "400", ip])
    return "TTL=" in out or "ttl=" in out

def scan_local_network_deep(progress=None):
    """Barrido ACTIVO de TU subred (/24): ping a .1-.254 + fabricante por MAC + puertos de depuración.
    Solo tu propia red. Más completo que el ARP pero tarda más."""
    base, myip = _my_subnet()
    if not base: return []
    alive = []; lock = threading.Lock()
    def worker(n):
        ip = "%s%d" % (base, n)
        if _ping(ip):
            with lock: alive.append(ip)
    # barrido en tandas de 32 hilos
    targets = list(range(1, 255))
    for i in range(0, len(targets), 32):
        ths = [threading.Thread(target=worker, args=(n,)) for n in targets[i:i+32]]
        for t in ths: t.start()
        for t in ths: t.join()
        if progress: progress(min(i+32, 254), 254)
    # MACs desde ARP (ya poblado por los pings)
    arp = run(["arp", "-a"]); macs = {}
    for line in arp.splitlines():
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{11,17})", line)
        if m: macs[m.group(1)] = m.group(2)
    t = load_trusted()
    devices = []
    for ip in sorted(alive, key=lambda x: int(x.rsplit(".",1)[1])):
        mac = macs.get(ip, "")
        openp = [ "%d %s" % (p, l) for p, l in DEBUG_PORTS.items() if _port_open(ip, p) ]
        trusted = is_trusted(t, ip, mac) or (ip == myip)
        devices.append({"ip": ip, "mac": mac,
                        "vendor": mac_vendor(mac) or ("(este PC)" if ip == myip else "(desconocido)"),
                        "host": ("(este PC)" if ip == myip else host_name(ip)),
                        "open": openp, "trusted": trusted, "risk": bool(openp) and not trusted})
    return devices

def public_ip():
    try:
        import urllib.request
        return urllib.request.urlopen("https://api.ipify.org", timeout=6).read().decode().strip()
    except Exception: return None

# ======================= MÓDULO ADB (limpiar TV / TV-box Android) =======================
# Tiendas legítimas: si una app de terceros NO viene de aquí, es sideload (típico de Badbox).
KNOWN_STORES = {"com.android.vending", "com.amazon.venezia", "com.sec.android.app.samsungapps",
                "com.huawei.appmarket", "com.xiaomi.market", "com.google.android.packageinstaller"}
# Firmas de nombre asociadas a adware/Badbox/proxyware en Android (heurístico, conservador).
BADBOX_HINTS = ["triada", "rooter", "hnyp", "proxy", "adsdk", "hidden", "silent", "clicker",
                "com.rock.", "gota", "ad.sdk", "peer", "residential"]
def _find_adb():
    """Localiza adb.exe: junto al exe (platform-tools), PATH, o rutas comunes."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    cands = [os.path.join(base, "platform-tools", "adb.exe"),
             os.path.join(os.path.dirname(os.path.abspath(__file__)), "platform-tools", "adb.exe")]
    w = run(["where", "adb"]).strip().splitlines()
    if w: cands.append(w[0].strip())
    for p in (os.environ.get("LOCALAPPDATA",""), os.environ.get("USERPROFILE","")):
        if p: cands.append(os.path.join(p, "Android", "Sdk", "platform-tools", "adb.exe"))
    for c in cands:
        if c and os.path.isfile(c): return c
    return None

def adb_connect(adb, ip):
    if ":" not in ip: ip = ip + ":5555"
    return run([adb, "connect", ip])

def adb_devices(adb):
    out = run([adb, "devices"]); devs = []
    for ln in out.splitlines()[1:]:
        p = ln.split()
        if len(p) >= 2 and p[1] == "device": devs.append(p[0])
    return devs

def adb_model(adb, serial):
    return (run([adb, "-s", serial, "shell", "getprop", "ro.product.model"]).strip() + " / " +
            run([adb, "-s", serial, "shell", "getprop", "ro.product.manufacturer"]).strip())

def adb_list_packages(adb, serial):
    """Apps de terceros con su instalador. Marca las sideload/sospechosas."""
    out = run([adb, "-s", serial, "shell", "pm", "list", "packages", "-3", "-i"])
    pkgs = []
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln.startswith("package:"): continue
        m = re.match(r"package:(\S+)(?:\s+installer=(\S+))?", ln)
        if not m: continue
        pkg = m.group(1); inst = (m.group(2) or "").strip()
        sideload = inst in ("", "null") or inst not in KNOWN_STORES
        badhint = any(h in pkg.lower() for h in BADBOX_HINTS)
        risk = "ALTO" if badhint else ("revisar" if sideload else "ok")
        pkgs.append({"pkg": pkg, "installer": inst or "(ninguno/sideload)", "risk": risk, "flag": badhint or sideload})
    return sorted(pkgs, key=lambda x: (x["risk"] != "ALTO", x["risk"] != "revisar", x["pkg"]))

def adb_disable(adb, serial, pkg):
    return run([adb, "-s", serial, "shell", "pm", "disable-user", "--user", "0", pkg])

def adb_uninstall(adb, serial, pkg):
    return run([adb, "-s", serial, "shell", "pm", "uninstall", "--user", "0", pkg])

def adb_close_debug(adb, serial):
    r1 = run([adb, "-s", serial, "shell", "settings", "put", "global", "adb_enabled", "0"])
    r2 = run([adb, "-s", serial, "shell", "settings", "put", "global", "adb_wifi_enabled", "0"])
    return (r1 + r2)

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

# Patrones de hosting/proxy en el nombre DNS inverso (delatan un nodo/proxy, no un servicio normal).
PROXY_HOST_PATTERNS = ["proxy", "vpn", "socks", "residential", "netnut", "brightdata", "luminati",
                       "oxylabs", "iproyal", "packetstream", "peer2profit", "honeygain", "smartproxy",
                       "webshare", "shifter", "rayobyte", "asocks", "922"]
# Organizaciones "buenas" muy comunes (para no alarmar): nube/CDN legítimos.
KNOWN_ORGS = {"amazonaws": "Amazon AWS", "googleusercontent": "Google", "1e100": "Google",
              "microsoft": "Microsoft", "azure": "Microsoft Azure", "akamai": "Akamai (CDN)",
              "cloudflare": "Cloudflare", "fastly": "Fastly (CDN)", "facebook": "Meta",
              "fbcdn": "Meta", "apple": "Apple", "icloud": "Apple", "cloudfront": "Amazon CloudFront",
              "gvt1": "Google", "whatsapp": "WhatsApp", "netflix": "Netflix", "spotify": "Spotify"}
_rdns_cache = {}
def _ip_org(ip):
    """Organización aproximada por DNS inverso (solo DNS, sin APIs externas). Devuelve (org, host, es_proxy)."""
    if ip in _rdns_cache: return _rdns_cache[ip]
    host = ""
    try:
        socket.setdefaulttimeout(1.0)
        host = socket.gethostbyaddr(ip)[0].lower()
    except Exception: host = ""
    org = ""
    low = host
    for key, name in KNOWN_ORGS.items():
        if key in low: org = name; break
    if not org and host:
        parts = host.split(".")
        org = parts[-2] if len(parts) >= 2 else host   # dominio de 2º nivel como pista
    is_proxy = any(p in low for p in PROXY_HOST_PATTERNS)
    res = (org or "(desconocida)", host or "(sin DNS inverso)", is_proxy)
    _rdns_cache[ip] = res
    return res

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
        out.append({"proc": pn, "ip": ra, "remote": "%s:%s" % (ra, r.get("RemotePort")), "lport": r.get("LocalPort"), "pid": pid})
    # inteligencia: resolver organización (DNS inverso) de cada IP única, en paralelo
    uniq = list(dict.fromkeys(o["ip"] for o in out))
    orgs = {}
    def _resolve(ip): orgs[ip] = _ip_org(ip)
    ths = [threading.Thread(target=_resolve, args=(ip,)) for ip in uniq]
    for t in ths: t.start()
    for t in ths: t.join(timeout=2.0)
    for o in out:
        org, host, is_proxy = orgs.get(o["ip"], ("(desconocida)", "", False))
        o["org"] = org; o["host"] = host; o["proxyhost"] = is_proxy
        # marca en rojo: muchas conexiones (posible nodo) O destino que parece proxy/residencial
        o["flag"] = counts.get(o["proc"], 0) >= 25 or is_proxy
    return out

def _exe_from_cmd(cmd):
    """Extrae la ruta del ejecutable de una línea de comando de arranque."""
    cmd = (cmd or "").strip()
    if not cmd: return ""
    if cmd[0] == '"':
        end = cmd.find('"', 1)
        return cmd[1:end] if end > 0 else cmd[1:]
    m = re.match(r'^(.*?\.(?:exe|bat|cmd|com|scr))\b', cmd, re.I)
    if m: return m.group(1)
    return cmd.split()[0]

def _is_orphan(cmd):
    """True si el arranque apunta a un archivo que YA NO EXISTE (típico de algo desinstalado)."""
    exe = os.path.expandvars(_exe_from_cmd(cmd))
    if not exe: return False
    low = exe.lower()
    if not any(low.endswith(e) for e in (".exe", ".bat", ".cmd", ".com", ".scr")): return False
    try:
        return not os.path.exists(exe)
    except Exception:
        return False

# --- Habilitar/deshabilitar entradas Run como hace el Administrador de tareas (clave StartupApproved) ---
SA_RUN = {"HKCU": "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run",
          "HKLM": "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run"}
def startup_enabled(hive, name):
    """True si la entrada Run está habilitada. Ausente en StartupApproved = habilitada por defecto."""
    try:
        k = winreg.OpenKey(_hkey(hive), SA_RUN[hive], 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        v, _ = winreg.QueryValueEx(k, name); winreg.CloseKey(k)
        # byte 0: par (02/06) = habilitada, impar (03/07) = deshabilitada
        return not (len(v) >= 1 and (v[0] & 1))
    except Exception:
        return True
def set_startup_enabled(hive, name, enabled):
    import struct
    k = winreg.CreateKeyEx(_hkey(hive), SA_RUN[hive], 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
    if enabled:
        blob = bytes([2,0,0,0,0,0,0,0,0,0,0,0])
    else:
        epoch = datetime.datetime(1601,1,1, tzinfo=datetime.timezone.utc)
        ft = int((datetime.datetime.now(datetime.timezone.utc) - epoch).total_seconds() * 10_000_000)
        blob = bytes([3,0,0,0]) + struct.pack("<Q", ft)
    winreg.SetValueEx(k, name, 0, winreg.REG_BINARY, blob); winreg.CloseKey(k)

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
                    cmd = str(val)
                    susp = any(x in cmd.lower() for x in ["\\temp\\", "\\appdata\\local\\temp", "powershell -e", "-enc "])
                    items.append({"type": "Run", "loc": hive, "name": name, "cmd": cmd, "susp": susp,
                                  "orphan": _is_orphan(cmd), "hive": hive, "regpath": path,
                                  "enabled": startup_enabled(hive, name)})
                except OSError: break
            winreg.CloseKey(k)
        except Exception: pass
    # Tareas: activas (cualquier origen) + tareas de TERCEROS aunque estén deshabilitadas (para poder reactivarlas).
    # Se ocultan las de Microsoft deshabilitadas (ruido del sistema).
    for t in psjson("Get-ScheduledTask | Select-Object TaskName,TaskPath,@{n='State';e={$_.State.ToString()}}")[:600]:
        if not isinstance(t, dict): continue
        tp = t.get("TaskPath") or "\\"
        state = str(t.get("State") or "")
        is_ms = tp.lower().startswith("\\microsoft\\")
        disabled = state.lower() == "disabled"
        if is_ms and disabled: continue
        items.append({"type": "Tarea", "loc": tp, "name": t.get("TaskName", ""),
                      "cmd": "", "susp": False, "orphan": False,
                      "taskpath": tp, "taskname": t.get("TaskName", ""), "enabled": not disabled})
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
        try:
            _ico = os.path.join(sys._MEIPASS if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__)), "icon.ico")
            if os.path.exists(_ico): self.iconbitmap(_ico)
        except Exception: pass
        self._style()
        self._tab_titles = []
        self._header()
        self.nb = ttk.Notebook(self); self.nb.pack(fill="both", expand=True, padx=12, pady=(0,10))
        self.tab_dash = self._tab("🏠  Panel")
        self.tab_prox = self._tab("🕵️  Anti-proxyware")
        self.tab_net  = self._tab("🌐  Red")
        self.tab_iot  = self._tab("🏘️  Red local")
        self.tab_tv   = self._tab("📺  Limpiar TV")
        self.tab_priv = self._tab("🔒  Privacidad")
        self.tab_start= self._tab("🧹  Arranque")
        self.tab_integ= self._tab("🛡️  Integridad")
        self.tab_help = self._tab("💬  Apoyo OptiSuite")
        self._build_dashboard(); self._build_proxyware(); self._build_network(); self._build_iot(); self._build_tv()
        self._build_privacy(); self._build_startup(); self._build_integrity(); self._build_help()
        self._snapshot_i18n()
        if LANG == "en": self._apply_lang()
        self._status(tr("Listo. Modo solo-escaneo: nada se cambia sin tu confirmación.") + ("" if is_admin() else tr("  ⚠ Ejecuta como administrador para aplicar cambios.")))

    # ---------- i18n ----------
    def _snapshot_i18n(self):
        """Guarda el texto español original de cada widget para poder alternar ES/EN sin reconstruir."""
        self._orig_text = []   # (widget, español)
        self._orig_head = []   # (treeview, columna, español)
        def walk(w):
            try:
                t = w.cget("text")
                if isinstance(t, str) and t.strip(): self._orig_text.append((w, t))
            except Exception: pass
            if isinstance(w, ttk.Treeview):
                cols = ("#0",) + tuple(w.cget("columns") or ())
                for c in cols:
                    try:
                        ht = w.heading(c).get("text")
                        if ht and str(ht).strip(): self._orig_head.append((w, c, str(ht)))
                    except Exception: pass
            for c in w.winfo_children(): walk(c)
        walk(self)

    def _apply_lang(self):
        for w, es in getattr(self, "_orig_text", []):
            try: w.configure(text=tr(es))
            except Exception: pass
        for tree, col, es in getattr(self, "_orig_head", []):
            try: tree.heading(col, text=tr(es))
            except Exception: pass
        for i, es in enumerate(getattr(self, "_tab_titles", [])):
            try: self.nb.tab(i, text=tr(es))
            except Exception: pass

    def set_lang(self, code):
        global LANG
        if code not in ("es", "en") or code == LANG: return
        LANG = code
        cfg = load_config(); cfg["lang"] = code; save_config(cfg)
        self._apply_lang()
        self._update_lang_buttons()
        self._status(tr("Listo. Modo solo-escaneo: nada se cambia sin tu confirmación.") + ("" if is_admin() else tr("  ⚠ Ejecuta como administrador para aplicar cambios.")))

    def _update_lang_buttons(self):
        for code, btn in getattr(self, "_lang_btns", {}).items():
            on = (code == LANG)
            btn.config(bg=(TEAL if on else BG2), fg=("#04210f" if on else MUT))

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
        # selector de idioma ES | EN
        lang = tk.Frame(h, bg=BG); lang.pack(side="right", padx=(0,12))
        self._lang_btns = {}
        for code, label in (("es", "ES"), ("en", "EN")):
            b = tk.Button(lang, text=label, bd=0, relief="flat", padx=9, pady=3, cursor="hand2",
                          font=("Segoe UI",9,"bold"), activebackground=TEAL2,
                          command=lambda c=code: self.set_lang(c))
            b.pack(side="left", padx=1)
            self._lang_btns[code] = b
        self._update_lang_buttons()

    def _tab(self, title):
        self._tab_titles.append(title)
        f = ttk.Frame(self.nb); self.nb.add(f, text=title); return f

    def _status(self, msg):
        if not hasattr(self, "_sb"):
            self._sb = tk.Label(self, text="", bg=CARD, fg=MUT, anchor="w", font=("Segoe UI",9), padx=12, pady=5)
            self._sb.pack(fill="x", side="bottom")
        self._sb.config(text=tr(msg))

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
        ttk.Label(f, text="En rojo = muchas conexiones salientes (posible nodo) O destino que parece proxy/residencial. La columna Organización viene del DNS inverso (solo DNS, nada sale a terceros).", style="Mut.TLabel", wraplength=980, justify="left").pack(anchor="w", padx=16)
        self.net_tree = ttk.Treeview(f, columns=("remote","org","pid"), show="tree headings", height=16)
        self.net_tree.heading("#0", text="Proceso"); self.net_tree.heading("remote", text="Destino"); self.net_tree.heading("org", text="Organización (DNS inverso)"); self.net_tree.heading("pid", text="PID")
        self.net_tree.column("#0", width=210); self.net_tree.column("remote", width=210); self.net_tree.column("org", width=280); self.net_tree.column("pid", width=70)
        self.net_tree.tag_configure("flag", foreground=RED)
        self.net_tree.pack(fill="both", expand=True, padx=16, pady=10)

    def refresh_network(self, data):
        if isinstance(data, Exception): return
        self.net_tree.delete(*self.net_tree.get_children())
        for x in data:
            org = x.get("org", "")
            if x.get("proxyhost"): org = "⚠ PROXY/RESIDENCIAL: " + org
            self.net_tree.insert("", "end", text=x["proc"], values=(x["remote"], org, x["pid"]),
                                 tags=("flag",) if x.get("flag") else ())

    # ---------- Red local (IoT / Badbox) ----------
    def _build_iot(self):
        f = self.tab_iot
        top = tk.Frame(f, bg=BG); top.pack(fill="x", padx=16, pady=12)
        ttk.Label(top, text="Red local — dispositivos y IoT (Badbox)", style="H.TLabel").pack(side="left")
        ttk.Button(top, text="🔎 Escaneo rápido (ARP)", style="Teal.TButton", command=lambda: (self._status("Escaneando red local…"), self._runbg(scan_local_network, self.refresh_iot))).pack(side="right")
        ttk.Button(top, text="🔬 Escaneo profundo", style="Ghost.TButton", command=self.deep_scan).pack(side="right", padx=8)
        ttk.Label(f, text="Rápido = dispositivos ya vistos (tabla ARP). Profundo = barrido activo de TODA tu subred (ping .1-.254 + fabricante por MAC), tarda ~30-60s. En rojo = puertos de depuración abiertos (5555 ADB, Telnet, FTP…) en un equipo NO marcado de confianza — típico de TV-box/IoT comprometidos por Badbox. Selecciona un equipo y pulsa «Detalles» para ver por qué; marca tus propios equipos como «de confianza» para que dejen de salir en rojo.", style="Mut.TLabel", wraplength=980, justify="left").pack(anchor="w", padx=16)
        self.iot_tree = ttk.Treeview(f, columns=("mac","vendor","host","open"), show="tree headings", selectmode="extended", height=14)
        self.iot_tree.heading("#0", text="IP"); self.iot_tree.heading("mac", text="MAC"); self.iot_tree.heading("vendor", text="Fabricante"); self.iot_tree.heading("host", text="Nombre / dispositivo"); self.iot_tree.heading("open", text="Puertos de depuración abiertos")
        self.iot_tree.column("#0", width=120); self.iot_tree.column("mac", width=135); self.iot_tree.column("vendor", width=150); self.iot_tree.column("host", width=175); self.iot_tree.column("open", width=290)
        self.iot_tree.tag_configure("risk", foreground=RED); self.iot_tree.tag_configure("trusted", foreground=TEAL2)
        self.iot_tree.pack(fill="both", expand=True, padx=16, pady=(10,4))
        self._iot_data = {}
        self.iot_tree.bind("<Double-1>", lambda e: self.iot_details())
        abar = tk.Frame(f, bg=BG); abar.pack(fill="x", padx=16, pady=(0,4))
        ttk.Button(abar, text="✓ Marcar de confianza", style="Ghost.TButton", command=lambda: self.iot_trust(True)).pack(side="left")
        ttk.Button(abar, text="✕ Quitar de confianza", style="Ghost.TButton", command=lambda: self.iot_trust(False)).pack(side="left", padx=8)
        ttk.Button(abar, text="🔎 Detalles del equipo", style="Ghost.TButton", command=self.iot_details).pack(side="left")
        tk.Label(abar, text="(doble clic = detalles)", bg=BG, fg=MUT, font=("Segoe UI",8)).pack(side="left", padx=8)
        # Reputación de IP pública
        ipbar = tk.Frame(f, bg=BG); ipbar.pack(fill="x", padx=16, pady=(0,14))
        self.ip_lbl = tk.Label(ipbar, text="Tu IP pública: (pulsa Ver)", bg=BG, fg=MUT, font=("Segoe UI",10)); self.ip_lbl.pack(side="left")
        ttk.Button(ipbar, text="🌐 Ver mi IP y reputación", style="Ghost.TButton", command=self.check_ip).pack(side="right")

    def deep_scan(self):
        self._status("Escaneo profundo en curso (barriendo toda tu subred)…")
        def prog(done, total): self.after(0, lambda: self._status("Escaneo profundo: %d/%d equipos sondeados…" % (done, total)))
        self._runbg(lambda: scan_local_network_deep(progress=prog), self.refresh_iot)

    def refresh_iot(self, data):
        if isinstance(data, Exception): return
        self.iot_tree.delete(*self.iot_tree.get_children())
        self._iot_data = {}
        if not data:
            self.iot_tree.insert("", "end", text="(sin dispositivos)", values=("","","","")); return
        for d in data:
            tag = "risk" if d.get("risk") else ("trusted" if d.get("trusted") else "")
            opentxt = " · ".join(d.get("open", [])) or "—"
            if d.get("trusted") and d.get("open"): opentxt += "  (de confianza)"
            iid = self.iot_tree.insert("", "end", text=d["ip"],
                                       values=(d.get("mac",""), d.get("vendor",""), d.get("host","") or "—", opentxt),
                                       tags=(tag,) if tag else ())
            self._iot_data[iid] = d
        self._status("Red local: %d dispositivos, %d con puertos de depuración (sin marcar de confianza)." % (len(data), len([x for x in data if x.get('risk')])))

    def iot_trust(self, add):
        sel = self.iot_tree.selection()
        if not sel: messagebox.showinfo(APP, "Selecciona uno o varios equipos en la lista."); return
        t = load_trusted()
        for iid in sel:
            d = self._iot_data.get(iid)
            if not d: continue
            if add:
                t["ips"].add(d["ip"])
                if d.get("mac"): t["macs"].add(_norm_mac(d["mac"]))
            else:
                t["ips"].discard(d["ip"])
                if d.get("mac"): t["macs"].discard(_norm_mac(d["mac"]))
        save_trusted(t)
        for d in self._iot_data.values():
            d["trusted"] = is_trusted(t, d["ip"], d.get("mac"))
            d["risk"] = bool(d.get("open")) and not d["trusted"]
        self.refresh_iot(list(self._iot_data.values()))
        self._status(("Marcados de confianza: %d equipo(s). Ya no saldrán en rojo." if add else "Quitados de confianza: %d equipo(s).") % len(sel))

    def iot_details(self):
        sel = self.iot_tree.selection()
        if not sel: messagebox.showinfo(APP, "Selecciona un equipo para ver sus detalles."); return
        d = self._iot_data.get(sel[0])
        if not d: return
        L = ["IP:  %s" % d["ip"], "MAC:  %s" % (d.get("mac") or "—"),
             "Fabricante:  %s" % (d.get("vendor") or "—"),
             "Nombre (DNS inverso):  %s" % (d.get("host") or "(no resuelve)"),
             "Marcado de confianza:  %s" % ("Sí" if d.get("trusted") else "No"), ""]
        if d.get("open"):
            L.append("Puertos de depuración abiertos:")
            for op in d["open"]:
                try: port = int(op.split()[0])
                except Exception: port = None
                L.append("• %s\n    %s" % (op, PORT_INFO.get(port, "Puerto de depuración/administración; conviene revisarlo.")))
            if not d.get("trusted"):
                L.append("\n➡ Si este equipo es TUYO y abriste ese puerto a propósito, márcalo de confianza para que deje de salir en rojo.")
        else:
            L.append("Sin puertos de depuración abiertos. ✔")
        messagebox.showinfo("Detalles del dispositivo", "\n".join(L))

    def check_ip(self):
        self.ip_lbl.config(text="Consultando…")
        def done(ip):
            if not ip: self.ip_lbl.config(text="No pude obtener la IP (¿sin internet?)"); return
            self.ip_lbl.config(text="Tu IP pública: %s" % ip)
            if messagebox.askyesno(APP, "Tu IP pública es %s.\n\n¿Abrir su reputación en AbuseIPDB (navegador)?\nSirve para ver si tu IP figura como abusiva (a veces por otro usuario del ISP)." % ip):
                webbrowser.open("https://www.abuseipdb.com/check/%s" % ip)
        self._runbg(public_ip, done)

    # ---------- Limpiar TV (ADB) ----------
    def _build_tv(self):
        f = self.tab_tv
        self._adb = _find_adb(); self._tv_serial = None
        top = tk.Frame(f, bg=BG); top.pack(fill="x", padx=16, pady=12)
        ttk.Label(top, text="Limpiar TV / TV-box Android (ADB)", style="H.TLabel").pack(side="left")
        ttk.Label(f, text="Conecta tu TV por USB o por red (habilitando temporalmente la Depuración). OptiShield lista sus apps, marca las sideload/sospechosas (típicas de Badbox), te deja desactivarlas o desinstalarlas y, al terminar, CIERRA la depuración. Todo con tu aprobación.", style="Mut.TLabel", wraplength=980, justify="left").pack(anchor="w", padx=16)
        # barra conexión
        cbar = tk.Frame(f, bg=BG); cbar.pack(fill="x", padx=16, pady=8)
        self.tv_status = tk.Label(cbar, text="", bg=BG, fg=MUT, font=("Segoe UI",9)); self.tv_status.pack(side="left")
        ttk.Button(cbar, text="↻ Detectar", style="Ghost.TButton", command=self.tv_detect).pack(side="right")
        tk.Label(cbar, text="IP del TV (red):", bg=BG, fg=MUT, font=("Segoe UI",9)).pack(side="right", padx=(0,4))
        self.tv_ip = tk.Entry(cbar, width=16, bg=CARD, fg=INK, insertbackground=INK, relief="flat"); self.tv_ip.pack(side="right", padx=6); self.tv_ip.insert(0,"192.168.")
        ttk.Button(cbar, text="🔌 Conectar por red", style="Ghost.TButton", command=self.tv_connect).pack(side="right", padx=6)
        # lista de apps
        self.tv_tree = ttk.Treeview(f, columns=("risk","inst"), show="tree headings", selectmode="extended", height=13)
        self.tv_tree.heading("#0", text="Paquete (app)"); self.tv_tree.heading("risk", text="Riesgo"); self.tv_tree.heading("inst", text="Instalador")
        self.tv_tree.column("#0", width=420); self.tv_tree.column("risk", width=90); self.tv_tree.column("inst", width=260)
        self.tv_tree.tag_configure("ALTO", foreground=RED); self.tv_tree.tag_configure("revisar", foreground=AMBER)
        self.tv_tree.pack(fill="both", expand=True, padx=16, pady=10)
        bar = tk.Frame(f, bg=BG); bar.pack(fill="x", padx=16, pady=(0,14))
        ttk.Button(bar, text="📋 Listar apps", style="Teal.TButton", command=self.tv_list).pack(side="left")
        ttk.Button(bar, text="🚫 Desactivar", style="Ghost.TButton", command=lambda: self.tv_act("disable")).pack(side="left", padx=6)
        ttk.Button(bar, text="🗑 Desinstalar", style="Ghost.TButton", command=lambda: self.tv_act("uninstall")).pack(side="left")
        ttk.Button(bar, text="🔒 Cerrar depuración del TV", style="Ghost.TButton", command=self.tv_close).pack(side="right")
        self.tv_detect()

    def tv_detect(self):
        self._adb = _find_adb()
        if not self._adb:
            self.tv_status.config(text="⚠ No encuentro ADB. Pon platform-tools junto al programa o instálalo.", fg="#ffb4b4"); return
        def work(): return adb_devices(self._adb)
        def done(devs):
            if isinstance(devs, Exception) or not devs:
                self.tv_status.config(text="ADB OK. Sin dispositivos. Conecta el TV por USB o pulsa 'Conectar por red'.", fg=MUT); self._tv_serial=None; return
            self._tv_serial = devs[0]
            model = adb_model(self._adb, self._tv_serial)
            self.tv_status.config(text="✅ Conectado: %s  [%s]" % (self._tv_serial, model), fg=TEAL2)
        self._runbg(work, done)

    def tv_connect(self):
        if not self._adb: messagebox.showwarning(APP,"No encuentro ADB (platform-tools)."); return
        ip = self.tv_ip.get().strip()
        if not ip or ip == "192.168.": messagebox.showinfo(APP,"Escribe la IP del TV (mira Ajustes → Red del TV)."); return
        self.tv_status.config(text="Conectando a %s…" % ip)
        def work(): adb_connect(self._adb, ip); return adb_devices(self._adb)
        def done(devs):
            if isinstance(devs, Exception) or not devs:
                self.tv_status.config(text="No pude conectar. ¿Activaste 'Depuración por red' en el TV y aceptaste el aviso?", fg="#ffb4b4"); return
            self.tv_detect()
        self._runbg(work, done)

    def tv_list(self):
        if not self._adb or not self._tv_serial: messagebox.showinfo(APP,"Primero conecta el TV (USB o red) y pulsa Detectar."); return
        self._status("Listando apps del TV…")
        self._runbg(lambda: adb_list_packages(self._adb, self._tv_serial), self._tv_fill)

    def _tv_fill(self, pkgs):
        if isinstance(pkgs, Exception): return
        self.tv_tree.delete(*self.tv_tree.get_children())
        for p in pkgs:
            self.tv_tree.insert("", "end", iid=p["pkg"], text=p["pkg"], values=(p["risk"], p["installer"]),
                                tags=(p["risk"],) if p["risk"] in ("ALTO","revisar") else ())
        flagged = len([p for p in pkgs if p["flag"]])
        self._status("TV: %d apps de terceros (%d para revisar/altas)." % (len(pkgs), flagged))

    def tv_act(self, mode):
        if not self._adb or not self._tv_serial: messagebox.showinfo(APP,"Conecta el TV primero."); return
        sel = self.tv_tree.selection()
        if not sel: messagebox.showinfo(APP,"Selecciona en la lista las apps a tratar."); return
        verb = "DESACTIVAR" if mode=="disable" else "DESINSTALAR"
        if not messagebox.askyesno(APP, "Vas a %s %d app(s) del TV:\n\n• %s\n\n¿Continuar?" % (verb, len(sel), "\n• ".join(sel))): return
        def work():
            ok=0
            for pkg in sel:
                r = adb_disable(self._adb,self._tv_serial,pkg) if mode=="disable" else adb_uninstall(self._adb,self._tv_serial,pkg)
                if "Success" in r or "disabled" in r.lower(): ok+=1
                log("TV %s %s -> %s" % (mode, pkg, r.strip()[:60]))
            return ok
        def done(ok):
            messagebox.showinfo(APP,"Hecho: %d/%d app(s) %s." % (ok, len(sel), verb.lower()+"das"))
            self.tv_list()
        self._runbg(work, done)

    def tv_close(self):
        if not self._adb or not self._tv_serial: messagebox.showinfo(APP,"Conecta el TV primero."); return
        if not messagebox.askyesno(APP,"Se DESACTIVARÁ la depuración (ADB) del TV para cerrarlo bien.\n(Recomendado al terminar.) ¿Continuar?"): return
        def work(): return adb_close_debug(self._adb, self._tv_serial)
        def done(_):
            messagebox.showinfo(APP,"Depuración del TV cerrada. Recuerda también desactivar 'Opciones de desarrollador' en el TV.")
            self.tv_status.config(text="🔒 Depuración cerrada en el TV.", fg=TEAL2)
        self._runbg(work, done)

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
        ttk.Label(f, text="Programas, tareas y entradas que arrancan con Windows. En rojo = sospechoso (Temp, comandos ofuscados). En ámbar = OBSOLETO: apunta a un archivo que ya no existe (típico de algo que desinstalaste). Puedes DESACTIVAR (deja de arrancar pero se conserva) o ELIMINAR lo que no sirva — todo reversible.", style="Mut.TLabel", wraplength=980, justify="left").pack(anchor="w", padx=16)
        self.start_tree = ttk.Treeview(f, columns=("type","loc","estado","cmd"), show="tree headings", selectmode="extended", height=15)
        self.start_tree.heading("#0", text="Nombre"); self.start_tree.heading("type", text="Tipo"); self.start_tree.heading("loc", text="Ubicación"); self.start_tree.heading("estado", text="Estado"); self.start_tree.heading("cmd", text="Comando")
        self.start_tree.column("#0", width=200); self.start_tree.column("type", width=70); self.start_tree.column("loc", width=90); self.start_tree.column("estado", width=150); self.start_tree.column("cmd", width=370)
        self.start_tree.tag_configure("susp", foreground=RED); self.start_tree.tag_configure("orphan", foreground=AMBER); self.start_tree.tag_configure("disabled", foreground=MUT)
        self.start_tree.pack(fill="both", expand=True, padx=16, pady=(10,4))
        self._start_data = {}
        bar = tk.Frame(f, bg=BG); bar.pack(fill="x", padx=16, pady=(0,14))
        ttk.Button(bar, text="⛔ Desactivar", style="Ghost.TButton", command=lambda: self.start_toggle(False)).pack(side="left")
        ttk.Button(bar, text="✅ Activar", style="Ghost.TButton", command=lambda: self.start_toggle(True)).pack(side="left", padx=8)
        ttk.Button(bar, text="🧹 Limpiar obsoletas", style="Teal.TButton", command=lambda: self.start_remove(only_orphans=True)).pack(side="left", padx=8)
        ttk.Button(bar, text="🗑 Eliminar", style="Ghost.TButton", command=lambda: self.start_remove(only_orphans=False)).pack(side="left")
        tk.Label(bar, text="Desactivar es reversible (Activar lo devuelve). Requiere administrador.", bg=BG, fg=MUT, font=("Segoe UI",8)).pack(side="left", padx=6)

    def refresh_startup(self, data):
        if isinstance(data, Exception): return
        self.start_tree.delete(*self.start_tree.get_children())
        self._start_data = {}
        for x in data:
            base = "⚠ obsoleto (no existe)" if x.get("orphan") else ("sospechoso" if x.get("susp") else "OK")
            enabled = x.get("enabled", True)
            estado = base if enabled else (base + " · " if base != "OK" else "") + "desactivado"
            if enabled:
                tag = "orphan" if x.get("orphan") else ("susp" if x.get("susp") else "")
            else:
                tag = "disabled"
            iid = self.start_tree.insert("", "end", text=x["name"], values=(x["type"], x["loc"], estado, x["cmd"][:120]),
                                         tags=(tag,) if tag else ())
            self._start_data[iid] = x

    def start_toggle(self, enable):
        if not is_admin(): messagebox.showwarning(APP, "Ejecuta OptiShield como administrador para cambiar el arranque."); return
        sel = list(self.start_tree.selection())
        if not sel: messagebox.showinfo(APP, "Selecciona en la lista las entradas a %s." % ("activar" if enable else "desactivar")); return
        items = [self._start_data[i] for i in sel if i in self._start_data]
        done = 0; err = 0
        for x in items:
            try:
                if x["type"] == "Run":
                    set_startup_enabled(x["hive"], x["name"], enable)
                    log("STARTUP %s Run %s\\%s" % ("enable" if enable else "disable", x["hive"], x["name"]))
                else:
                    tn = (x.get("taskpath", "\\") + x.get("taskname", "")).replace("\\\\", "\\")
                    run(["schtasks", "/Change", "/TN", tn, "/ENABLE" if enable else "/DISABLE"])
                    log("STARTUP %s task %s" % ("enable" if enable else "disable", tn))
                done += 1
            except Exception as e:
                err += 1; log("STARTUP toggle fail %s: %s" % (x.get("name"), e))
        messagebox.showinfo(APP, "%s: %d entrada(s)." % ("Activadas" if enable else "Desactivadas", done) + (" %d con error." % err if err else ""))
        self._runbg(scan_startup, self.refresh_startup)

    def start_remove(self, only_orphans=False):
        if not is_admin(): messagebox.showwarning(APP, "Ejecuta OptiShield como administrador para eliminar entradas de arranque."); return
        if only_orphans:
            targets = [i for i, d in self._start_data.items() if d.get("orphan") and d["type"] == "Run"]
            if not targets: messagebox.showinfo(APP, "No hay entradas de arranque obsoletas (huérfanas) que limpiar. Pulsa «Escanear» primero."); return
        else:
            targets = list(self.start_tree.selection())
            if not targets: messagebox.showinfo(APP, "Selecciona en la lista las entradas a eliminar."); return
        items = [self._start_data[i] for i in targets if i in self._start_data]
        names = [x["name"] for x in items]
        msg = "Se tratarán %d entrada(s) de arranque:\n\n• %s" % (len(items), "\n• ".join(names[:20]))
        if len(names) > 20: msg += "\n• …(+%d)" % (len(names) - 20)
        if any(x["type"] == "Tarea" for x in items): msg += "\n\n(Las tareas programadas se DESACTIVAN, no se borran.)"
        msg += "\n\nSe registra el valor en el log de OptiShield para poder revertir. ¿Continuar?"
        if not messagebox.askyesno(APP, msg): return
        done = 0
        for x in items:
            try:
                if x["type"] == "Run":
                    log("STARTUP delete Run %s\\%s = %s" % (x["hive"], x["name"], x["cmd"]))
                    k = winreg.OpenKey(_hkey(x["hive"]), x["regpath"], 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
                    winreg.DeleteValue(k, x["name"]); winreg.CloseKey(k); done += 1
                else:
                    tn = (x.get("taskpath", "\\") + x.get("taskname", "")).replace("\\\\", "\\")
                    run(["schtasks", "/Change", "/TN", tn, "/DISABLE"]); log("STARTUP disable task %s" % tn); done += 1
            except Exception as e:
                log("STARTUP remove fail %s: %s" % (x.get("name"), e))
        messagebox.showinfo(APP, "Hecho: %d entrada(s) tratada(s).\nReversible: las de «Run» quedan registradas en el log (%s) y las tareas se pueden reactivar en el Programador de tareas." % (done, os.path.join(LOG_DIR, "optishield.log")))
        self._runbg(scan_startup, self.refresh_startup)

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
        box = tk.Frame(f, bg=CARD, highlightbackground=LINE, highlightthickness=1); box.pack(fill="both", expand=True, padx=40, pady=24)
        tk.Label(box, text="🛡️ OptiShield", bg=CARD, fg=INK, font=("Segoe UI",22,"bold")).pack(pady=(20,2))
        tk.Label(box, text="Una herramienta gratuita de OptiSuite para proteger tu privacidad y seguridad.", bg=CARD, fg=MUT, font=("Segoe UI",11)).pack()
        tk.Label(box, text="Defensiva · reversible · 100%% local (no enviamos tus datos a ningún sitio).", bg=CARD, fg=TEAL2, font=("Segoe UI",10,"bold")).pack(pady=(4,12))
        tk.Label(box, text="Es gratis y sin anuncios. Si te ayuda, una estrella en GitHub o una aportación\nmantienen OptiSuite vivo. ¡Gracias! 🙌", bg=CARD, fg=INK, font=("Segoe UI",10), justify="center").pack(pady=(0,10))
        btns = tk.Frame(box, bg=CARD); btns.pack(pady=4)
        ttk.Button(btns, text="⭐ Estrella en GitHub", style="Teal.TButton", command=lambda: webbrowser.open(GITHUB)).pack(side="left", padx=6)
        ttk.Button(btns, text="☕ Ko-fi", style="Ghost.TButton", command=lambda: webbrowser.open(KOFI)).pack(side="left", padx=6)
        ttk.Button(btns, text="♡ Liberapay", style="Ghost.TButton", command=lambda: webbrowser.open(LIBERAPAY)).pack(side="left", padx=6)
        ttk.Button(btns, text="🌐 Visitar OptiSuite", style="Ghost.TButton", command=lambda: webbrowser.open("https://"+WEB)).pack(side="left", padx=6)
        tk.Label(box, text="O con criptomonedas (toca para copiar):", bg=CARD, fg=MUT, font=("Segoe UI",9)).pack(pady=(16,4))
        crow = tk.Frame(box, bg=CARD); crow.pack()
        def copy_btn(label, value):
            ttk.Button(crow, text="%s:  %s" % (label, value), style="Ghost.TButton",
                       command=lambda: (self.clipboard_clear(), self.clipboard_append(value), self._status("Copiado al portapapeles: %s" % value))).pack(side="left", padx=6)
        copy_btn("Binance Pay ID", BINANCE_ID)
        copy_btn("USDT · BSC (BEP-20)", USDT_BSC)
        tk.Label(box, text="✉  %s      🌐  %s" % (EMAIL, WEB), bg=CARD, fg=MUT, font=("Segoe UI",10)).pack(pady=(16,2))
        tk.Label(box, text="© OptiSuite · OptiShield es gratuito. Si te ayuda, compártelo.", bg=CARD, fg=MUT, font=("Segoe UI",9)).pack(side="bottom", pady=14)

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
