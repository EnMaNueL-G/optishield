# -*- coding: utf-8 -*-
"""
OptiShield — Escudo de privacidad y seguridad (Windows).  Enmanuel Gil · OptiSuite
Defensivo · reversible (con copia de seguridad) · no toca Defender, Firewall de Windows (solo añade
reglas propias etiquetadas) ni UAC.
Sin dependencias externas: solo Python estándar + tkinter + comandos de Windows.
"""
import os, sys, json, subprocess, threading, ctypes, socket, datetime, webbrowser, re, shutil, queue, time

APP = "OptiShield"
VERSION = "1.2.0"
BRAND = "OptiSuite"
SIGNATURE = "Enmanuel Gil · OptiSuite"
WHATSAPP = "+56 9 7832 7863"
WA_URL = "https://wa.me/56978327863"
EMAIL = "support@optisuite.app"
WEB = "optisuite.app"
GITHUB = "https://github.com/EnMaNueL-G/optishield"
BINANCE_ID = "1165745950"
USDT_BSC = "0xb6f6731a4ea87f8e1fd6f44f48b5bc4204571f08"

# ---- rutas de datos (config, backups, logs) ----
DATA_DIR = os.path.join(os.environ.get("PROGRAMDATA", os.path.expanduser("~")), "OptiShield")
BACKUP_DIR = os.path.join(DATA_DIR, "backups")
LOG_DIR = os.path.join(DATA_DIR, "logs")
for _d in (DATA_DIR, BACKUP_DIR, LOG_DIR):
    try: os.makedirs(_d, exist_ok=True)
    except Exception: pass

CREATE_NO_WINDOW = 0x08000000
WINDIR = os.environ.get("SystemRoot") or os.environ.get("windir") or "C:\\Windows"
HOSTS_FILE = os.path.join(WINDIR, "System32", "drivers", "etc", "hosts")


def resource_dirs():
    """Carpetas donde buscar data\\ y platform-tools\\ .
    Empaquetado (.exe): PRIMERO junto al .exe (lo que el usuario puede editar), luego dentro (_MEIPASS)."""
    dirs = []
    if getattr(sys, "frozen", False):
        dirs.append(os.path.dirname(os.path.abspath(sys.executable)))
        if getattr(sys, "_MEIPASS", None): dirs.append(sys._MEIPASS)
    else:
        dirs.append(os.path.dirname(os.path.abspath(__file__)))
    return dirs


# ======================= CONFIG =======================
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")
def load_config():
    try:
        with open(CONFIG_FILE, encoding="utf-8") as f:
            c = json.load(f)
            return c if isinstance(c, dict) else {}
    except Exception: return {}
def save_config(c):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f: json.dump(c, f, ensure_ascii=False, indent=2)
    except Exception: pass
def cfg_get(key, default=None):
    return load_config().get(key, default)
def cfg_set(key, value):
    c = load_config(); c[key] = value; save_config(c)


# ======================= IDIOMA (i18n ES/EN) =======================
def _detect_lang():
    lang = cfg_get("lang")
    if lang in ("es", "en"): return lang
    try:
        langid = ctypes.windll.kernel32.GetUserDefaultUILanguage()
        return "en" if (langid & 0x3FF) == 0x09 else "es"
    except Exception: pass
    try:
        import locale
        loc = (locale.getlocale()[0] or "").lower()
        return "en" if loc.startswith("en") or loc.startswith("english") else "es"
    except Exception:
        return "es"

LANG = _detect_lang()

# Traducciones inglesas indexadas por el texto español EXACTO. Lo que no esté aquí se queda en español.
TR = {
    # pestañas
    "🏠 Panel": "🏠 Dashboard", "🕵 Proxyware": "🕵 Proxyware", "🌐 Red": "🌐 Network", "🏘 Red local": "🏘 Local network",
    "📺 TV": "📺 TV", "🔒 Privacidad": "🔒 Privacy", "🧹 Arranque": "🧹 Startup", "🛡 Integridad": "🛡 Integrity",
    "💬 Apoyo": "💬 Support",
    # cabecera / estado
    "  Escudo de privacidad y seguridad · Enmanuel Gil · OptiSuite": "  Privacy & security shield · Enmanuel Gil · OptiSuite",
    "ADMIN": "ADMIN", "SIN ADMIN": "NO ADMIN",
    "Listo. Modo solo-escaneo: nada se cambia sin tu confirmación.": "Ready. Scan-only mode: nothing changes without your confirmation.",
    "  ⚠ Ejecuta como administrador para aplicar cambios.": "  ⚠ Run as administrator to apply changes.",
    "Analizando el sistema…": "Analyzing the system…", "Analizando…": "Analyzing…",
    "Análisis terminado.": "Analysis complete.",
    "Análisis terminado con errores en: %s": "Analysis finished with errors in: %s",
    "Escaneando red local…": "Scanning local network…",
    "Escaneo profundo en curso (barriendo toda tu subred)…": "Deep scan in progress (sweeping your whole subnet)…",
    "Escaneo profundo: %d/%d equipos sondeados…": "Deep scan: %d/%d hosts probed…",
    "Consultando…": "Checking…", "Trabajando…": "Working…", "Escaneando…": "Scanning…",
    "Hecho.": "Done.", "Error: %s": "Error: %s",
    "Copiado al portapapeles: %s": "Copied to clipboard: %s",
    # riesgos / categorías
    "alto": "high", "medio": "medium", "bajo": "low", "info": "info",
    "proceso": "process", "servicio": "service", "carpeta": "folder", "registro": "registry", "puerto": "port", "DLL": "DLL",
    # panel
    "Estado general del sistema": "System overview",
    "Pulsa «Analizar todo» para un chequeo completo. Nada se cambia sin tu confirmación.": "Click «Analyze all» for a full check. Nothing is changed without your confirmation.",
    "🔎 Analizar todo": "🔎 Analyze all",
    "👁 Vigilancia (revisa proxyware cada 15 min)": "👁 Monitoring (checks proxyware every 15 min)",
    "Defender: lo desactivé a propósito": "Defender: I turned it off on purpose",
    "🕵 Proxyware": "🕵 Proxyware", "🌐 Red": "🌐 Network", "🧹 Arranque": "🧹 Startup", "🛡 Integridad": "🛡 Integrity", "🦠 Defender": "🦠 Defender",
    "OK": "OK", "Apagado (a propósito)": "Off (on purpose)", "Apagado": "Off", "Desconocido": "Unknown", "Error": "Error",
    "Proxyware que comparte tu conexión: %d (de %d detecciones)": "Proxyware sharing your connection: %d (of %d detections)",
    "   • %s [%s] — %s": "   • %s [%s] — %s",
    "Conexiones marcadas en rojo (posible nodo): %d": "Connections flagged red (possible node): %d",
    "Arranque sospechoso: %d · obsoleto: %d": "Suspicious startup entries: %d · orphaned: %d",
    "IOCs en hosts: %d": "IOCs in hosts: %d",
    "Defender: encendido (antivirus=%s, tiempo real=%s)": "Defender: on (antivirus=%s, real-time=%s)",
    "Defender: apagado a propósito (marcado por ti). No cuenta como problema.": "Defender: turned off on purpose (marked by you). Not counted as a problem.",
    "Defender: apagado. Si usas otro antivirus o lo apagaste a propósito, márcalo en la casilla de arriba.": "Defender: off. If you use another antivirus or turned it off on purpose, tick the box above.",
    "Defender: no pude leer su estado (puede estar desinstalado o desactivado por directiva).": "Defender: couldn't read its status (it may be removed or disabled by policy).",
    "Antivirus registrado en Windows: %s": "Antivirus registered in Windows: %s",
    "⚠ La parte «%s» falló: %s": "⚠ The «%s» part failed: %s",
    "\n✔ Análisis terminado. Revisa cada pestaña para actuar.": "\n✔ Analysis complete. Check each tab to act.",
    "👁 Vigilancia ACTIVADA (cada 15 min). Ignora lo que marques como «Permitido».": "👁 Monitoring ON (every 15 min). Ignores what you mark as «Allowed».",
    "👁 Vigilancia desactivada.": "👁 Monitoring off.",
    "⚠ VIGILANCIA: proxyware activo → %s": "⚠ MONITORING: active proxyware → %s",
    "OptiShield detectó proxyware activo:\n\n• %s\n\nVe a la pestaña Proxyware para neutralizarlo, o márcalo como «Permitido» si lo instalaste a propósito.":
        "OptiShield detected active proxyware:\n\n• %s\n\nGo to the Proxyware tab to neutralize it, or mark it «Allowed» if you installed it on purpose.",
    "Proxyware": "Proxyware", "Red": "Network", "Arranque": "Startup", "Integridad": "Integrity", "Defender": "Defender",
    # anti-proxyware
    "Anti-proxyware / anti-botnet": "Anti-proxyware / anti-botnet",
    "🔎 Escanear": "🔎 Scan",
    "Proxyware = apps que COMPARTEN tu conexión a cambio de dinero (Honeygain, Pawns, EarnApp…) o SDK ocultos que hacen lo mismo. Los proxies/VPN de pago que TÚ usas (Decodo/Smartproxy, IPRoyal, Oxylabs…) salen como «informativo» y no se tocan. Si algo lo instalaste a propósito, márcalo como «Permitido». Ojo: el bloqueo por hosts no cubre subdominios ni el DNS seguro (DoH) del navegador; por eso OptiShield bloquea también el programa en el firewall cuando conoce su ruta.":
        "Proxyware = apps that SHARE your connection for money (Honeygain, Pawns, EarnApp…) or hidden SDKs that do the same. Paid proxies/VPNs that YOU use (Decodo/Smartproxy, IPRoyal, Oxylabs…) show as «informational» and are not touched. If you installed something on purpose, mark it «Allowed». Note: hosts blocking does not cover subdomains or the browser's secure DNS (DoH); that's why OptiShield also blocks the program in the firewall when it knows its path.",
    "Detección": "Detection", "Riesgo": "Risk", "Veredicto": "Verdict", "Evidencia": "Evidence",
    "🛑 Neutralizar seleccionados": "🛑 Neutralize selected",
    "↩ Deshacer neutralización": "↩ Undo neutralization",
    "✓ Permitir (lo instalé a propósito)": "✓ Allow (I installed it on purpose)", "✕ Quitar permiso": "✕ Remove allowance",
    "✔ Sin proxyware detectado": "✔ No proxyware detected",
    "Comparte tu conexión: se está ejecutando": "Sharing your connection: running now",
    "Instalado (no se está ejecutando ahora)": "Installed (not running right now)",
    "Servicio de proxy/VPN que usas (informativo)": "Proxy/VPN service you use (informational)",
    "Permitido por ti (lo instalaste a propósito)": "Allowed by you (installed on purpose)",
    "Proxy local (informativo)": "Local proxy (informational)",
    "Proxy SOCKS5 abierto a tu red: revisar": "SOCKS5 proxy open to your network: review",
    "SDK de proxyware cargado en una app: revisar": "Proxyware SDK loaded in an app: review",
    "Proxy SOCKS5 en el puerto %d (%s)": "SOCKS5 proxy on port %d (%s)",
    "SDK de proxyware dentro de %s": "Proxyware SDK inside %s",
    "Mysterium (nodo MystNodes)": "Mysterium (MystNodes node)",
    "Hola VPN (gratis = nodo de salida)": "Hola VPN (free = exit node)",
    "Salad (si compartes ancho de banda)": "Salad (if you share bandwidth)",
    "Proxyrack PeerConnect (compartir)": "Proxyrack PeerConnect (sharing)",
    "Smartproxy / Decodo (proxy de pago)": "Smartproxy / Decodo (paid proxy)",
    "IPRoyal (proxy de pago)": "IPRoyal (paid proxy)", "Oxylabs (proxy de pago)": "Oxylabs (paid proxy)",
    "Bright Data (proxy de pago)": "Bright Data (paid proxy)", "Proxy-Cheap (proxy de pago)": "Proxy-Cheap (paid proxy)",
    "922 S5 / IP2World (proxy de pago)": "922 S5 / IP2World (paid proxy)", "Asocks (proxy de pago)": "Asocks (paid proxy)",
    "Proxifier (cliente de proxy)": "Proxifier (proxy client)", "Tuxler VPN (gratis = comparte tu IP)": "Tuxler VPN (free = shares your IP)",
    "predeterminado de Windows, sin uso": "Windows default, unused",
    "  %d adaptador(es) solo con los DNS IPv6 predeterminados de Windows (fec0::, sin uso): %s": "  %d adapter(s) with only Windows' default IPv6 DNS (fec0::, unused): %s", "Infatica (red P2B)": "Infatica (P2B network)",
    "(desconocido)": "(unknown)",
    "Ejecuta OptiShield como administrador para neutralizar.": "Run OptiShield as administrator to neutralize.",
    "Selecciona en la lista lo que quieras neutralizar.": "Select in the list what you want to neutralize.",
    "Esto NO es proxyware: es un servicio de proxy/VPN que usas, o algo que marcaste como permitido:\n\n• %s\n\n¿Neutralizarlo igualmente?":
        "This is NOT proxyware: it's a proxy/VPN service you use, or something you marked as allowed:\n\n• %s\n\nNeutralize it anyway?",
    "Se hará, con copia de seguridad (se puede deshacer):\n• Bloquear en el firewall (salida) los programas encontrados\n• Detener SOLO esos procesos (por PID y ruta)\n• Desactivar sus servicios (guardando su modo de arranque)\n• Bloquear sus dominios en hosts\n\nNo se borra ningún archivo. ¿Continuar?":
        "This will be done, with a backup (can be undone):\n• Block the programs found in the firewall (outbound)\n• Stop ONLY those processes (by PID and path)\n• Disable their services (saving their startup mode)\n• Block their domains in hosts\n\nNo files are deleted. Continue?",
    "Sobre lo que no está en la base de datos (no se hace nada automático):": "About items not in the database (nothing automatic is done):",
    "• %s: es el programa «%s» (PID %s%s). Si no lo reconoces, ciérralo desde el Administrador de tareas y desinstálalo desde Configuración → Aplicaciones. Tor, Clash, v2rayN o «ssh -D» abren proxies así a propósito.":
        "• %s: it's the program «%s» (PID %s%s). If you don't recognise it, close it from Task Manager and uninstall it from Settings → Apps. Tor, Clash, v2rayN or «ssh -D» open proxies like this on purpose.",
    "• %s: hay una DLL de proxyware cargada dentro de otra app. OptiShield no puede quitarla sin romper esa app: desinstala la extensión o programa que la trajo y reinicia la app.":
        "• %s: a proxyware DLL is loaded inside another app. OptiShield can't remove it without breaking that app: uninstall the extension or program that brought it and restart the app.",
    "Resumen de la neutralización:": "Neutralization summary:",
    "✔ Firewall: bloqueado %s": "✔ Firewall: blocked %s", "✖ Firewall: no pude bloquear %s (%s)": "✖ Firewall: couldn't block %s (%s)",
    "✔ Proceso detenido: %s (PID %s)": "✔ Process stopped: %s (PID %s)", "✖ No pude detener %s (PID %s): %s": "✖ Couldn't stop %s (PID %s): %s",
    "• %s (PID %s) ya no se estaba ejecutando o cambió de programa: no se tocó.": "• %s (PID %s) was no longer running or became another program: not touched.",
    "✔ Servicio desactivado: %s": "✔ Service disabled: %s", "✖ Servicio %s: %s": "✖ Service %s: %s",
    "✔ hosts: bloqueados %d nombres (+ DNS vaciado)": "✔ hosts: blocked %d names (+ DNS flushed)",
    "✖ hosts: no pude escribir (%s)": "✖ hosts: couldn't write (%s)",
    "• Sin ruta de programa conocida: no se creó regla de firewall.": "• No known program path: no firewall rule was created.",
    "Copia guardada en: %s": "Backup saved at: %s",
    "No hay ninguna neutralización pendiente de deshacer.": "There is no neutralization to undo.",
    "Se deshará la neutralización del %s:\n\n• %s\n\n(servicios a su modo original, reglas de firewall y líneas de hosts de esa vez). ¿Continuar?":
        "The neutralization from %s will be undone:\n\n• %s\n\n(services back to their original mode, that time's firewall rules and hosts lines). Continue?",
    "Resumen de deshacer:": "Undo summary:",
    "✔ Servicio %s → %s": "✔ Service %s → %s", "✔ Regla de firewall quitada: %s": "✔ Firewall rule removed: %s",
    "✖ No pude quitar la regla %s": "✖ Couldn't remove rule %s", "✔ hosts: quitadas %d líneas": "✔ hosts: removed %d lines",
    "Selecciona uno o varios elementos de la lista.": "Select one or more items in the list.",
    "Permitidos: %d. Ya no cuentan como problema ni avisa la vigilancia.": "Allowed: %d. They no longer count as a problem and monitoring won't alert.",
    "Permiso quitado: %d.": "Allowance removed: %d.",
    # red
    "Conexiones de red activas": "Active network connections",
    "En rojo = un programa (contado por PID) con muchas conexiones salientes, excepto navegadores/Steam/torrent/servicios de Windows, o destino de una red de proxyware conocida. En ámbar = destino que parece un proxy o VPN (normal si usas uno). La columna Organización sale del DNS inverso: solo consultas DNS normales, sin enviar nada a terceros.":
        "Red = a program (counted per PID) with many outbound connections, except browsers/Steam/torrent/Windows services, or a destination on a known proxyware network. Amber = destination that looks like a proxy or VPN (normal if you use one). The Organization column comes from reverse DNS: only normal DNS queries, nothing sent to third parties.",
    "Proceso": "Process", "Destino": "Destination", "Organización (DNS inverso)": "Organization (reverse DNS)", "PID": "PID", "Nota": "Note",
    "(desconocida)": "(unknown)", "(sin DNS inverso)": "(no reverse DNS)",
    "muchas conexiones (%d)": "many connections (%d)", "red de proxyware": "proxyware network",
    "proxy (normal si usas uno)": "proxy (normal if you use one)", "VPN": "VPN",
    # red local
    "Red local — dispositivos y IoT (Badbox)": "Local network — devices & IoT (Badbox)",
    "🔎 Escaneo rápido (ARP)": "🔎 Quick scan (ARP)", "🔬 Escaneo profundo": "🔬 Deep scan",
    "Rápido = dispositivos ya vistos (tabla ARP). Profundo = barrido activo de TODA tu subred (ping .1-.254 + fabricante por MAC), tarda ~30-60 s. En rojo = puertos de depuración abiertos (5555 ADB, Telnet, FTP…) en un equipo NO marcado de confianza — típico de TV-box/IoT comprometidos por Badbox. Selecciona un equipo y pulsa «Detalles»; marca tus propios equipos como «de confianza» para que dejen de salir en rojo.":
        "Quick = devices already seen (ARP table). Deep = active sweep of your WHOLE subnet (ping .1-.254 + vendor by MAC), takes ~30-60 s. Red = open debug ports (5555 ADB, Telnet, FTP…) on a device NOT marked trusted — typical of TV-boxes/IoT compromised by Badbox. Select a device and click «Details»; mark your own devices as «trusted» so they stop showing in red.",
    "IP": "IP", "MAC": "MAC", "Fabricante": "Vendor", "Nombre / dispositivo": "Name / device",
    "Puertos de depuración abiertos": "Open debug ports",
    "✓ Marcar de confianza": "✓ Mark as trusted", "✕ Quitar de confianza": "✕ Remove trust",
    "🔎 Detalles del equipo": "🔎 Device details", "(doble clic = detalles)": "(double-click = details)",
    "Tu IP pública: (pulsa el botón)": "Your public IP: (click the button)",
    "🌐 Ver mi IP y reputación": "🌐 View my IP & reputation",
    "(sin dispositivos)": "(no devices)", "(este PC)": "(this PC)", "(de confianza)": "(trusted)",
    "No pude obtener la IP (¿sin internet?)": "Couldn't get the IP (no internet?)",
    "Tu IP pública: %s": "Your public IP: %s",
    "Para saber tu IP pública, OptiShield preguntará a api.ipify.org (un servicio externo: verá tu IP, como cualquier web que visitas). No se envía nada más. ¿Continuar?":
        "To find your public IP, OptiShield will ask api.ipify.org (an external service: it will see your IP, like any website you visit). Nothing else is sent. Continue?",
    "Tu IP pública es %s.\n\n¿Abrir su reputación en AbuseIPDB (en tu navegador)?\nSirve para ver si tu IP figura como abusiva (a veces por otro usuario de tu proveedor).":
        "Your public IP is %s.\n\nOpen its reputation on AbuseIPDB (in your browser)?\nIt shows whether your IP is listed as abusive (sometimes because of another customer of your ISP).",
    "Red local: %d dispositivos, %d con puertos de depuración (sin marcar de confianza).": "Local network: %d devices, %d with debug ports (not marked trusted).",
    "Selecciona uno o varios equipos en la lista.": "Select one or more devices in the list.",
    "Marcados de confianza: %d equipo(s). Ya no saldrán en rojo.": "Marked as trusted: %d device(s). They won't show in red anymore.",
    "Quitados de confianza: %d equipo(s).": "Trust removed: %d device(s).",
    "Selecciona un equipo para ver sus detalles.": "Select a device to see its details.",
    "Detalles del dispositivo": "Device details",
    "Fabricante:  %s": "Vendor:  %s", "Nombre (DNS inverso):  %s": "Name (reverse DNS):  %s", "(no resuelve)": "(doesn't resolve)",
    "Marcado de confianza:  %s": "Marked as trusted:  %s", "Sí": "Yes", "No": "No",
    "Puertos de depuración abiertos:": "Open debug ports:",
    "➡ Si este equipo es TUYO y abriste ese puerto a propósito, márcalo de confianza para que deje de salir en rojo.": "➡ If this device is YOURS and you opened that port on purpose, mark it trusted so it stops showing in red.",
    "Sin puertos de depuración abiertos. ✔": "No debug ports open. ✔",
    "Puerto de depuración/administración; conviene revisarlo.": "Debug/admin port; worth checking.",
    "Depuración ADB de Android expuesta a la red — el vector típico de Badbox. En una TV-box legítima debería estar CERRADO. Si es tu equipo y activaste ADB por red a propósito, márcalo de confianza y ciérralo al terminar.":
        "Android ADB debugging exposed to the network — the typical Badbox vector. On a legitimate TV-box it should be CLOSED. If it's your device and you enabled network ADB on purpose, mark it trusted and close it when done.",
    "Telnet: acceso remoto SIN cifrar, muy usado por botnets IoT (Mirai/Badbox). Casi ningún dispositivo doméstico moderno debería tenerlo abierto.":
        "Telnet: UNENCRYPTED remote access, widely used by IoT botnets (Mirai/Badbox). Almost no modern home device should have it open.",
    "FTP: transferencia de archivos sin cifrar; en un equipo de casa normal no suele estar abierto.": "FTP: unencrypted file transfer; not usually open on a normal home device.",
    "Puerto de depuración/UART común en cámaras IP y TV-box baratas comprometidas.": "Debug/UART port common in cheap compromised IP cameras and TV-boxes.",
    "Puerto de depuración/administración; sospechoso en un dispositivo de consumo.": "Debug/admin port; suspicious on a consumer device.",
    "Puerto asociado a backdoors (p. ej. Metasploit); muy sospechoso.": "Port associated with backdoors (e.g. Metasploit); very suspicious.",
    # limpiar TV
    "Limpiar TV / TV-box Android (ADB)": "Clean Android TV / TV-box (ADB)",
    "Conecta tu TV por USB o por red (activando temporalmente la Depuración). OptiShield lista sus apps y marca las instaladas fuera de una tienda o con nombres sospechosos. Lo recomendado es DESACTIVAR (se puede reactivar y conserva los datos); desinstalar borra los datos de esa app. Al terminar, CIERRA la depuración. Todo con tu aprobación.":
        "Connect your TV by USB or over the network (temporarily enabling Debugging). OptiShield lists its apps and flags those installed outside a store or with suspicious names. DISABLING is recommended (can be re-enabled and keeps data); uninstalling deletes that app's data. When finished, CLOSE debugging. All with your approval.",
    "↻ Detectar": "↻ Detect", "IP del TV (red):": "TV IP (network):", "🔌 Conectar por red": "🔌 Connect over network",
    "Paquete (app)": "Package (app)", "Instalador": "Installer", "📋 Listar apps": "📋 List apps",
    "🚫 Desactivar (recomendado)": "🚫 Disable (recommended)", "🗑 Desinstalar (borra datos)": "🗑 Uninstall (deletes data)",
    "🔒 Cerrar depuración del TV": "🔒 Close TV debugging",
    "Pulsa «Detectar» cuando tengas el TV conectado (no se ejecuta ADB hasta entonces).": "Click «Detect» once the TV is connected (ADB isn't run until then).",
    "⚠ No encuentro ADB. Pon platform-tools junto al programa o instálalo.": "⚠ ADB not found. Put platform-tools next to the program or install it.",
    "ADB OK. Sin dispositivos. Conecta el TV por USB o pulsa «Conectar por red».": "ADB OK. No devices. Connect the TV by USB or click «Connect over network».",
    "✅ Conectado: %s  [%s]": "✅ Connected: %s  [%s]", "Conectando a %s…": "Connecting to %s…",
    "⚠ Acepta el aviso de depuración en la TV (marca «Permitir siempre») y pulsa «Detectar».": "⚠ Accept the debugging prompt on the TV (tick «Always allow») and click «Detect».",
    "⚠ El TV aparece «offline»: desconecta y vuelve a conectar, o reinicia la depuración.": "⚠ The TV shows as «offline»: disconnect and reconnect, or restart debugging.",
    "No pude conectar. ¿Activaste «Depuración por red» en el TV y aceptaste el aviso?": "Couldn't connect. Did you enable «Network debugging» on the TV and accept the prompt?",
    "🔒 Depuración cerrada en el TV.": "🔒 Debugging closed on the TV.",
    "⚠ Cierre de depuración incompleto: revisa Opciones de desarrollador en el TV.": "⚠ Debugging close incomplete: check Developer options on the TV.",
    "No encuentro ADB (platform-tools).": "ADB (platform-tools) not found.",
    "Escribe la IP del TV (mira Ajustes → Red del TV).": "Type the TV's IP (see the TV's Settings → Network).",
    "Primero conecta el TV (USB o red) y pulsa «Detectar».": "First connect the TV (USB or network) and click «Detect».",
    "Listando apps del TV…": "Listing TV apps…",
    "TV: %d apps de terceros (%d para revisar/altas).": "TV: %d third-party apps (%d to review/high).",
    "Conecta el TV primero.": "Connect the TV first.",
    "Selecciona en la lista las apps a tratar.": "Select the apps to handle in the list.",
    "Vas a DESACTIVAR %d app(s) del TV (se pueden reactivar; los datos se conservan):\n\n• %s\n\n¿Continuar?":
        "You are going to DISABLE %d TV app(s) (can be re-enabled; data is kept):\n\n• %s\n\nContinue?",
    "Vas a DESINSTALAR %d app(s) del TV. Esto BORRA sus datos y no se puede deshacer desde aquí. Si solo quieres que dejen de funcionar, mejor «Desactivar».\n\n• %s\n\n¿Desinstalar igualmente?":
        "You are going to UNINSTALL %d TV app(s). This DELETES their data and can't be undone from here. If you only want them to stop working, «Disable» is better.\n\n• %s\n\nUninstall anyway?",
    "Hecho: %d/%d app(s) desactivadas.": "Done: %d/%d app(s) disabled.", "Hecho: %d/%d app(s) desinstaladas.": "Done: %d/%d app(s) uninstalled.",
    "No se pudo completar: %s": "Couldn't complete: %s",
    "Se DESACTIVARÁ la depuración (primero la depuración por red y después la USB) del TV para cerrarlo bien.\n(Recomendado al terminar.) ¿Continuar?":
        "TV debugging will be TURNED OFF (network debugging first, then USB) to close it properly.\n(Recommended when finished.) Continue?",
    "Depuración por red: %s\nDepuración ADB: %s\n\nRecuerda desactivar también «Opciones de desarrollador» en el TV.":
        "Network debugging: %s\nADB debugging: %s\n\nRemember to also turn off «Developer options» on the TV.",
    "desactivada ✔": "off ✔", "no confirmada ✖": "not confirmed ✖", "orden enviada (la conexión se cierra) ✔": "command sent (connection closes) ✔",
    "ALTO": "HIGH", "revisar": "review", "ok": "ok", "(ninguno/sideload)": "(none/sideload)",
    # privacidad
    "Blindaje de privacidad y telemetría": "Privacy & telemetry hardening",
    "Marca lo que quieras cambiar. NO se toca Defender, Firewall ni UAC. Al aplicar se guarda el valor ORIGINAL de cada ajuste; «Revertir» devuelve exactamente ese valor (o lo borra si antes no existía). Si un ajuste no tiene copia, no se toca.":
        "Tick what you want to change. Defender, Firewall and UAC are NOT touched. Applying saves the ORIGINAL value of each setting; «Revert» restores exactly that value (or deletes it if it didn't exist). Settings without a backup are not touched.",
    "🔒 Aplicar seleccionados": "🔒 Apply selected", "↩ Revertir seleccionados": "↩ Revert selected",
    "Marcar los no aplicados": "Tick not applied", "Marcar los aplicados (para revertir)": "Tick applied (to revert)", "Desmarcar todo": "Untick all",
    "Telemetría de Windows al mínimo": "Windows telemetry to minimum",
    "ID de publicidad (desactivar)": "Advertising ID (disable)",
    "Ubicación (servicio + apps + política)": "Location (service + apps + policy)",
    "Historial de actividad (no recopilar/subir)": "Activity history (don't collect/upload)",
    "Experiencias personalizadas con diagnóstico": "Tailored experiences with diagnostic data",
    "Seguimiento de apps abiertas (Inicio)": "Tracking of launched apps (Start)",
    "Contenido/anuncios sugeridos de Windows": "Windows suggested content/ads",
    "Búsqueda web / Bing en el menú Inicio": "Web search / Bing in the Start menu",
    "Acceso de webs a tu lista de idiomas": "Websites' access to your language list",
    "Notificaciones de comentarios (feedback)": "Feedback notifications",
    "✔ Aplicado por OptiShield (%s) — se puede revertir": "✔ Applied by OptiShield (%s) — can be reverted",
    "Ya está en modo privado (sin copia de OptiShield: no se puede revertir desde aquí)": "Already private (no OptiShield backup: can't be reverted from here)",
    "Sin aplicar": "Not applied",
    "Ejecuta OptiShield como administrador para cambiar estos ajustes.": "Run OptiShield as administrator to change these settings.",
    "Marca al menos una opción.": "Tick at least one option.",
    "Ninguno de los marcados tiene copia de OptiShield, así que no hay nada que revertir (no se toca nada).": "None of the ticked items has an OptiShield backup, so there's nothing to revert (nothing is touched).",
    "Privacidad aplicada: %d valores cambiados, %d servicios desactivados.": "Privacy applied: %d values changed, %d services disabled.",
    "Privacidad revertida: %d valores restaurados, %d servicios restaurados.": "Privacy reverted: %d values restored, %d services restored.",
    "Sin copia (no se tocó): %s": "No backup (not touched): %s",
    "Fallos: %s": "Failures: %s",
    "Reinicia el PC para que todo quede aplicado.": "Restart the PC so everything takes effect.",
    # arranque
    "Auditoría de arranque": "Startup audit",
    "Programas, tareas y entradas que arrancan con Windows (Run 64/32 bits, RunOnce, carpeta Inicio y tareas). En rojo = sospechoso (Temp, comandos ofuscados). En ámbar = OBSOLETO: apunta a un archivo que ya no existe. «Desconocido» = no se pudo comprobar (no se toca). Antes de cualquier cambio se guarda copia; «Restaurar arranque» lo devuelve.":
        "Programs, tasks and entries that start with Windows (Run 64/32-bit, RunOnce, Startup folder and tasks). Red = suspicious (Temp, obfuscated commands). Amber = ORPHANED: points to a file that no longer exists. «Unknown» = couldn't be checked (left alone). A backup is saved before any change; «Restore startup» brings it back.",
    "Nombre": "Name", "Tipo": "Type", "Ubicación": "Location", "Estado": "Status", "Comando": "Command",
    "⛔ Desactivar": "⛔ Disable", "✅ Activar": "✅ Enable", "🧹 Limpiar obsoletas": "🧹 Clean orphaned", "🗑 Eliminar": "🗑 Delete",
    "↩ Restaurar arranque": "↩ Restore startup", "Mostrar tareas de Windows": "Show Windows tasks",
    "Tarea": "Task", "Run (32 bits)": "Run (32-bit)", "RunOnce (32 bits)": "RunOnce (32-bit)", "Carpeta Inicio": "Startup folder",
    "Carpeta Inicio (todos)": "Startup folder (all users)",
    "⚠ obsoleto (no existe)": "⚠ orphaned (missing)", "sospechoso": "suspicious", "desconocido": "unknown", "desactivado": "disabled",
    "Ejecuta OptiShield como administrador para cambiar el arranque.": "Run OptiShield as administrator to change startup.",
    "Selecciona en la lista las entradas a tratar.": "Select the entries to handle in the list.",
    "Vas a tocar %d tarea(s) de WINDOWS (carpeta \\Microsoft\\):\n\n• %s\n\nDesactivar tareas del sistema puede romper actualizaciones, copias o funciones de Windows. Hazlo solo si sabes qué es. ¿Continuar?":
        "You are about to change %d WINDOWS task(s) (\\Microsoft\\ folder):\n\n• %s\n\nDisabling system tasks can break updates, backups or Windows features. Only do it if you know what it is. Continue?",
    "Se DESACTIVARÁN %d entrada(s) (se guarda copia):\n\n• %s\n\n¿Continuar?": "%d entry(ies) will be DISABLED (a backup is saved):\n\n• %s\n\nContinue?",
    "Se ACTIVARÁN %d entrada(s) (se guarda copia):\n\n• %s\n\n¿Continuar?": "%d entry(ies) will be ENABLED (a backup is saved):\n\n• %s\n\nContinue?",
    "Se ELIMINARÁN %d entrada(s) (se guarda copia exacta para «Restaurar arranque»; las tareas solo se DESACTIVAN y los accesos de la carpeta Inicio se mueven a la copia):\n\n• %s\n\n¿Continuar?":
        "%d entry(ies) will be DELETED (an exact backup is saved for «Restore startup»; tasks are only DISABLED and Startup-folder shortcuts are moved into the backup):\n\n• %s\n\nContinue?",
    "No hay entradas obsoletas (que apunten a un archivo que ya no existe). Pulsa «Escanear» primero.": "There are no orphaned entries (pointing to a file that no longer exists). Click «Scan» first.",
    "Entradas de arranque obsoletas": "Orphaned startup entries",
    "Estas entradas apuntan a un archivo que YA NO EXISTE. Marca las que quieras eliminar (se guarda copia exacta; «Restaurar arranque» las devuelve):":
        "These entries point to a file that NO LONGER EXISTS. Tick the ones you want to delete (an exact backup is saved; «Restore startup» brings them back):",
    "Eliminar las marcadas": "Delete ticked", "Cancelar": "Cancel",
    "Resultado:": "Result:", "✔ %s": "✔ %s", "✖ %s: %s": "✖ %s: %s",
    "RunOnce no tiene interruptor de activar/desactivar en Windows: solo se puede eliminar.": "RunOnce has no enable/disable switch in Windows: it can only be deleted.",
    "No hay copias de arranque.": "There are no startup backups.",
    "Restaurar arranque": "Restore startup", "Elige la copia a restaurar (la primera es la más reciente):": "Choose the backup to restore (the first one is the most recent):",
    "Restaurar": "Restore", "%s — %s — %d entrada(s)": "%s — %s — %d entry(ies)",
    "desactivar": "disable", "activar": "enable", "eliminar": "delete",
    "código de salida %s": "exit code %s", "no existe": "missing",
    # integridad
    "Integridad del sistema": "System integrity",
    "🧽 Quitar bloqueos hosts": "🧽 Remove hosts blocks", "🧯 Quitar reglas firewall": "🧯 Remove firewall rules",
    "📄 Exportar informe": "📄 Export report",
    "PROXY DEL SISTEMA: %s": "SYSTEM PROXY: %s", "ACTIVO → %s": "ACTIVE → %s", "sin proxy de sistema": "no system proxy",
    "SERVIDORES DNS:": "DNS SERVERS:", "  (no leído)": "  (not read)",
    "⚠ DOMINIOS IOC EN HOSTS (revisar):": "⚠ IOC DOMAINS IN HOSTS (review):",
    "✔ Sin dominios IOC sospechosos en hosts.": "✔ No suspicious IOC domains in hosts.",
    "ENTRADAS ACTIVAS EN HOSTS (%d, de ellas %d de OptiShield):": "ACTIVE HOSTS ENTRIES (%d, %d from OptiShield):",
    "  (vacío)": "  (empty)",
    "Nota: hosts no bloquea subdominios ni el DNS seguro (DoH) del navegador.": "Note: hosts doesn't block subdomains or the browser's secure DNS (DoH).",
    "router/red local": "router/local network",
    "Requiere administrador.": "Requires administrator.",
    "Se quitarán las líneas marcadas «# OptiShield» del archivo hosts (se guarda copia antes). ¿Continuar?": "Lines marked «# OptiShield» will be removed from the hosts file (a backup is saved first). Continue?",
    "Bloqueos de OptiShield retirados del archivo hosts: %d líneas. Copia: %s": "OptiShield blocks removed from the hosts file: %d lines. Backup: %s",
    "No pude editar hosts: %s": "Couldn't edit hosts: %s",
    "Se borrarán SOLO las reglas de firewall creadas por OptiShield («OptiShield block …»). ¿Continuar?": "ONLY the firewall rules created by OptiShield («OptiShield block …») will be deleted. Continue?",
    "Reglas de firewall de OptiShield eliminadas: %d de %d.": "OptiShield firewall rules removed: %d of %d.",
    "Informe guardado.": "Report saved.", "Texto": "Text",
    # apoyo
    "Una herramienta gratuita de OptiSuite para proteger tu privacidad y seguridad.": "A free OptiSuite tool to protect your privacy and security.",
    "Defensiva · reversible · Sin telemetría. Solo consultas DNS normales y, si pulsas el botón, ipify.org / AbuseIPDB.":
        "Defensive · reversible · No telemetry. Only normal DNS queries and, if you click the button, ipify.org / AbuseIPDB.",
    "OptiShield no sustituye a un antivirus.": "OptiShield doesn't replace an antivirus.",
    "Es gratis y sin anuncios. Si te ayuda, una estrella en GitHub o una aportación por Binance\nmantienen OptiSuite vivo. ¡Gracias! 🙌":
        "It's free and ad-free. If it helps you, a GitHub star or a donation via Binance\nkeeps OptiSuite alive. Thank you! 🙌",
    "⭐ Estrella en GitHub": "⭐ Star on GitHub", "🌐 Visitar OptiSuite": "🌐 Visit OptiSuite",
    "Donaciones por Binance (toca para copiar):": "Donations via Binance (tap to copy):",
    "© OptiSuite · OptiShield es gratuito. Si te ayuda, compártelo.": "© OptiSuite · OptiShield is free. If it helps you, share it.",
    # informe
    "informe": "report", "=== Proxyware ===": "=== Proxyware ===", "(sin datos: pulsa «Analizar todo» antes)": "(no data: click «Analyze all» first)",
    "=== Red (conexiones en rojo) ===": "=== Network (red connections) ===", "=== Arranque (sospechoso u obsoleto) ===": "=== Startup (suspicious or orphaned) ===",
    "=== Integridad ===": "=== Integrity ===", "=== Defender ===": "=== Defender ===", "(nada)": "(none)",
    "Generado en tu PC. OptiShield no tiene telemetría: solo consultas DNS normales y, si pulsas el botón, ipify.org / AbuseIPDB.":
        "Generated on your PC. OptiShield has no telemetry: only normal DNS queries and, if you click the button, ipify.org / AbuseIPDB.",
}

def tr(s):
    return TR.get(s, s) if LANG == "en" else s

class L:
    """Texto traducible perezoso: se traduce al formatear (así el texto dinámico cambia con el idioma)."""
    def __init__(self, key): self.key = key
    def __str__(self): return tr(self.key)
    def __repr__(self): return "L(%r)" % self.key

def fmt(key, args=()):
    s = tr(key)
    if args:
        try: return s % tuple(args)
        except Exception: return s + " " + " ".join(str(a) for a in args)
    return s


# ======================= BASE DE DATOS DE PROXYWARE =======================
# cat: "proxyware" = comparte TU conexión a cambio de dinero (o SDK oculto que lo hace).
#      "paid"      = cliente de un servicio de proxy de pago que TÚ usas (informativo).
#      "vpn"       = VPN normal (informativo).
# proc = nombres de proceso inequívocos; proc_generic = nombres genéricos que SOLO cuentan si la ruta del
# ejecutable está dentro de una carpeta de la firma (paths). domains = se bloquean al neutralizar (solo proxyware).
BUILTIN_DB = {
    # --- proxyware (comparte tu conexión) ---
    "honeygain":      {"name": "Honeygain", "cat": "proxyware", "risk": "medium", "proc": ["honeygain.exe"], "svc": ["HoneygainService"], "paths": ["Honeygain"], "reg": ["Honeygain"], "domains": ["honeygain.com", "honeygain.io"]},
    "pawns":          {"name": "Pawns.app (IPRoyal Pawns)", "cat": "proxyware", "risk": "medium", "proc": ["pawns.exe", "iproyal_pawns.exe", "pawns-cli.exe"], "svc": ["PawnsService"], "paths": ["Pawns", "IPRoyal Pawns"], "reg": ["Pawns", "IPRoyal Pawns"], "domains": ["pawns.app"]},
    "earnapp":        {"name": "EarnApp (Bright Data)", "cat": "proxyware", "risk": "medium", "proc": ["earnapp.exe"], "svc": ["EarnApp"], "paths": ["EarnApp"], "reg": ["EarnApp"], "domains": ["earnapp.com"]},
    "packetstream":   {"name": "PacketStream", "cat": "proxyware", "risk": "medium", "proc": ["packetstream.exe"], "proc_generic": ["psclient.exe"], "svc": ["PacketStream"], "paths": ["PacketStream"], "reg": ["PacketStream"], "domains": ["packetstream.io"]},
    "peer2profit":    {"name": "Peer2Profit", "cat": "proxyware", "risk": "medium", "proc": ["peer2profit.exe"], "proc_generic": ["p2papp.exe"], "paths": ["Peer2Profit"], "reg": ["Peer2Profit"], "domains": ["peer2profit.com"]},
    "traffmonetizer": {"name": "Traffmonetizer", "cat": "proxyware", "risk": "medium", "proc": ["traffmonetizer.exe"], "proc_generic": ["tm.exe"], "paths": ["Traffmonetizer"], "reg": ["Traffmonetizer"], "domains": ["traffmonetizer.com"]},
    "repocket":       {"name": "Repocket", "cat": "proxyware", "risk": "medium", "proc": ["repocket.exe"], "proc_generic": ["rpnetwork.exe"], "paths": ["Repocket"], "reg": ["Repocket"], "domains": ["repocket.co"]},
    "packetshare":    {"name": "PacketShare", "cat": "proxyware", "risk": "medium", "proc": ["packetshare.exe"], "paths": ["PacketShare"], "reg": ["PacketShare"], "domains": ["packetshare.io"]},
    "proxyrack_peer": {"name": "Proxyrack PeerConnect (compartir)", "cat": "proxyware", "risk": "high", "proc": ["peerconnect.exe"], "paths": ["PeerConnect"], "domains": []},
    "infatica":       {"name": "Infatica (red P2B)", "cat": "proxyware", "risk": "high", "proc": ["infatica.exe", "infatica-service.exe"], "svc": ["InfaticaService"], "paths": ["Infatica"], "reg": ["Infatica"], "domains": ["infatica.io"]},
    "netnut_sdk":     {"name": "NetNut SDK", "cat": "proxyware", "risk": "high", "paths": ["NetNut"], "reg": ["NetNut"], "domains": ["netnut.io", "netnut.net"]},
    "mysterium_node": {"name": "Mysterium (nodo MystNodes)", "cat": "proxyware", "risk": "medium", "proc": ["mystnodeslauncher.exe"], "svc": ["MysteriumNode"], "paths": ["MystNodes"], "domains": ["mystnodes.com"]},
    "hola":           {"name": "Hola VPN (gratis = nodo de salida)", "cat": "proxyware", "risk": "high", "proc": ["hola.exe", "hola_svc.exe", "hola_updater.exe"], "svc": ["hola_svc", "hola_updater"], "paths": ["Hola"], "reg": ["Hola"], "domains": ["hola.org", "holavpn.net"]},
    "grass":          {"name": "Grass (getgrass.io)", "cat": "proxyware", "risk": "medium", "proc_generic": ["grass.exe"], "paths": ["Grass"], "domains": ["getgrass.io"]},
    "nodepay":        {"name": "Nodepay", "cat": "proxyware", "risk": "medium", "paths": ["Nodepay"], "domains": ["nodepay.ai"]},
    "bytelixir":      {"name": "Bytelixir", "cat": "proxyware", "risk": "medium", "paths": ["Bytelixir"], "domains": ["bytelixir.com"]},
    "earnfm":         {"name": "EarnFM", "cat": "proxyware", "risk": "medium", "paths": ["EarnFM"], "domains": ["earn.fm"]},
    "proxylite":      {"name": "ProxyLite", "cat": "proxyware", "risk": "medium", "paths": ["ProxyLite"], "domains": []},
    "bitping":        {"name": "Bitping", "cat": "proxyware", "risk": "medium", "paths": ["Bitping"], "domains": ["bitping.com"]},
    "tuxler":         {"name": "Tuxler VPN (gratis = comparte tu IP)", "cat": "proxyware", "risk": "medium", "proc": ["tuxlervpn.exe"], "paths": ["tuxlerVPN", "Tuxler VPN"], "domains": ["tuxler.com"]},
    "salad":          {"name": "Salad (si compartes ancho de banda)", "cat": "proxyware", "risk": "low", "proc_generic": ["salad.exe"], "paths": ["Salad"], "domains": []},
    # --- proxies de pago que TÚ usas (informativo) ---
    "smartproxy_decodo": {"name": "Smartproxy / Decodo (proxy de pago)", "cat": "paid", "risk": "info", "proc": ["smartproxy.exe"], "paths": ["Smartproxy", "Decodo"], "domains": ["smartproxy.com", "decodo.com"]},
    "iproyal":        {"name": "IPRoyal (proxy de pago)", "cat": "paid", "risk": "info", "paths": ["IPRoyal"], "reg": ["IPRoyal"], "domains": ["iproyal.com"]},
    "oxylabs":        {"name": "Oxylabs (proxy de pago)", "cat": "paid", "risk": "info", "paths": ["Oxylabs"], "reg": ["Oxylabs"], "domains": ["oxylabs.io"]},
    "brightdata":     {"name": "Bright Data (proxy de pago)", "cat": "paid", "risk": "info", "paths": ["BrightData", "Bright Data"], "domains": ["brightdata.com"]},
    "proxycheap":     {"name": "Proxy-Cheap (proxy de pago)", "cat": "paid", "risk": "info", "paths": ["ProxyCheap", "Proxy-Cheap"], "domains": ["proxy-cheap.com"]},
    "ip2world_922":   {"name": "922 S5 / IP2World (proxy de pago)", "cat": "paid", "risk": "info", "proc": ["922proxy.exe", "ip2world.exe"], "proc_generic": ["s5.exe"], "paths": ["922proxy", "922 S5", "IP2World"], "domains": ["922proxy.com", "ip2world.com"]},
    "asocks":         {"name": "Asocks (proxy de pago)", "cat": "paid", "risk": "info", "proc": ["asocks.exe"], "paths": ["Asocks"], "domains": ["asocks.com"]},
    "proxifier":      {"name": "Proxifier (cliente de proxy)", "cat": "paid", "risk": "info", "proc": ["proxifier.exe"], "paths": ["Proxifier"], "domains": []},
    # --- VPN normales (informativo) ---
    "mysterium_vpn":  {"name": "Mysterium VPN", "cat": "vpn", "risk": "info", "paths": ["Mysterium VPN", "MysteriumVPN"], "domains": []},
    "psiphon":        {"name": "Psiphon", "cat": "vpn", "risk": "info", "proc": ["psiphon3.exe", "psiphon.exe"], "paths": ["Psiphon"], "domains": []},
    "betternet":      {"name": "Betternet", "cat": "vpn", "risk": "info", "proc": ["betternet.exe"], "paths": ["Betternet"], "domains": []},
    "touchvpn":       {"name": "TouchVPN", "cat": "vpn", "risk": "info", "proc": ["touchvpn.exe"], "paths": ["TouchVPN"], "domains": []},
}
PROXYWARE_DB = {k: dict(v) for k, v in BUILTIN_DB.items()}
IOC_DOMAINS = []

def _rebuild_ioc():
    del IOC_DOMAINS[:]
    for v in PROXYWARE_DB.values():
        if v.get("cat", "proxyware") == "proxyware":
            for d in v.get("domains", []) or []:
                if d not in IOC_DOMAINS: IOC_DOMAINS.append(d)

DB_MIN_VERSION = "1.2.0"
def _ver_tuple(v):
    try: return tuple(int(x) for x in str(v).split("."))
    except Exception: return (0,)

def _load_external_db():
    """Amplía/actualiza PROXYWARE_DB desde data\\proxyware_db.json (primero junto al .exe), sin recompilar."""
    for base in resource_dirs():
        p = os.path.join(base, "data", "proxyware_db.json")
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f) or {}
            sigs = data.get("signatures", {})
        except Exception:
            continue
        # Una BD antigua (< 1.2.0) traería firmas ya corregidas (Grasshopper, tm.exe sin carpeta…): se ignora.
        if _ver_tuple(data.get("_version", "0")) < _ver_tuple(DB_MIN_VERSION):
            log("proxyware_db.json %s ignorada (antigua): %s" % (data.get("_version"), p)); break
        for k, v in sigs.items():
            if isinstance(v, dict) and v.get("name"):
                v = dict(v); v.setdefault("cat", "proxyware"); v.setdefault("risk", "medium")
                PROXYWARE_DB[k] = v
        break
    _rebuild_ioc()


# ======================= AJUSTES DE PRIVACIDAD =======================
# reg: (hive, path, name, kind, valor_por_defecto_de_windows, valor_privado). Aplicar pone el valor privado.
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


# ======================= UTILIDADES DE SISTEMA =======================
def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception: return False

def _oem_encoding():
    try: return "cp%d" % ctypes.windll.kernel32.GetOEMCP()
    except Exception: return "cp850"
def _ansi_encoding():
    try: return "cp%d" % ctypes.windll.kernel32.GetACP()
    except Exception: return "cp1252"
OEM_ENC = _oem_encoding()
ANSI_ENC = _ansi_encoding()

def decode_oem(b, enc=None):
    """Decodifica la salida de un comando de consola (página de códigos OEM, p. ej. cp850)."""
    if b is None: return ""
    if isinstance(b, str): return b
    try: return b.decode(enc or OEM_ENC, errors="replace")
    except LookupError: return b.decode("utf-8", errors="replace")

def run_ex(args, timeout=40, enc=None):
    """Ejecuta un comando SIN ventana. Devuelve (código_salida, stdout, stderr) ya decodificados."""
    try:
        p = subprocess.run(args, capture_output=True, creationflags=CREATE_NO_WINDOW, timeout=timeout)
        return p.returncode, decode_oem(p.stdout, enc), decode_oem(p.stderr, enc)
    except FileNotFoundError as e:
        return -1, "", str(e)
    except subprocess.TimeoutExpired:
        return -2, "", "timeout"
    except Exception as e:
        return -3, "", str(e)

def run(args, timeout=40):
    return run_ex(args, timeout)[1]

PS_PREFIX = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ProgressPreference='SilentlyContinue'; "
def ps_ex(cmd, timeout=60):
    rc, out, err = run_ex(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                           "-Command", PS_PREFIX + cmd], timeout=timeout, enc="utf-8")
    return rc, out.lstrip("\ufeff"), err
def ps(cmd, timeout=60):
    return ps_ex(cmd, timeout)[1]

def psjson(cmd, timeout=60):
    out = ps(cmd + " | ConvertTo-Json -Compress -Depth 4", timeout).strip()
    if not out or out == "null": return []
    try:
        d = json.loads(out)
        return d if isinstance(d, list) else [d]
    except Exception: return []

def log(msg):
    try:
        with open(os.path.join(LOG_DIR, "optishield.log"), "a", encoding="utf-8") as f:
            f.write("[%s] %s\n" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg))
    except Exception: pass

_load_external_db()   # aquí: ya existe log()

def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]

def write_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f: json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)

def read_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as f: return json.load(f)
    except Exception: return default


# ---- Registro: lectura, copia exacta (tipo + dato) y restauración ----
import winreg
REG_TYPES = {winreg.REG_SZ: "REG_SZ", winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ", winreg.REG_DWORD: "REG_DWORD",
             winreg.REG_QWORD: "REG_QWORD", winreg.REG_BINARY: "REG_BINARY", winreg.REG_MULTI_SZ: "REG_MULTI_SZ",
             winreg.REG_NONE: "REG_NONE"}
REG_TYPES_INV = {v: k for k, v in REG_TYPES.items()}
KEY64 = winreg.KEY_WOW64_64KEY

def _hkey(h): return winreg.HKEY_LOCAL_MACHINE if h == "HKLM" else winreg.HKEY_CURRENT_USER

def reg_read(hive, path, name):
    try:
        with winreg.OpenKey(_hkey(hive), path, 0, winreg.KEY_READ | KEY64) as k:
            return winreg.QueryValueEx(k, name)[0]
    except Exception: return None

def reg_get(hive, path, name):
    """(existe, tipo_int, dato)"""
    try:
        with winreg.OpenKey(_hkey(hive), path, 0, winreg.KEY_READ | KEY64) as k:
            v, t = winreg.QueryValueEx(k, name)
            return True, t, v
    except Exception:
        return False, None, None

def _reg_key_exists(hive, path):
    try:
        with winreg.OpenKey(_hkey(hive), path, 0, winreg.KEY_READ | KEY64): return True
    except Exception: return False

def reg_snapshot(hive, path, name):
    """Copia exacta de un valor: si existía, su TIPO (REG_SZ/REG_EXPAND_SZ/...) y su dato."""
    ex, t, v = reg_get(hive, path, name)
    snap = {"hive": hive, "path": path, "name": name, "exists": ex}
    if ex:
        snap["type"] = REG_TYPES.get(t, str(t))
        snap["data"] = v.hex() if isinstance(v, (bytes, bytearray)) else v
    return snap

def reg_set(hive, path, name, typ, data):
    t = REG_TYPES_INV.get(typ, typ) if isinstance(typ, str) else typ
    if t == winreg.REG_BINARY and isinstance(data, str): data = bytes.fromhex(data)
    if t == winreg.REG_NONE and isinstance(data, str): data = bytes.fromhex(data) if data else None
    with winreg.CreateKeyEx(_hkey(hive), path, 0, winreg.KEY_SET_VALUE | KEY64) as k:
        winreg.SetValueEx(k, name, 0, t, data)

def reg_delete_value(hive, path, name):
    """Borra un valor. True si lo borró o ya no existía."""
    try:
        with winreg.OpenKey(_hkey(hive), path, 0, winreg.KEY_SET_VALUE | KEY64) as k:
            winreg.DeleteValue(k, name)
        return True
    except FileNotFoundError:
        return True

def reg_restore(snap):
    """Deja el valor EXACTAMENTE como estaba en la copia: si no existía → se borra; si existía → mismo tipo y dato."""
    if not snap.get("exists"):
        return reg_delete_value(snap["hive"], snap["path"], snap["name"])
    reg_set(snap["hive"], snap["path"], snap["name"], snap.get("type", "REG_SZ"), snap.get("data"))
    return True

def reg_write_kind(hive, path, name, kind, value):
    reg_set(hive, path, name, "REG_DWORD" if kind == "dword" else "REG_SZ", value)


# ---- Servicios: modo de arranque (copia y restauración) ----
SVC_KEY = "SYSTEM\\CurrentControlSet\\Services\\%s"
START_MODES = {0: "boot", 1: "system", 2: "auto", 3: "demand", 4: "disabled"}

def service_exists(name):
    return _reg_key_exists("HKLM", SVC_KEY % name)

def service_running(name):
    rc, out, _ = run_ex(["sc", "query", name], timeout=15)
    return rc == 0 and "RUNNING" in out.upper()

def service_snapshot(name):
    return {"name": name, "exists": service_exists(name),
            "start": reg_snapshot("HKLM", SVC_KEY % name, "Start"),
            "delayed": reg_snapshot("HKLM", SVC_KEY % name, "DelayedAutostart"),
            "running": service_running(name) if service_exists(name) else False}

def service_disable(name):
    """sc stop + sc config start= disabled. Devuelve (ok, detalle)."""
    if not service_exists(name): return False, tr("no existe")
    run_ex(["sc", "stop", name], timeout=30)
    rc, out, err = run_ex(["sc", "config", name, "start=", "disabled"], timeout=30)
    return rc == 0, ("" if rc == 0 else (out.strip() or err.strip() or fmt("código de salida %s", (rc,)))[-160:])

def service_restore(snap):
    """Vuelve a poner el modo de arranque original (y lo arranca si estaba en marcha). (ok, modo)"""
    name = snap["name"]
    if not snap.get("exists") or not snap.get("start", {}).get("exists"): return False, tr("no existe")
    start = int(snap["start"].get("data") or 3)
    mode = START_MODES.get(start, "demand")
    if start == 2 and snap.get("delayed", {}).get("exists") and int(snap["delayed"].get("data") or 0) == 1:
        mode = "delayed-auto"
    if mode in ("boot", "system"):
        reg_restore(snap["start"]); ok = True
    else:
        rc, out, err = run_ex(["sc", "config", name, "start=", mode], timeout=30); ok = rc == 0
    if ok and snap.get("running"):
        run_ex(["sc", "start", name], timeout=30)
    return ok, mode


# ======================= hosts (con copia y conservando la codificación) =======================
def hosts_read(path=HOSTS_FILE):
    """Devuelve (texto, codificación, salto_de_línea). Detecta UTF-8 (con/sin BOM) o ANSI."""
    with open(path, "rb") as f: raw = f.read()
    if raw.startswith(b"\xef\xbb\xbf"): enc = "utf-8-sig"
    else:
        try: raw.decode("utf-8"); enc = "utf-8"
        except UnicodeDecodeError: enc = ANSI_ENC
    text = raw.decode(enc, errors="replace")
    nl = "\r\n" if "\r\n" in text else ("\n" if "\n" in text else "\r\n")
    return text, enc, nl

def hosts_write(text, enc, path=HOSTS_FILE):
    with open(path, "wb") as f: f.write(text.encode(enc, errors="replace"))

def hosts_backup(path=HOSTS_FILE, backup_dir=BACKUP_DIR):
    os.makedirs(backup_dir, exist_ok=True)
    dst = os.path.join(backup_dir, "hosts_%s.bak" % stamp())
    shutil.copy2(path, dst)
    return dst

def hosts_block(domains, path=HOSTS_FILE, backup_dir=BACKUP_DIR):
    """Añade '0.0.0.0 dominio # OptiShield' (y www.) para los que falten. Devuelve (líneas_añadidas, copia)."""
    text, enc, nl = hosts_read(path)
    existing = set()
    for ln in text.splitlines():
        s = ln.split("#", 1)[0].split()
        for h in s[1:]: existing.add(h.lower())
    add = []
    for d in domains:
        for h in (d, "www." + d):
            if h.lower() not in existing:
                add.append("0.0.0.0 %s # OptiShield" % h); existing.add(h.lower())
    if not add: return [], None
    bk = hosts_backup(path, backup_dir)
    if text and not text.endswith(("\n", "\r")): text += nl
    text += nl.join(add) + nl
    hosts_write(text, enc, path)
    return add, bk

def hosts_remove(lines=None, path=HOSTS_FILE, backup_dir=BACKUP_DIR):
    """Quita las líneas indicadas (o, si lines=None, todas las que llevan '# OptiShield'). (n_quitadas, copia)"""
    text, enc, nl = hosts_read(path)
    parts = text.splitlines(True)
    want = set(l.strip() for l in lines) if lines is not None else None
    keep, removed = [], 0
    for p in parts:
        s = p.strip()
        if (want is not None and s in want) or (want is None and "# OptiShield" in p):
            removed += 1; continue
        keep.append(p)
    if not removed: return 0, None
    bk = hosts_backup(path, backup_dir)
    hosts_write("".join(keep), enc, path)
    return removed, bk

def flush_dns():
    return run_ex(["ipconfig", "/flushdns"], timeout=20)[0] == 0


# ======================= PROCESOS / SERVICIOS =======================
def list_processes_full():
    """Lista de {pid, name, path}. La ruta solo está disponible para procesos que podemos leer (admin = casi todos)."""
    res = []
    for p in psjson("Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ExecutablePath"):
        if isinstance(p, dict):
            res.append({"pid": str(p.get("ProcessId")), "name": p.get("Name") or "", "path": p.get("ExecutablePath") or ""})
    return res

def list_services():
    return [s for s in psjson("Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName") if isinstance(s, dict)]

def program_dirs():
    env = os.environ.get
    dirs = [env("ProgramFiles", ""), env("ProgramFiles(x86)", ""), env("LOCALAPPDATA", ""), env("APPDATA", ""), env("ProgramData", "")]
    if env("LOCALAPPDATA"): dirs.append(os.path.join(env("LOCALAPPDATA"), "Programs"))
    return [d for d in dict.fromkeys(dirs) if d]

def _path_in_sig_dirs(path, sig_paths):
    low = "\\" + (path or "").lower().replace("/", "\\")
    return any(("\\" + sp.lower() + "\\") in low for sp in sig_paths)


# ======================= ESCÁNER DE PROXYWARE =======================
V_RUN = "Comparte tu conexión: se está ejecutando"
V_INST = "Instalado (no se está ejecutando ahora)"
V_INFO = "Servicio de proxy/VPN que usas (informativo)"
V_ALLOWED = "Permitido por ti (lo instalaste a propósito)"
V_SOCKS_LOCAL = "Proxy local (informativo)"
V_SOCKS_LAN = "Proxy SOCKS5 abierto a tu red: revisar"
V_SDK = "SDK de proxyware cargado en una app: revisar"
RISK_LABEL = {"high": "alto", "medium": "medio", "low": "bajo", "info": "info"}

def match_signature(key, d, procs, svcs, dirs):
    """Busca una firma. procs: [{pid,name,path}], svcs: {lower(nombre): servicio}, dirs: carpetas base."""
    ev, mprocs, msvcs, folders = [], [], [], []
    running = False
    uniq = set(n.lower() for n in d.get("proc", []) or [])
    generic = set(n.lower() for n in d.get("proc_generic", []) or [])
    sig_paths = d.get("paths", []) or []
    for p in procs:
        nm = (p.get("name") or "").lower()
        if nm in uniq or (nm in generic and _path_in_sig_dirs(p.get("path"), sig_paths)):
            mprocs.append(p); running = True
            ev.append(["proceso", "%s (PID %s%s)" % (p.get("name"), p.get("pid"), (", " + p["path"]) if p.get("path") else "")])
    for sv in d.get("svc", []) or []:
        s = svcs.get(sv.lower())
        if s:
            msvcs.append(sv)
            st = str(s.get("State") or "")
            if st.lower() == "running": running = True
            ev.append(["servicio", "%s (%s)" % (sv, st or "?")])
    for base in dirs:
        for pth in sig_paths:
            full = os.path.join(base, pth)
            try:
                if os.path.isdir(full) and full not in folders:
                    folders.append(full); ev.append(["carpeta", full])
            except Exception: pass
    for rp in d.get("reg", []) or []:
        for hv in ("HKLM", "HKCU"):
            if _reg_key_exists(hv, "SOFTWARE\\" + rp):
                ev.append(["registro", "%s\\SOFTWARE\\%s" % (hv, rp)]); break
    if not ev: return None
    cat = d.get("cat", "proxyware")
    if cat == "proxyware": verdict = V_RUN if running else V_INST
    else: verdict = V_INFO
    return {"id": key, "name": d["name"], "cat": cat, "risk": d.get("risk", "medium") if cat == "proxyware" else "info",
            "evidence": ev, "domains": list(d.get("domains", []) or []) if cat == "proxyware" else [],
            "procs": mprocs, "svcs": msvcs, "folders": folders, "running": running, "verdict": verdict, "in_db": True}

def dedupe_findings(findings):
    """Une hallazgos con el mismo id (evita iids duplicados en la lista)."""
    out, idx = [], {}
    for f in findings:
        k = f["id"]
        if k in idx:
            g = idx[k]
            for e in f.get("evidence", []):
                if e not in g["evidence"]: g["evidence"].append(e)
            for key in ("procs", "svcs", "folders", "domains"):
                for x in f.get(key, []) or []:
                    if x not in g.setdefault(key, []): g[key].append(x)
            g["running"] = g.get("running") or f.get("running")
        else:
            g = dict(f); g["evidence"] = list(f.get("evidence", [])); idx[k] = g; out.append(g)
    return out

def is_problem(f, allowed=()):
    """¿Cuenta como problema? Solo proxyware/SOCKS abierto a la red/SDK, y no permitido por el usuario."""
    if f["id"] in allowed: return False
    return f.get("cat") in ("proxyware", "socks_lan", "sdk")

def scan_proxyware(procs=None, svcs=None, dirs=None, include_ports=True, include_sdk=True):
    if procs is None: procs = list_processes_full()
    if svcs is None: svcs = {(s.get("Name") or "").lower(): s for s in list_services()}
    if dirs is None: dirs = program_dirs()
    findings = []
    for key, d in PROXYWARE_DB.items():
        try:
            f = match_signature(key, d, procs, svcs, dirs)
            if f: findings.append(f)
        except Exception as e:
            log("firma %s: %s" % (key, e))
    if include_ports:
        by_pid = {p["pid"]: p for p in procs}
        findings.extend(scan_socks(by_pid))
    if include_sdk:
        findings.extend(scan_embedded_sdk())
    return dedupe_findings(findings)


# ---- SOCKS5: un proxy escuchando en 127.0.0.1 es LOCAL (Tor, Clash, v2rayN, ssh -D…), no un nodo de salida ----
SAFE_PORTS = {135,139,445,3306,33060,33061,5432,1433,1434,27017,27018,6379,11211,5000,5001,
              7680,8005,9000,3389,5900,1521,2049,25,110,143,993,995}
KNOWN_LOCAL_PROXIES = {"tor.exe": "Tor", "firefox.exe": "Tor Browser / Firefox", "clash.exe": "Clash", "clash-verge.exe": "Clash Verge",
                       "mihomo.exe": "Clash (mihomo)", "v2rayn.exe": "v2rayN", "xray.exe": "Xray (v2rayN)", "v2ray.exe": "V2Ray",
                       "sing-box.exe": "sing-box", "ssh.exe": "ssh -D", "privoxy.exe": "Privoxy", "proxifier.exe": "Proxifier"}

def listening_ports():
    """[(puerto, dirección_local, pid)] de sockets TCP a la escucha (IPv4 e IPv6)."""
    out = run(["netstat", "-ano", "-p", "TCP"]) + "\n" + run(["netstat", "-ano", "-p", "TCPv6"])
    res = []
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 5 and p[0].upper().startswith("TCP") and p[3].upper() in ("LISTENING", "ESCUCHANDO"):
            try:
                addr, port = p[1].rsplit(":", 1)
                res.append((int(port), addr.strip("[]"), p[4]))
            except Exception: pass
    return res

def _is_socks5(port, host="127.0.0.1"):
    """Handshake SOCKS5 real: respuesta de EXACTAMENTE 2 bytes = 0x05 + método válido (00/01/02/FF)."""
    if port in SAFE_PORTS: return False
    try:
        with socket.create_connection((host, port), timeout=0.6) as s:
            s.settimeout(0.6)
            s.sendall(b"\x05\x01\x00")
            r = s.recv(4)
        return len(r) == 2 and r[0] == 0x05 and r[1] in (0x00, 0x01, 0x02, 0xFF)
    except Exception:
        return False

def _is_loopback(addr):
    return addr.startswith("127.") or addr in ("::1", "localhost")

def socks_finding(port, addrs, pid, pname="", ppath=""):
    """Clasifica un SOCKS5 detectado. Solo loopback → informativo. Abierto a la red → revisar."""
    local_only = all(_is_loopback(a) for a in addrs)
    owner = pname or "?"
    label = KNOWN_LOCAL_PROXIES.get(owner.lower())
    who = owner + ((" = " + label) if label else "")
    return {"id": "socks5_%d" % port, "name": "Proxy SOCKS5 en el puerto %d (%s)", "name_args": [port, who],
            "cat": "socks_local" if local_only else "socks_lan", "risk": "info" if local_only else "medium",
            "evidence": [["puerto", "%d en %s · PID %s%s" % (port, ", ".join(sorted(set(addrs))), pid, (" · " + ppath) if ppath else "")]],
            "domains": [], "procs": [{"pid": str(pid), "name": pname, "path": ppath}] if pid else [], "svcs": [], "folders": [],
            "running": True, "verdict": V_SOCKS_LOCAL if local_only else V_SOCKS_LAN, "in_db": False}

def scan_socks(procs_by_pid=None):
    procs_by_pid = procs_by_pid or {}
    ports = {}
    for port, addr, pid in listening_ports():
        if port <= 1024 or port in SAFE_PORTS or pid in ("0", "4"): continue
        e = ports.setdefault(port, {"addrs": set(), "pid": pid}); e["addrs"].add(addr)
    found = []
    def probe(port, info):
        host = "127.0.0.1"
        if all(":" in a for a in info["addrs"]): host = "::1"
        if _is_socks5(port, host):
            p = procs_by_pid.get(str(info["pid"]), {})
            found.append(socks_finding(port, info["addrs"], info["pid"], p.get("name", ""), p.get("path", "")))
    ths = [threading.Thread(target=probe, args=(pt, inf), daemon=True) for pt, inf in ports.items()]
    for i in range(0, len(ths), 24):
        for t in ths[i:i+24]: t.start()
        for t in ths[i:i+24]: t.join(2.0)
    return sorted(found, key=lambda f: f["id"])


# ---- SDK de proxyware incrustado en apps comunes (DLLs cargadas) ----
SDK_SIGS = ["netnut", "luminati", "brightdata", "bright_data", "oxylabs", "pawns", "honeygain",
            "packetstream", "peer2profit", "proxyrack", "infatica", "iproyal", "asocks", "traffmonetizer", "repocket"]
HOST_PROCS = ["chrome", "msedge", "firefox", "brave", "opera", "spotify", "discord"]
def scan_embedded_sdk():
    out = ps("Get-Process %s -ErrorAction SilentlyContinue | ForEach-Object { $n=$_.Name; $i=$_.Id; "
             "try { $_.Modules | ForEach-Object { \"$n|$i|$($_.ModuleName)|$($_.FileName)\" } } catch {} }" % ",".join(HOST_PROCS), timeout=90)
    found = {}
    for ln in out.splitlines():
        parts = ln.strip().split("|")
        if len(parts) < 4: continue
        base, pid, mod, fpath = parts[0], parts[1], parts[2], parts[3]
        low = mod.lower()
        if not low.endswith(".dll"): continue
        for sig in SDK_SIGS:
            if sig in low:
                fid = "sdk_%s_%s" % (base.lower(), sig)
                f = found.get(fid)
                if not f:
                    f = found[fid] = {"id": fid, "name": "SDK de proxyware dentro de %s", "name_args": [base + ".exe"],
                                      "cat": "sdk", "risk": "high", "evidence": [], "domains": [], "procs": [], "svcs": [],
                                      "folders": [], "running": True, "verdict": V_SDK, "in_db": False, "pids": []}
                e = ["DLL", "%s (%s)" % (mod, fpath)]
                if e not in f["evidence"]: f["evidence"].append(e)
                if pid not in f["pids"]: f["pids"].append(pid)
                break
    return list(found.values())


def finding_name(f):
    return fmt(f["name"], f.get("name_args") or ())

def finding_evidence(f, limit=None):
    s = " · ".join("%s: %s" % (tr(k), v) for k, v in f.get("evidence", []))
    return s[:limit] if limit else s


# ---- Neutralizar / deshacer (con copia) ----
def _fw_rule_name(fid, exe_path):
    return "OptiShield block %s (%s)" % (os.path.basename(exe_path), fid)

def firewall_block_program(rule, exe_path):
    rc, out, err = run_ex(["netsh", "advfirewall", "firewall", "add", "rule", "name=%s" % rule,
                           "dir=out", "action=block", "program=%s" % exe_path, "enable=yes"], timeout=30)
    return rc == 0, (out.strip() or err.strip())[-160:]

def firewall_delete_rule(rule):
    rc, out, err = run_ex(["netsh", "advfirewall", "firewall", "delete", "rule", "name=%s" % rule], timeout=30)
    return rc == 0

def process_path(pid):
    out = ps("(Get-CimInstance Win32_Process -Filter 'ProcessId=%d').ExecutablePath" % int(pid), timeout=20).strip()
    return out

def kill_pid_if_path(pid, expected_path, expected_name=""):
    """Termina SOLO ese PID si sigue siendo el mismo programa (misma ruta o, sin ruta, mismo nombre). (estado, detalle)"""
    try: pid = int(pid)
    except Exception: return "gone", ""
    cur = process_path(pid)
    if expected_path:
        if not cur or os.path.normcase(cur) != os.path.normcase(expected_path): return "gone", ""
    else:
        rows = psjson("Get-CimInstance Win32_Process -Filter 'ProcessId=%d' | Select-Object Name" % pid)
        if not rows or (rows[0].get("Name") or "").lower() != (expected_name or "").lower(): return "gone", ""
    rc, out, err = run_ex(["taskkill", "/F", "/PID", str(pid)], timeout=30)
    return ("ok" if rc == 0 else "fail"), (out.strip() or err.strip())[-160:]

def _exes_in_folder(folder, limit=20):
    res = []
    try:
        for root, dirs, files in os.walk(folder):
            if root.count(os.sep) - folder.count(os.sep) > 2: dirs[:] = []; continue
            for fn in files:
                if fn.lower().endswith(".exe"): res.append(os.path.join(root, fn))
                if len(res) >= limit: return res
    except Exception: pass
    return res

def neutralize(findings, backup_dir=BACKUP_DIR, hosts_path=HOSTS_FILE):
    """Neutraliza hallazgos DE LA BASE DE DATOS. Devuelve (líneas_resumen [(clave,args)], ruta_copia)."""
    st = stamp()
    bk = {"kind": "neutralize", "when": st, "undone": False, "items": [], "services": [], "fw_rules": [],
          "hosts_added": [], "hosts_backup": None}
    lines = []
    domains = []
    for f in findings:
        bk["items"].append({"id": f["id"], "name": finding_name(f)})
        exes = []
        for p in f.get("procs", []):
            if p.get("path") and p["path"] not in exes: exes.append(p["path"])
        for fo in f.get("folders", []):
            for e in _exes_in_folder(fo):
                if e not in exes: exes.append(e)
        if not exes: lines.append(("• Sin ruta de programa conocida: no se creó regla de firewall.", ()))
        for exe in exes:
            rule = _fw_rule_name(f["id"], exe)
            ok, det = firewall_block_program(rule, exe)
            if ok:
                bk["fw_rules"].append(rule); lines.append(("✔ Firewall: bloqueado %s", (exe,)))
            else:
                lines.append(("✖ Firewall: no pude bloquear %s (%s)", (exe, det)))
        for p in f.get("procs", []):
            status, det = kill_pid_if_path(p.get("pid"), p.get("path"), p.get("name"))
            if status == "ok": lines.append(("✔ Proceso detenido: %s (PID %s)", (p.get("name"), p.get("pid"))))
            elif status == "fail": lines.append(("✖ No pude detener %s (PID %s): %s", (p.get("name"), p.get("pid"), det)))
            else: lines.append(("• %s (PID %s) ya no se estaba ejecutando o cambió de programa: no se tocó.", (p.get("name"), p.get("pid"))))
        for sv in f.get("svcs", []):
            snap = service_snapshot(sv)
            bk["services"].append(snap)
            write_json(os.path.join(backup_dir, "neutralize_%s.json" % st), bk)   # copia ANTES de tocar
            ok, det = service_disable(sv)
            lines.append(("✔ Servicio desactivado: %s", (sv,)) if ok else ("✖ Servicio %s: %s", (sv, det)))
        domains += [d for d in f.get("domains", []) if d not in domains]
    if domains:
        try:
            added, hb = hosts_block(domains, hosts_path, backup_dir)
            bk["hosts_added"] = added; bk["hosts_backup"] = hb
            flush_dns()
            lines.append(("✔ hosts: bloqueados %d nombres (+ DNS vaciado)", (len(added),)))
        except Exception as e:
            lines.append(("✖ hosts: no pude escribir (%s)", (str(e),)))
    path = os.path.join(backup_dir, "neutralize_%s.json" % st)
    write_json(path, bk)
    for k, a in lines: log("neutralizar: " + fmt(k, a))
    return lines, path

def last_neutralize_backup(backup_dir=BACKUP_DIR):
    try:
        files = sorted((f for f in os.listdir(backup_dir) if f.startswith("neutralize_") and f.endswith(".json")), reverse=True)
    except Exception: return None
    for fn in files:
        d = read_json(os.path.join(backup_dir, fn), {})
        if d and not d.get("undone"): return os.path.join(backup_dir, fn)
    return None

def undo_neutralize(path, hosts_path=HOSTS_FILE, backup_dir=BACKUP_DIR):
    bk = read_json(path, {}) or {}
    lines = []
    for snap in bk.get("services", []):
        ok, mode = service_restore(snap)
        lines.append(("✔ Servicio %s → %s", (snap["name"], mode)) if ok else ("✖ Servicio %s: %s", (snap["name"], mode)))
    for rule in bk.get("fw_rules", []):
        lines.append(("✔ Regla de firewall quitada: %s", (rule,)) if firewall_delete_rule(rule) else ("✖ No pude quitar la regla %s", (rule,)))
    if bk.get("hosts_added"):
        try:
            n, _ = hosts_remove(bk["hosts_added"], hosts_path, backup_dir); flush_dns()
            lines.append(("✔ hosts: quitadas %d líneas", (n,)))
        except Exception as e:
            lines.append(("✖ hosts: no pude escribir (%s)", (str(e),)))
    bk["undone"] = True; bk["undone_when"] = stamp()
    write_json(path, bk)
    return lines


# ======================= RED LOCAL (IoT / Badbox) =======================
def _port_open(ip, port, timeout=0.35):
    try:
        with socket.create_connection((ip, port), timeout=timeout): return True
    except Exception: return False

_rdns_cache = {}
_rdns_lock = threading.Lock()
def resolve_many(ips, deadline=4.0, workers=32):
    """DNS inverso en paralelo con límite de tiempo total (sin tocar el timeout global de sockets)."""
    res = {}
    todo = []
    with _rdns_lock:
        for ip in ips:
            if ip in _rdns_cache: res[ip] = _rdns_cache[ip]
            else: todo.append(ip)
    sem = threading.Semaphore(workers)
    def one(ip):
        with sem:
            try: h = socket.gethostbyaddr(ip)[0]
            except Exception: h = ""
        with _rdns_lock:
            _rdns_cache[ip] = h; res[ip] = h
    ths = [threading.Thread(target=one, args=(ip,), daemon=True) for ip in todo]
    for t in ths: t.start()
    end = time.time() + deadline
    for t in ths: t.join(max(0.0, end - time.time()))
    with _rdns_lock:
        return {ip: res.get(ip, "") for ip in ips}

def host_name(ip):
    return resolve_many([ip], deadline=2.0).get(ip, "")

DEBUG_PORTS = {5555: "ADB (vector Badbox)", 23: "Telnet", 21: "FTP", 9527: "debug/UART", 7001: "debug", 4444: "backdoor"}
PORT_INFO = {
    5555: "Depuración ADB de Android expuesta a la red — el vector típico de Badbox. En una TV-box legítima debería estar CERRADO. Si es tu equipo y activaste ADB por red a propósito, márcalo de confianza y ciérralo al terminar.",
    23:   "Telnet: acceso remoto SIN cifrar, muy usado por botnets IoT (Mirai/Badbox). Casi ningún dispositivo doméstico moderno debería tenerlo abierto.",
    21:   "FTP: transferencia de archivos sin cifrar; en un equipo de casa normal no suele estar abierto.",
    9527: "Puerto de depuración/UART común en cámaras IP y TV-box baratas comprometidas.",
    7001: "Puerto de depuración/administración; sospechoso en un dispositivo de consumo.",
    4444: "Puerto asociado a backdoors (p. ej. Metasploit); muy sospechoso.",
}

def _probe_debug_ports(ips):
    res = {ip: [] for ip in ips}
    lock = threading.Lock()
    def one(ip, port, label):
        if _port_open(ip, port):
            with lock: res[ip].append((port, "%d %s" % (port, label)))
    ths = [threading.Thread(target=one, args=(ip, p, l), daemon=True) for ip in ips for p, l in DEBUG_PORTS.items()]
    for i in range(0, len(ths), 64):
        for t in ths[i:i+64]: t.start()
        for t in ths[i:i+64]: t.join(2.0)
    return {ip: [x[1] for x in sorted(v)] for ip, v in res.items()}

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
    return OUI.get(mac.lower().replace(":", "-")[:8], "")

TRUSTED_FILE = os.path.join(DATA_DIR, "trusted.json")
def _norm_mac(mac): return (mac or "").lower().replace(":", "-")
def load_trusted():
    d = read_json(TRUSTED_FILE, {}) or {}
    return {"ips": set(d.get("ips", [])), "macs": set(_norm_mac(x) for x in d.get("macs", []))}
def save_trusted(t):
    try: write_json(TRUSTED_FILE, {"ips": sorted(t["ips"]), "macs": sorted(t["macs"])})
    except Exception: pass
def is_trusted(t, ip, mac):
    return (ip in t["ips"]) or (bool(mac) and _norm_mac(mac) in t["macs"])

def _arp_table():
    out = run(["arp", "-a"]); res = []
    for line in out.splitlines():
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{11,17})\s+(\S+)", line)
        if not m: continue
        ip, mac, typ = m.group(1), m.group(2), m.group(3).lower()
        if ip.endswith(".255") or ip.startswith(("224.", "239.")) or mac.lower().startswith("ff-ff"): continue
        res.append((ip, mac, typ))
    return res

def _build_devices(entries, myip=None):
    """entries: [(ip, mac)]. Sondea puertos y DNS en paralelo."""
    ips = [ip for ip, _ in entries]
    openp = _probe_debug_ports(ips)
    names = resolve_many([ip for ip in ips if ip != myip], deadline=4.0)
    t = load_trusted(); devices = []
    for ip, mac in entries:
        mine = (ip == myip)
        trusted = is_trusted(t, ip, mac) or mine
        devices.append({"ip": ip, "mac": mac, "vendor": mac_vendor(mac) or ("(este PC)" if mine else "(desconocido)"),
                        "host": "(este PC)" if mine else names.get(ip, ""), "open": openp.get(ip, []),
                        "trusted": trusted, "risk": bool(openp.get(ip)) and not trusted})
    return devices

def scan_local_network():
    """Tabla ARP (equipos ya vistos) + sondeo SOLO de puertos de depuración."""
    seen, entries = set(), []
    for ip, mac, typ in _arp_table():
        if ("dynamic" in typ or "din" in typ) and ip not in seen:
            seen.add(ip); entries.append((ip, mac))
    return _build_devices(entries)

def _my_subnet():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]   # UDP connect: no envía paquetes
        return ip.rsplit(".", 1)[0] + ".", ip
    except Exception:
        return None, None

def _ping(ip):
    rc, out, _ = run_ex(["ping", "-n", "1", "-w", "400", ip], timeout=5)
    return "TTL=" in out.upper()

def scan_local_network_deep(progress=None):
    """Barrido ACTIVO de TU subred (/24)."""
    base, myip = _my_subnet()
    if not base: return []
    alive = []; lock = threading.Lock()
    def worker(n):
        ip = "%s%d" % (base, n)
        if _ping(ip):
            with lock: alive.append(ip)
    targets = list(range(1, 255))
    for i in range(0, len(targets), 32):
        ths = [threading.Thread(target=worker, args=(n,), daemon=True) for n in targets[i:i+32]]
        for t in ths: t.start()
        for t in ths: t.join(6)
        if progress: progress(min(i + 32, 254), 254)
    macs = {ip: mac for ip, mac, _ in _arp_table()}
    entries = [(ip, macs.get(ip, "")) for ip in sorted(alive, key=lambda x: int(x.rsplit(".", 1)[1]))]
    return _build_devices(entries, myip)

def public_ip():
    try:
        import urllib.request
        return urllib.request.urlopen("https://api.ipify.org", timeout=6).read().decode().strip()
    except Exception: return None


# ======================= MÓDULO ADB (limpiar TV / TV-box Android) =======================
KNOWN_STORES = {"com.android.vending", "com.amazon.venezia", "com.sec.android.app.samsungapps",
                "com.huawei.appmarket", "com.xiaomi.market", "com.google.android.packageinstaller"}
# Firmas FUERTES (familias conocidas) → ALTO. Palabras genéricas → solo «revisar».
BADBOX_STRONG = ["triada", "hnyp", "com.rock.", "gota", "clicker"]
BADBOX_WEAK = ["proxy", "peer", "hidden", "silent", "adsdk", "ad.sdk", "residential", "rooter"]

def _find_adb():
    cands = [os.path.join(b, "platform-tools", "adb.exe") for b in resource_dirs()]
    w = shutil.which("adb")
    if w: cands.append(w)
    for p in (os.environ.get("LOCALAPPDATA", ""), os.environ.get("USERPROFILE", "")):
        if p: cands.append(os.path.join(p, "Android", "Sdk", "platform-tools", "adb.exe"))
    for c in cands:
        if c and os.path.isfile(c): return c
    return None

def adb_connect(adb, ip):
    if ":" not in ip: ip = ip + ":5555"
    return run([adb, "connect", ip], timeout=20)

def adb_devices(adb):
    """[(serial, estado)] — estado: device / unauthorized / offline…"""
    out = run([adb, "devices"], timeout=20); devs = []
    for ln in out.splitlines()[1:]:
        p = ln.split()
        if len(p) >= 2: devs.append((p[0], p[1]))
    return devs

def adb_model(adb, serial):
    return (run([adb, "-s", serial, "shell", "getprop", "ro.product.model"], timeout=15).strip() + " / " +
            run([adb, "-s", serial, "shell", "getprop", "ro.product.manufacturer"], timeout=15).strip())

def classify_package(pkg, installer):
    inst = (installer or "").strip()
    sideload = inst in ("", "null") or inst not in KNOWN_STORES
    low = pkg.lower()
    strong = any(h in low for h in BADBOX_STRONG)
    weak = any(h in low for h in BADBOX_WEAK)
    risk = "ALTO" if strong else ("revisar" if (weak or sideload) else "ok")
    return risk

def adb_list_packages(adb, serial):
    out = run([adb, "-s", serial, "shell", "pm", "list", "packages", "-3", "-i"], timeout=40)
    pkgs = []
    for ln in out.splitlines():
        m = re.match(r"package:(\S+)(?:\s+installer=(\S+))?", ln.strip())
        if not m: continue
        pkg = m.group(1); inst = (m.group(2) or "").strip()
        risk = classify_package(pkg, inst)
        pkgs.append({"pkg": pkg, "installer": inst if inst and inst != "null" else "(ninguno/sideload)", "risk": risk, "flag": risk != "ok"})
    return sorted(pkgs, key=lambda x: (x["risk"] != "ALTO", x["risk"] != "revisar", x["pkg"]))

def adb_disable(adb, serial, pkg):
    return run([adb, "-s", serial, "shell", "pm", "disable-user", "--user", "0", pkg], timeout=30)

def adb_uninstall(adb, serial, pkg):
    return run([adb, "-s", serial, "shell", "pm", "uninstall", "--user", "0", pkg], timeout=60)

def adb_close_debug(adb, serial):
    """Primero la depuración por red (y se comprueba), después la USB/ADB. Devuelve (wifi_ok, adb_ok)."""
    run_ex([adb, "-s", serial, "shell", "settings", "put", "global", "adb_wifi_enabled", "0"], timeout=20)
    rc, out, _ = run_ex([adb, "-s", serial, "shell", "settings", "get", "global", "adb_wifi_enabled"], timeout=20)
    wifi_ok = rc == 0 and out.strip() in ("0", "null", "")
    rc2, _, _ = run_ex([adb, "-s", serial, "shell", "settings", "put", "global", "adb_enabled", "0"], timeout=20)
    return wifi_ok, rc2 == 0


# ======================= ARRANQUE =======================
EXEC_EXTS = (".exe", ".bat", ".cmd", ".com", ".scr", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".ps1", ".lnk", ".msi", ".dll", ".cpl", ".pif")

def _exe_from_cmd(cmd):
    """Extrae el ejecutable de una línea de comando de arranque."""
    cmd = (cmd or "").strip()
    if not cmd: return ""
    if cmd[0] == '"':
        end = cmd.find('"', 1)
        return cmd[1:end] if end > 0 else cmd[1:]
    m = re.match(r'^(.*?\.(?:exe|bat|cmd|com|scr|vbs|js|ps1|lnk|msi))(?=\s|$|,)', cmd, re.I)
    if m: return m.group(1)
    return cmd.split()[0]

def _resolve_program(name):
    """Busca un programa sin ruta como lo haría Windows: PATH (+PATHEXT), System32, SysWOW64, Windows."""
    cands = [name] if os.path.splitext(name)[1] else [name + ".exe", name + ".com", name + ".bat", name + ".cmd", name]
    for c in cands:
        w = shutil.which(c)
        if w: return w
        for d in (os.path.join(WINDIR, "System32"), os.path.join(WINDIR, "Sysnative"), os.path.join(WINDIR, "SysWOW64"), WINDIR):
            p = os.path.join(d, c)
            if os.path.isfile(p): return p
    return None

def orphan_state(cmd):
    """'ok' (existe), 'orphan' (ruta ABSOLUTA con extensión de programa que ya no existe) o 'unknown'."""
    raw = _exe_from_cmd(os.path.expandvars(cmd or ""))
    exe = raw.strip().strip('"')
    if not exe: return "unknown"
    is_abs = bool(re.match(r"^[a-zA-Z]:\\", exe)) or exe.startswith("\\\\")
    if is_abs:
        try:
            if os.path.exists(exe): return "ok"
            # redirección WOW64: System32 visto desde un proceso de 32 bits
            alt = re.sub(r"(?i)\\system32\\", r"\\Sysnative\\", exe)
            if alt != exe and os.path.exists(alt): return "ok"
        except Exception:
            return "unknown"
        if os.path.splitext(exe)[1].lower() in EXEC_EXTS:
            return "orphan"
        return "unknown"
    if "\\" in exe or "/" in exe:   # ruta relativa: no se puede afirmar nada
        return "unknown"
    return "ok" if _resolve_program(exe) else "unknown"

def _is_orphan(cmd):
    return orphan_state(cmd) == "orphan"

SA_BASE = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved"
RUN_SOURCES = [
    # (hive, ruta, etiqueta, (hive_sa, ruta_sa) o None si Windows no permite activar/desactivar)
    ("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "Run", ("HKLM", SA_BASE + "\\Run")),
    ("HKLM", "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "Run (32 bits)", ("HKLM", SA_BASE + "\\Run32")),
    ("HKCU", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "Run", ("HKCU", SA_BASE + "\\Run")),
    ("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "RunOnce", None),
    ("HKLM", "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "RunOnce (32 bits)", None),
    ("HKCU", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "RunOnce", None),
]
SUSP_RES = [re.compile(x, re.I) for x in (
    r"\\temp\\", r"\\appdata\\local\\temp\\",
    r"(^|\s)-(e|ec|en|enc|enco|encod|encodedcommand)\s+[a-z0-9+/=]{16,}",   # PowerShell con comando codificado
    r"frombase64string", r"mshta(\.exe)?\s+[\"']?(https?|javascript|vbscript):", r"(iwr|invoke-webrequest|downloadstring)\b.*https?://")]
def is_suspicious_cmd(cmd):
    return any(r.search(cmd or "") for r in SUSP_RES)

def startup_enabled(sa_hive, sa_path, name):
    """StartupApproved: byte 0 par (02/06) = activado, impar (03/07) = desactivado. Ausente = activado."""
    ex, t, v = reg_get(sa_hive, sa_path, name)
    if not ex or not isinstance(v, (bytes, bytearray)) or not v: return True
    return not (v[0] & 1)

def _sa_blob(enabled):
    import struct
    if enabled: return bytes([2] + [0] * 11)
    epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    ft = int((datetime.datetime.now(datetime.timezone.utc) - epoch).total_seconds() * 10_000_000)
    return bytes([3, 0, 0, 0]) + struct.pack("<Q", ft)

def scan_run_key(hive, path, label, sa):
    items = []
    try:
        with winreg.OpenKey(_hkey(hive), path, 0, winreg.KEY_READ | KEY64) as k:
            i = 0
            while True:
                try: name, val, typ = winreg.EnumValue(k, i); i += 1
                except OSError: break
                cmd = str(val)
                items.append({"type": "RunOnce" if label.startswith("RunOnce") else "Run", "label": label,
                              "loc": hive + ("\\WOW6432Node" if "WOW6432Node" in path else ""),
                              "name": name, "cmd": cmd, "hive": hive, "regpath": path, "regtype": REG_TYPES.get(typ, str(typ)),
                              "susp": is_suspicious_cmd(cmd), "orphan": orphan_state(cmd),
                              "sa": list(sa) if sa else None,
                              "enabled": startup_enabled(sa[0], sa[1], name) if sa else True, "is_ms": False})
    except Exception: pass
    return items

def startup_folders():
    res = []
    ap = os.environ.get("APPDATA"); pd = os.environ.get("ProgramData")
    if ap: res.append((os.path.join(ap, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"), "HKCU", "Carpeta Inicio"))
    if pd: res.append((os.path.join(pd, "Microsoft", "Windows", "Start Menu", "Programs", "StartUp"), "HKLM", "Carpeta Inicio (todos)"))
    return res

def scan_startup_folders():
    items = []
    for folder, sa_hive, label in startup_folders():
        try: files = os.listdir(folder)
        except Exception: continue
        for fn in files:
            if fn.lower() == "desktop.ini": continue
            full = os.path.join(folder, fn)
            if not os.path.isfile(full): continue
            sa = (sa_hive, SA_BASE + "\\StartupFolder")
            items.append({"type": "Carpeta", "label": label, "loc": folder, "name": fn, "cmd": full, "file": full,
                          "susp": False, "orphan": "ok", "sa": list(sa), "enabled": startup_enabled(sa[0], sa[1], fn), "is_ms": False})
    return items

def scan_tasks():
    items = []
    rows = psjson("Get-ScheduledTask | Select-Object TaskName,TaskPath,@{n='State';e={$_.State.ToString()}},"
                  "@{n='Exe';e={($_.Actions | Select-Object -First 1).Execute}},@{n='Args';e={($_.Actions | Select-Object -First 1).Arguments}}", timeout=90)
    for t in rows:
        if not isinstance(t, dict): continue
        tp = t.get("TaskPath") or "\\"
        exe = t.get("Exe") or ""
        cmd = (('"%s"' % exe if " " in exe and not exe.startswith('"') else exe) + (" " + t["Args"] if t.get("Args") else "")).strip()
        is_ms = tp.lower().startswith("\\microsoft\\")
        items.append({"type": "Tarea", "label": "Tarea", "loc": tp, "name": t.get("TaskName", ""), "cmd": cmd,
                      "susp": is_suspicious_cmd(cmd), "orphan": orphan_state(cmd) if exe else "unknown",
                      "tn": tp + (t.get("TaskName") or ""), "enabled": str(t.get("State") or "").lower() != "disabled",
                      "is_ms": is_ms, "sa": None})
    return items

def scan_startup():
    items = []
    for hive, path, label, sa in RUN_SOURCES:
        items += scan_run_key(hive, path, label, sa)
    items += scan_startup_folders()
    items += scan_tasks()
    return items


def _startup_backup_path(backup_dir, action):
    return os.path.join(backup_dir, "startup_%s_%s.json" % (stamp(), action))

def startup_set_enabled(items, enable, backup_dir=BACKUP_DIR):
    """Activa/desactiva (StartupApproved o schtasks). Guarda copia ANTES. Devuelve (resultados, copia)."""
    bk = {"kind": "startup", "action": "enable" if enable else "disable", "when": stamp(), "items": []}
    path = _startup_backup_path(backup_dir, bk["action"])
    for x in items:
        if x["type"] in ("Run", "Carpeta") and x.get("sa"):
            bk["items"].append({"type": x["type"], "name": x["name"], "sa_snap": reg_snapshot(x["sa"][0], x["sa"][1], x["name"])})
        elif x["type"] == "Tarea":
            bk["items"].append({"type": "Tarea", "name": x["name"], "tn": x["tn"], "prev_enabled": x.get("enabled", True)})
    write_json(path, bk)
    results = []
    for x in items:
        try:
            if x["type"] == "RunOnce" or (x["type"] in ("Run", "Carpeta") and not x.get("sa")):
                results.append((x["name"], False, tr("RunOnce no tiene interruptor de activar/desactivar en Windows: solo se puede eliminar.")))
            elif x["type"] in ("Run", "Carpeta"):
                reg_set(x["sa"][0], x["sa"][1], x["name"], "REG_BINARY", _sa_blob(enable))
                results.append((x["name"], True, ""))
            elif x["type"] == "Tarea":
                rc, out, err = run_ex(["schtasks", "/Change", "/TN", x["tn"], "/ENABLE" if enable else "/DISABLE"], timeout=30)
                results.append((x["name"], rc == 0, "" if rc == 0 else (err.strip() or out.strip() or fmt("código de salida %s", (rc,)))[-200:]))
            log("STARTUP %s %s %s -> %s" % (bk["action"], x["type"], x["name"], results[-1][1]))
        except Exception as e:
            results.append((x["name"], False, str(e)))
    return results, path

def startup_delete(items, backup_dir=BACKUP_DIR):
    """Elimina entradas Run/RunOnce (copia exacta con tipo y dato), mueve accesos de la carpeta Inicio a la copia
    y DESACTIVA (no borra) tareas. Devuelve (resultados, copia)."""
    st = stamp()
    bk = {"kind": "startup", "action": "delete", "when": st, "items": []}
    path = os.path.join(backup_dir, "startup_%s_delete.json" % st)
    files_dir = os.path.join(backup_dir, "startup_files_%s" % st)
    for x in items:
        if x["type"] in ("Run", "RunOnce"):
            bk["items"].append({"type": x["type"], "name": x["name"], "snap": reg_snapshot(x["hive"], x["regpath"], x["name"]),
                                "sa_snap": reg_snapshot(x["sa"][0], x["sa"][1], x["name"]) if x.get("sa") else None})
        elif x["type"] == "Carpeta":
            bk["items"].append({"type": "Carpeta", "name": x["name"], "file": x["file"],
                                "moved_to": os.path.join(files_dir, x["name"]),
                                "sa_snap": reg_snapshot(x["sa"][0], x["sa"][1], x["name"]) if x.get("sa") else None})
        elif x["type"] == "Tarea":
            bk["items"].append({"type": "Tarea", "name": x["name"], "tn": x["tn"], "prev_enabled": x.get("enabled", True)})
    write_json(path, bk)
    results = []
    for x in items:
        try:
            if x["type"] in ("Run", "RunOnce"):
                reg_delete_value(x["hive"], x["regpath"], x["name"]); results.append((x["name"], True, ""))
            elif x["type"] == "Carpeta":
                os.makedirs(files_dir, exist_ok=True)
                shutil.move(x["file"], os.path.join(files_dir, x["name"])); results.append((x["name"], True, ""))
            elif x["type"] == "Tarea":
                rc, out, err = run_ex(["schtasks", "/Change", "/TN", x["tn"], "/DISABLE"], timeout=30)
                results.append((x["name"], rc == 0, "" if rc == 0 else (err.strip() or out.strip() or fmt("código de salida %s", (rc,)))[-200:]))
            log("STARTUP delete %s %s -> %s" % (x["type"], x["name"], results[-1][1]))
        except Exception as e:
            results.append((x["name"], False, str(e)))
    return results, path

def list_startup_backups(backup_dir=BACKUP_DIR):
    res = []
    try:
        for fn in sorted(os.listdir(backup_dir), reverse=True):
            if fn.startswith("startup_") and fn.endswith(".json"):
                d = read_json(os.path.join(backup_dir, fn), {}) or {}
                if d.get("kind") == "startup":
                    res.append((os.path.join(backup_dir, fn), d))
    except Exception: pass
    return res

def startup_restore(path):
    """Restaura una copia de arranque (valores con su tipo original, StartupApproved, tareas, accesos movidos)."""
    bk = read_json(path, {}) or {}
    results = []
    for it in reversed(bk.get("items", [])):
        try:
            if it.get("snap"): reg_restore(it["snap"])
            if it["type"] == "Carpeta" and it.get("moved_to") and os.path.exists(it["moved_to"]) and not os.path.exists(it["file"]):
                shutil.move(it["moved_to"], it["file"])
            if it.get("sa_snap"): reg_restore(it["sa_snap"])
            if it["type"] == "Tarea":
                rc, out, err = run_ex(["schtasks", "/Change", "/TN", it["tn"], "/ENABLE" if it.get("prev_enabled", True) else "/DISABLE"], timeout=30)
                if rc != 0: raise RuntimeError((err.strip() or out.strip() or fmt("código de salida %s", (rc,)))[-200:])
            results.append((it["name"], True, ""))
        except Exception as e:
            results.append((it.get("name", "?"), False, str(e)))
    log("STARTUP restore %s -> %s" % (path, results))
    return results


# ======================= PRIVACIDAD (copia al aplicar, restauración exacta al revertir) =======================
PRIV_STATE_FILE = os.path.join(BACKUP_DIR, "privacy_state.json")

def privacy_status(tweaks=PRIVACY_TWEAKS, state_file=PRIV_STATE_FILE):
    state = read_json(state_file, {}) or {}
    res = {}
    for tw in tweaks:
        if tw["id"] in state:
            res[tw["id"]] = ("applied", state[tw["id"]].get("when", ""))
        else:
            private = all(reg_read(hv, p, n) == off for hv, p, n, kind, on, off in tw.get("reg", []))
            res[tw["id"]] = ("private" if private and tw.get("reg") else "default", "")
    return res

def privacy_apply(ids, tweaks=PRIVACY_TWEAKS, state_file=PRIV_STATE_FILE, backup_dir=BACKUP_DIR, do_services=True):
    """Aplica los ajustes elegidos. La PRIMERA vez guarda el estado original de cada valor y servicio."""
    state = read_json(state_file, {}) or {}
    chosen = [tw for tw in tweaks if tw["id"] in ids]
    for tw in chosen:
        if tw["id"] not in state:
            state[tw["id"]] = {"when": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
                               "reg": [reg_snapshot(hv, p, n) for hv, p, n, kind, on, off in tw.get("reg", [])],
                               "svc": [service_snapshot(s) for s in tw.get("svc", [])] if do_services else []}
    write_json(state_file, state)
    write_json(os.path.join(backup_dir, "privacy_%s.json" % stamp()), {"kind": "privacy", "state": state})
    nreg, nsvc, fails = 0, 0, []
    for tw in chosen:
        for hv, p, n, kind, on, off in tw.get("reg", []):
            try: reg_write_kind(hv, p, n, kind, off); nreg += 1
            except Exception as e: fails.append("%s (%s)" % (n, e)); log("reg fail %s: %s" % (n, e))
        if do_services:
            for sv in tw.get("svc", []):
                if not service_exists(sv): continue
                ok, det = service_disable(sv)
                if ok: nsvc += 1
                else: fails.append("%s (%s)" % (sv, det))
    return nreg, nsvc, fails

def privacy_revert(ids, tweaks=PRIVACY_TWEAKS, state_file=PRIV_STATE_FILE, do_services=True):
    """Restaura EXACTAMENTE lo que había antes de aplicar. Sin copia → no se toca (se informa)."""
    state = read_json(state_file, {}) or {}
    nreg, nsvc, fails, nocopy = 0, 0, [], []
    for tw in tweaks:
        if tw["id"] not in ids: continue
        s = state.get(tw["id"])
        if not s: nocopy.append(tw["name"]); continue
        ok_all = True
        for snap in s.get("reg", []):
            try: reg_restore(snap); nreg += 1
            except Exception as e: ok_all = False; fails.append("%s (%s)" % (snap.get("name"), e))
        if do_services:
            for snap in s.get("svc", []):
                if not snap.get("exists"): continue
                ok, mode = service_restore(snap)
                if ok: nsvc += 1
                else: ok_all = False; fails.append("%s (%s)" % (snap["name"], mode))
        if ok_all: state.pop(tw["id"], None)
    write_json(state_file, state)
    return nreg, nsvc, fails, nocopy


# ======================= RED (conexiones) =======================
PROXYWARE_NET_PATTERNS = ["honeygain", "packetstream", "peer2profit", "earnapp", "traffmonetizer", "repocket",
                          "pawns.app", "packetshare", "netnut", "infatica", "getgrass", "nodepay", "bitping", "mystnodes"]
PROXY_HOST_PATTERNS = ["proxy", "socks", "residential", "smartproxy", "decodo", "iproyal", "oxylabs", "brightdata",
                       "luminati", "webshare", "shifter", "rayobyte", "asocks", "922proxy", "ip2world"]
KNOWN_ORGS = {"amazonaws": "Amazon AWS", "googleusercontent": "Google", "1e100": "Google",
              "microsoft": "Microsoft", "azure": "Microsoft Azure", "akamai": "Akamai (CDN)",
              "cloudflare": "Cloudflare", "fastly": "Fastly (CDN)", "facebook": "Meta",
              "fbcdn": "Meta", "apple": "Apple", "icloud": "Apple", "cloudfront": "Amazon CloudFront",
              "gvt1": "Google", "whatsapp": "WhatsApp", "netflix": "Netflix", "spotify": "Spotify"}
# Programas que abren MUCHAS conexiones por diseño: no se marcan por cantidad.
NET_COUNT_EXCLUDE = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "opera_gx.exe", "vivaldi.exe",
                     "iexplore.exe", "msedgewebview2.exe", "tor.exe", "svchost.exe", "system", "steam.exe", "steamwebhelper.exe",
                     "steamservice.exe", "qbittorrent.exe", "utorrent.exe", "bittorrent.exe", "transmission-qt.exe",
                     "deluge.exe", "biglybt.exe", "tixati.exe", "onedrive.exe", "dropbox.exe", "googledrivefs.exe",
                     "teams.exe", "ms-teams.exe", "discord.exe", "spotify.exe", "epicgameslauncher.exe", "battle.net.exe",
                     "lsass.exe", "wininit.exe", "services.exe", "msmpeng.exe", "code.exe", "node.exe", "electron.exe"}
NET_THRESHOLD = 25

def classify_host(host):
    """('proxyware'|'proxy'|'vpn'|'', organización)"""
    low = (host or "").lower()
    org = ""
    for key, name in KNOWN_ORGS.items():
        if key in low: org = name; break
    if not org and low:
        parts = low.split(".")
        if len(parts) >= 3 and parts[-2] in ("com", "net", "org", "co", "gov", "edu", "ac", "gob", "ne", "or"): org = parts[-3]
        else: org = parts[-2] if len(parts) >= 2 else low
    if any(p in low for p in PROXYWARE_NET_PATTERNS): kind = "proxyware"
    elif any(p in low for p in PROXY_HOST_PATTERNS): kind = "proxy"
    elif "vpn" in low: kind = "vpn"
    else: kind = ""
    return kind, org

def flag_connections(conns, threshold=NET_THRESHOLD):
    """Cuenta conexiones POR PID (no por nombre). Rojo = muchas (salvo exclusiones) o red de proxyware conocida."""
    counts = {}
    for c in conns: counts[c["pid"]] = counts.get(c["pid"], 0) + 1
    for c in conns:
        n = counts.get(c["pid"], 0)
        many = n >= threshold and (c.get("proc") or "").lower() not in NET_COUNT_EXCLUDE
        c["count"] = n; c["many"] = many
        c["flag"] = many or c.get("kind") == "proxyware"
        c["info"] = (not c["flag"]) and c.get("kind") in ("proxy", "vpn")
    return conns

def scan_network(resolve=True):
    rows = psjson("Get-NetTCPConnection -State Established | Select-Object LocalPort,RemoteAddress,RemotePort,OwningProcess")
    procs = {p["pid"]: p for p in list_processes_full()}
    conns = []
    for r in rows:
        if not isinstance(r, dict): continue
        ra = r.get("RemoteAddress", "") or ""
        if ra.startswith("127.") or ra in ("::1", "0.0.0.0", "::"): continue
        pid = str(r.get("OwningProcess"))
        conns.append({"proc": procs.get(pid, {}).get("name") or "?", "pid": pid, "ip": ra,
                      "remote": ("[%s]:%s" if ":" in ra else "%s:%s") % (ra, r.get("RemotePort")), "lport": r.get("LocalPort")})
    names = resolve_many(list(dict.fromkeys(c["ip"] for c in conns)), deadline=4.0) if resolve else {}
    for c in conns:
        host = (names.get(c["ip"]) or "").lower()
        kind, org = classify_host(host)
        c["host"] = host; c["org"] = org; c["kind"] = kind
    return flag_connections(conns)


# ======================= INTEGRIDAD =======================
KNOWN_DNS = {"1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare", "8.8.8.8": "Google", "8.8.4.4": "Google",
             "9.9.9.9": "Quad9", "149.112.112.112": "Quad9", "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
             "94.140.14.14": "AdGuard", "94.140.15.15": "AdGuard", "2606:4700:4700::1111": "Cloudflare",
             "2001:4860:4860::8888": "Google"}

def _is_private(ip):
    return ip.startswith(("10.", "192.168.", "169.254.", "fe80", "fd", "fc")) or bool(re.match(r"^172\.(1[6-9]|2\d|3[01])\.", ip))

def read_dns_servers():
    rows = psjson("Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses -and $_.InterfaceAlias -notlike 'Loopback*' } | "
                  "Select-Object InterfaceAlias,AddressFamily,ServerAddresses")
    res = []
    for r in rows:
        if not isinstance(r, dict): continue
        sv = r.get("ServerAddresses") or []
        if isinstance(sv, str): sv = [sv]
        fam = r.get("AddressFamily")
        res.append({"alias": r.get("InterfaceAlias", "?"), "family": "IPv6" if str(fam) in ("23", "IPv6") else "IPv4", "servers": list(sv)})
    return res

def scan_integrity(hosts_path=HOSTS_FILE):
    res = {"hosts": [], "ioc_hits": [], "optishield_lines": 0, "proxy_enabled": False, "proxy_server": "", "dns": []}
    try:
        text, _, _ = hosts_read(hosts_path)
        for ln in text.splitlines():
            s = ln.strip()
            if not s or s.startswith("#"): continue
            res["hosts"].append(s)
            if "# OptiShield" in s: res["optishield_lines"] += 1
            parts = s.split("#", 1)[0].split()
            if len(parts) >= 2 and parts[0] not in ("0.0.0.0", "127.0.0.1", "::", "::1"):
                for d in IOC_DOMAINS:
                    if any(h.lower() == d or h.lower().endswith("." + d) for h in parts[1:]):
                        res["ioc_hits"].append(s); break
    except Exception as e:
        log("hosts read: %s" % e)
    pe = reg_read("HKCU", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "ProxyEnable")
    res["proxy_enabled"] = bool(pe)
    res["proxy_server"] = str(reg_read("HKCU", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "ProxyServer") or "")
    res["dns"] = read_dns_servers()
    return res

def defender_status():
    d = psjson("Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge")
    res = {"av": None, "rt": None, "age": None, "others": []}
    if d and isinstance(d[0], dict):
        s = d[0]; res.update({"av": s.get("AntivirusEnabled"), "rt": s.get("RealTimeProtectionEnabled"), "age": s.get("AntivirusSignatureAge")})
    try:
        for a in psjson("Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | Select-Object displayName"):
            n = (a or {}).get("displayName")
            if n and "defender" not in n.lower() and n not in res["others"]: res["others"].append(n)
    except Exception: pass
    return res


# ======================= INTERFAZ =======================
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

BG="#0e1a1c"; BG2="#12282b"; CARD="#0a1416"; LINE="#1c3b3e"; TEAL="#09b1ba"; TEAL2="#33d1a0"; INK="#eafcff"; MUT="#8fc9cd"; RED="#ef4444"; AMBER="#e0a72a"; GRAY="#7d8f91"

class OptiShield(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("%s %s · %s" % (APP, VERSION, SIGNATURE))
        self.geometry("1180x740"); self.minsize(980, 640); self.configure(bg=BG)
        try:
            for b in resource_dirs():
                ico = os.path.join(b, "icon.ico")
                if os.path.exists(ico): self.iconbitmap(ico); break
        except Exception: pass
        self._q = queue.Queue(); self._busy = False; self._dyn = {}
        self._dlog_items = []
        self._prox_data = []; self._net_data = []; self._start_items = []; self._integ = None; self._def = None
        self._iot_list = []; self._tv_pkgs = []
        self._style()
        self._tab_titles = []
        self._header()
        self.nb = ttk.Notebook(self); self.nb.pack(fill="both", expand=True, padx=12, pady=(0, 10))
        self.tab_dash = self._tab("🏠 Panel")
        self.tab_prox = self._tab("🕵 Proxyware")
        self.tab_net  = self._tab("🌐 Red")
        self.tab_iot  = self._tab("🏘 Red local")
        self.tab_tv   = self._tab("📺 TV")
        self.tab_priv = self._tab("🔒 Privacidad")
        self.tab_start= self._tab("🧹 Arranque")
        self.tab_integ= self._tab("🛡 Integridad")
        self.tab_help = self._tab("💬 Apoyo")
        self._status_bar()
        self._build_dashboard(); self._build_proxyware(); self._build_network(); self._build_iot(); self._build_tv()
        self._build_privacy(); self._build_startup(); self._build_integrity(); self._build_help()
        self._snapshot_i18n()
        self._apply_lang()
        self._ready_status()
        self.after(80, self._poll)

    # ---------- hilos: el trabajo va en segundo plano; tkinter SOLO desde el hilo principal ----------
    def _poll(self):
        try:
            while True:
                fn = self._q.get_nowait()
                try: fn()
                except Exception as e: log("ui callback: %s" % e)
        except queue.Empty: pass
        self.after(80, self._poll)

    def _post(self, fn):
        """Llamable desde cualquier hilo: encola fn para el hilo principal."""
        self._q.put(fn)

    def _runbg(self, fn, done, busy_key=None):
        if busy_key: self._status(busy_key)
        def wrap():
            try: r = fn()
            except Exception as e:
                r = e; log("error: %r" % e)
            self._q.put(lambda: done(r))
        threading.Thread(target=wrap, daemon=True).start()

    # ---------- i18n ----------
    def _snapshot_i18n(self):
        self._orig_text = []; self._orig_head = []
        def walk(w):
            if w not in self._dyn:
                try:
                    t = w.cget("text")
                    if isinstance(t, str) and t.strip(): self._orig_text.append((w, t))
                except Exception: pass
            if isinstance(w, ttk.Treeview):
                for c in ("#0",) + tuple(w.cget("columns") or ()):
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
        for i, es in enumerate(self._tab_titles):
            try: self.nb.tab(i, text=tr(es))
            except Exception: pass
        for w, (key, args) in list(self._dyn.items()):
            try: w.configure(text=fmt(key, args))
            except Exception: pass
        self._render_dlog()
        self.refresh_proxyware(self._prox_data); self.refresh_network(self._net_data)
        self.refresh_startup(self._start_items); self._render_iot(); self._render_tv()
        if self._integ is not None: self.refresh_integrity(self._integ)
        self._refresh_privacy_status()
        self._render_defender_card()

    def set_lang(self, code):
        global LANG
        if code not in ("es", "en") or code == LANG: return
        LANG = code; cfg_set("lang", code)
        self._apply_lang(); self._update_lang_buttons()

    def _update_lang_buttons(self):
        for code, btn in getattr(self, "_lang_btns", {}).items():
            on = (code == LANG)
            btn.config(bg=(TEAL if on else BG2), fg=("#04210f" if on else MUT))

    def _set_text(self, widget, key, *args, **kw):
        self._dyn[widget] = (key, args)
        widget.configure(text=fmt(key, args), **kw)

    # mensajes traducidos
    def _info(self, key, *a): messagebox.showinfo(APP, fmt(key, a), parent=self)
    def _warn(self, key, *a): messagebox.showwarning(APP, fmt(key, a), parent=self)
    def _err(self, key, *a): messagebox.showerror(APP, fmt(key, a), parent=self)
    def _ask(self, key, *a): return messagebox.askyesno(APP, fmt(key, a), parent=self)

    def _style(self):
        s = ttk.Style(self); s.theme_use("clam")
        s.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(2, 4, 2, 0))
        s.configure("TNotebook.Tab", background=BG2, foreground=MUT, padding=(11, 7), font=("Segoe UI", 10, "bold"))
        s.map("TNotebook.Tab", background=[("selected", BG)], foreground=[("selected", INK)])
        s.configure("TFrame", background=BG)
        s.configure("TLabel", background=BG, foreground=INK, font=("Segoe UI", 10))
        s.configure("Mut.TLabel", background=BG, foreground=MUT, font=("Segoe UI", 9))
        s.configure("H.TLabel", background=BG, foreground=INK, font=("Segoe UI", 13, "bold"))
        s.configure("Teal.TButton", background=TEAL, foreground="#001", font=("Segoe UI", 10, "bold"), borderwidth=0, padding=(12, 7))
        s.map("Teal.TButton", background=[("active", TEAL2)])
        s.configure("Ghost.TButton", background=BG2, foreground=INK, borderwidth=1, padding=(10, 6))
        s.map("Ghost.TButton", background=[("active", LINE)])
        s.configure("Treeview", background=CARD, fieldbackground=CARD, foreground=INK, borderwidth=0, rowheight=24, font=("Segoe UI", 9))
        s.configure("Treeview.Heading", background=BG2, foreground=MUT, font=("Segoe UI", 9, "bold"))
        s.map("Treeview", background=[("selected", LINE)])
        s.configure("TCheckbutton", background=CARD, foreground=INK, font=("Segoe UI", 10))
        s.map("TCheckbutton", background=[("active", CARD)])
        s.configure("Bg.TCheckbutton", background=BG, foreground=INK, font=("Segoe UI", 9))
        s.configure("Vertical.TScrollbar", background=BG2, troughcolor=CARD, bordercolor=LINE, arrowcolor=MUT, lightcolor=BG2, darkcolor=BG2)
        s.map("Vertical.TScrollbar", background=[("active", LINE)])
        s.map("Bg.TCheckbutton", background=[("active", BG)])

    def _header(self):
        h = tk.Frame(self, bg=BG); h.pack(fill="x", padx=14, pady=(12, 8))
        tk.Label(h, text="🛡️ OptiShield", bg=BG, fg=INK, font=("Segoe UI", 18, "bold")).pack(side="left")
        tk.Label(h, text="  Escudo de privacidad y seguridad · Enmanuel Gil · OptiSuite", bg=BG, fg=MUT, font=("Segoe UI", 10)).pack(side="left")
        tk.Label(h, text="ADMIN" if is_admin() else "SIN ADMIN", bg=(BG2 if is_admin() else "#3a2323"), fg=(TEAL2 if is_admin() else "#ffb4b4"),
                 font=("Segoe UI", 9, "bold"), padx=10, pady=3).pack(side="right")
        lang = tk.Frame(h, bg=BG); lang.pack(side="right", padx=(0, 12))
        self._lang_btns = {}
        for code, label in (("es", "ES"), ("en", "EN")):
            b = tk.Button(lang, text=label, bd=0, relief="flat", padx=9, pady=3, cursor="hand2",
                          font=("Segoe UI", 9, "bold"), activebackground=TEAL2, command=lambda c=code: self.set_lang(c))
            b.pack(side="left", padx=1); self._lang_btns[code] = b
        self._update_lang_buttons()

    def _tab(self, title):
        self._tab_titles.append(title)
        f = ttk.Frame(self.nb); self.nb.add(f, text=title); return f

    def _status_bar(self):
        self._sb = tk.Label(self, text="", bg=CARD, fg=MUT, anchor="w", font=("Segoe UI", 9), padx=12, pady=5)
        self._sb.pack(fill="x", side="bottom", before=self.nb)
        self._dyn[self._sb] = ("", ())

    def _status(self, key, *args):
        self._set_text(self._sb, key, *args)

    def _ready_status(self):
        if is_admin(): self._status("Listo. Modo solo-escaneo: nada se cambia sin tu confirmación.")
        else: self._status("%s%s", L("Listo. Modo solo-escaneo: nada se cambia sin tu confirmación."), L("  ⚠ Ejecuta como administrador para aplicar cambios."))

    def _tree(self, parent, columns, height, selectmode="browse", pady=10):
        """Treeview con barra de desplazamiento vertical."""
        fr = tk.Frame(parent, bg=BG); fr.pack(fill="both", expand=True, padx=16, pady=pady)
        t = ttk.Treeview(fr, columns=columns, show="tree headings", selectmode=selectmode, height=height)
        sb = ttk.Scrollbar(fr, orient="vertical", command=t.yview); t.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y"); t.pack(side="left", fill="both", expand=True)
        return t

    def _text(self, parent, **kw):
        """Text con barra de desplazamiento vertical."""
        pady = kw.pop("pady_out", 10)
        fr = tk.Frame(parent, bg=BG); fr.pack(fill="both", expand=True, padx=16, pady=pady)
        t = tk.Text(fr, bd=0, wrap="word", padx=10, pady=8, **kw)
        sb = ttk.Scrollbar(fr, orient="vertical", command=t.yview); t.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y"); t.pack(side="left", fill="both", expand=True)
        return t

    def _mut(self, parent, key, wrap=1100):
        return ttk.Label(parent, text=key, style="Mut.TLabel", wraplength=wrap, justify="left")

    # ---------- Panel ----------
    def _build_dashboard(self):
        f = self.tab_dash
        ttk.Label(f, text="Estado general del sistema", style="H.TLabel").pack(anchor="w", padx=16, pady=(16, 4))
        self._mut(f, "Pulsa «Analizar todo» para un chequeo completo. Nada se cambia sin tu confirmación.").pack(anchor="w", padx=16)
        self.cards = tk.Frame(f, bg=BG); self.cards.pack(fill="x", padx=16, pady=14)
        self.card_widgets = {}
        for i, (k, t) in enumerate([("prox", "🕵 Proxyware"), ("net", "🌐 Red"), ("start", "🧹 Arranque"), ("integ", "🛡 Integridad"), ("def", "🦠 Defender")]):
            c = tk.Frame(self.cards, bg=CARD, highlightbackground=LINE, highlightthickness=1)
            c.grid(row=0, column=i, padx=6, ipadx=10, ipady=10, sticky="nsew"); self.cards.columnconfigure(i, weight=1)
            tk.Label(c, text=t, bg=CARD, fg=INK, font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=10, pady=(8, 2))
            lbl = tk.Label(c, text="—", bg=CARD, fg=MUT, font=("Segoe UI", 15, "bold")); lbl.pack(anchor="w", padx=10, pady=(0, 8))
            self._dyn[lbl] = ("—", ())
            self.card_widgets[k] = lbl
        actionbar = tk.Frame(f, bg=BG); actionbar.pack(fill="x", padx=16, pady=6)
        ttk.Button(actionbar, text="🔎 Analizar todo", style="Teal.TButton", command=self.scan_all).pack(side="left")
        self.watch_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(actionbar, text="👁 Vigilancia (revisa proxyware cada 15 min)", variable=self.watch_var,
                        style="Bg.TCheckbutton", command=self.toggle_watch).pack(side="left", padx=16)
        self.def_var = tk.BooleanVar(value=bool(cfg_get("defender_intentional", False)))
        ttk.Checkbutton(actionbar, text="Defender: lo desactivé a propósito", variable=self.def_var,
                        style="Bg.TCheckbutton", command=self._toggle_def_intentional).pack(side="left", padx=4)
        self.dash_log = self._text(f, bg=CARD, fg=MUT, height=12, font=("Consolas", 9), pady_out=(6, 16))
        self._watch_job = None; self._watch_last = set()

    def _dlog(self, key, *args):
        self._dlog_items.append((key, args))
        self.dash_log.insert("end", fmt(key, args) + "\n"); self.dash_log.see("end")

    def _render_dlog(self):
        self.dash_log.delete("1.0", "end")
        for k, a in self._dlog_items: self.dash_log.insert("end", fmt(k, a) + "\n")
        self.dash_log.see("end")

    def _allowed(self):
        return set(cfg_get("allowed_findings", []) or [])

    def scan_all(self):
        if self._busy: return
        self._busy = True
        self._dlog_items = []; self._render_dlog()
        self._dlog("Analizando…"); self._status("Analizando el sistema…")
        parts = [("prox", "Proxyware", scan_proxyware), ("net", "Red", scan_network), ("start", "Arranque", scan_startup),
                 ("integ", "Integridad", scan_integrity), ("def", "Defender", defender_status)]
        def work():
            res, errs = {}, {}
            for key, label, fn in parts:
                try: res[key] = fn()
                except Exception as e:
                    errs[key] = (label, "%s: %s" % (type(e).__name__, e)); log("scan %s: %r" % (key, e))
            return res, errs
        def done(r):
            self._busy = False
            if isinstance(r, Exception):
                self._dlog("Error: %s", str(r)); self._status("Error: %s", str(r)); return
            res, errs = r
            allowed = self._allowed()
            if "prox" in res:
                px = res["prox"]; self._prox_data = px
                probs = [x for x in px if is_problem(x, allowed)]
                self._setcard("prox", len(probs), len(px))
                self._dlog("Proxyware que comparte tu conexión: %d (de %d detecciones)", len(probs), len(px))
                for x in px:
                    self._dlog("   • %s [%s] — %s", _Lazy(finding_name, x), L(RISK_LABEL.get(x["risk"], x["risk"])),
                               L(V_ALLOWED if x["id"] in allowed else x["verdict"]))
                self.refresh_proxyware(px)
            if "net" in res:
                self._net_data = res["net"]; nf = len([x for x in res["net"] if x.get("flag")])
                self._setcard("net", nf, None); self._dlog("Conexiones marcadas en rojo (posible nodo): %d", nf)
                self.refresh_network(res["net"])
            if "start" in res:
                self._start_items = res["start"]
                ns = len([x for x in res["start"] if x.get("susp") and x.get("enabled")])
                no = len([x for x in res["start"] if x.get("orphan") == "orphan" and not x.get("is_ms")])
                self._setcard("start", ns, None); self._dlog("Arranque sospechoso: %d · obsoleto: %d", ns, no)
                self.refresh_startup(res["start"])
            if "integ" in res:
                self._integ = res["integ"]; ioc = len(res["integ"]["ioc_hits"])
                self._setcard("integ", ioc, None); self._dlog("IOCs en hosts: %d", ioc)
                self.refresh_integrity(res["integ"])
            if "def" in res:
                self._def = res["def"]; self._render_defender_card(log_it=True)
            for key, (label, msg) in errs.items():
                self._set_text(self.card_widgets[key], "Error", fg=RED)
                self._dlog("⚠ La parte «%s» falló: %s", L(label), msg)
            self._dlog("\n✔ Análisis terminado. Revisa cada pestaña para actuar.")
            if errs: self._status("Análisis terminado con errores en: %s", ", ".join(tr(l) for l, _ in errs.values()))
            else: self._status("Análisis terminado.")
        self._runbg(work, done)

    def _setcard(self, k, bad, total):
        lbl = self.card_widgets[k]
        if total is not None and total > 0: self._set_text(lbl, "%d/%d", bad, total, fg=(TEAL2 if bad == 0 else RED))
        elif bad == 0: self._set_text(lbl, "✔ 0", fg=TEAL2)
        else: self._set_text(lbl, "%d", bad, fg=RED)

    def _toggle_def_intentional(self):
        cfg_set("defender_intentional", bool(self.def_var.get()))
        self._render_defender_card()

    def _render_defender_card(self, log_it=False):
        d = self._def
        if d is None: return
        lbl = self.card_widgets["def"]
        intentional = bool(self.def_var.get())
        if d.get("av"):
            self._set_text(lbl, "OK", fg=TEAL2)
            if log_it: self._dlog("Defender: encendido (antivirus=%s, tiempo real=%s)", L("Sí") if d.get("av") else L("No"), L("Sí") if d.get("rt") else L("No"))
        elif intentional:
            self._set_text(lbl, "Apagado (a propósito)", fg=GRAY)
            if log_it: self._dlog("Defender: apagado a propósito (marcado por ti). No cuenta como problema.")
        elif d.get("av") is None:
            self._set_text(lbl, "Desconocido", fg=AMBER)
            if log_it: self._dlog("Defender: no pude leer su estado (puede estar desinstalado o desactivado por directiva).")
        else:
            self._set_text(lbl, "Apagado", fg=AMBER)
            if log_it: self._dlog("Defender: apagado. Si usas otro antivirus o lo apagaste a propósito, márcalo en la casilla de arriba.")
        if log_it and d.get("others"): self._dlog("Antivirus registrado en Windows: %s", ", ".join(d["others"]))

    def toggle_watch(self):
        if self.watch_var.get():
            self._dlog("👁 Vigilancia ACTIVADA (cada 15 min). Ignora lo que marques como «Permitido».")
            self._watch_last = set(); self._watch_tick()
        else:
            if self._watch_job:
                try: self.after_cancel(self._watch_job)
                except Exception: pass
                self._watch_job = None
            self._dlog("👁 Vigilancia desactivada.")

    def _watch_tick(self):
        if not self.watch_var.get(): return
        allowed = self._allowed()
        def work():
            # chequeo ligero: procesos y servicios de las firmas de proxyware (sin sondeo de puertos ni DLLs)
            fs = scan_proxyware(include_ports=False, include_sdk=False)
            return sorted(set(finding_name(f) for f in fs if f.get("cat") == "proxyware" and f.get("running") and f["id"] not in allowed))
        def done(a):
            if isinstance(a, Exception): a = []
            new = set(a) - self._watch_last
            self._watch_last = set(a)
            if new:
                self.bell()
                self._dlog("⚠ VIGILANCIA: proxyware activo → %s", ", ".join(a))
                self._warn("OptiShield detectó proxyware activo:\n\n• %s\n\nVe a la pestaña Proxyware para neutralizarlo, o márcalo como «Permitido» si lo instalaste a propósito.", "\n• ".join(a))
            if self.watch_var.get(): self._watch_job = self.after(900000, self._watch_tick)
        self._runbg(work, done)

    # ---------- Anti-proxyware ----------
    def _build_proxyware(self):
        f = self.tab_prox
        top = tk.Frame(f, bg=BG); top.pack(fill="x", padx=16, pady=12)
        ttk.Label(top, text="Anti-proxyware / anti-botnet", style="H.TLabel").pack(side="left")
        ttk.Button(top, text="🔎 Escanear", style="Teal.TButton", command=self.scan_prox).pack(side="right")
        self._mut(f, "Proxyware = apps que COMPARTEN tu conexión a cambio de dinero (Honeygain, Pawns, EarnApp…) o SDK ocultos que hacen lo mismo. Los proxies/VPN de pago que TÚ usas (Decodo/Smartproxy, IPRoyal, Oxylabs…) salen como «informativo» y no se tocan. Si algo lo instalaste a propósito, márcalo como «Permitido». Ojo: el bloqueo por hosts no cubre subdominios ni el DNS seguro (DoH) del navegador; por eso OptiShield bloquea también el programa en el firewall cuando conoce su ruta.").pack(anchor="w", padx=16)
        self.prox_tree = self._tree(f, ("risk", "verd", "ev"), 12, "extended", 10)
        for c, t in (("#0", "Detección"), ("risk", "Riesgo"), ("verd", "Veredicto"), ("ev", "Evidencia")): self.prox_tree.heading(c, text=t)
        self.prox_tree.column("#0", width=280); self.prox_tree.column("risk", width=60); self.prox_tree.column("verd", width=300); self.prox_tree.column("ev", width=460)
        self.prox_tree.tag_configure("high", foreground=RED); self.prox_tree.tag_configure("medium", foreground=AMBER)
        self.prox_tree.tag_configure("info", foreground=MUT); self.prox_tree.tag_configure("allowed", foreground=TEAL2)
        bar = tk.Frame(f, bg=BG); bar.pack(fill="x", padx=16, pady=(0, 14))
        ttk.Button(bar, text="🛑 Neutralizar seleccionados", style="Ghost.TButton", command=self.neutralize_proxyware).pack(side="left")
        ttk.Button(bar, text="↩ Deshacer neutralización", style="Ghost.TButton", command=self.undo_neutralization).pack(side="left", padx=8)
        ttk.Button(bar, text="✕ Quitar permiso", style="Ghost.TButton", command=lambda: self.allow_selected(False)).pack(side="right")
        ttk.Button(bar, text="✓ Permitir (lo instalé a propósito)", style="Ghost.TButton", command=lambda: self.allow_selected(True)).pack(side="right", padx=8)

    def scan_prox(self):
        self._status("Escaneando…")
        def done(d):
            if isinstance(d, Exception): self._status("Error: %s", str(d)); return
            self._prox_data = d; self.refresh_proxyware(d); self._status("Hecho.")
        self._runbg(scan_proxyware, done)

    def refresh_proxyware(self, data):
        if isinstance(data, Exception) or not hasattr(self, "prox_tree"): return
        self.prox_tree.delete(*self.prox_tree.get_children())
        if not data:
            self.prox_tree.insert("", "end", iid="__none__", text=tr("✔ Sin proxyware detectado"), values=("", "", "")); return
        allowed = self._allowed()
        used = set()
        for x in data:
            iid = x["id"]
            while iid in used: iid += "_"
            used.add(iid)
            al = x["id"] in allowed
            tag = "allowed" if al else ("info" if x["risk"] == "info" else ("high" if x["risk"] == "high" else "medium"))
            self.prox_tree.insert("", "end", iid=iid, text=finding_name(x),
                                  values=(tr(RISK_LABEL.get(x["risk"], x["risk"])), tr(V_ALLOWED if al else x["verdict"]), finding_evidence(x, 220)),
                                  tags=(tag,))

    def _sel_findings(self):
        ids = [i.rstrip("_") for i in self.prox_tree.selection() if i != "__none__"]
        return [x for x in self._prox_data if x["id"] in ids]

    def allow_selected(self, add):
        sel = self._sel_findings()
        if not sel: self._info("Selecciona uno o varios elementos de la lista."); return
        al = self._allowed()
        for x in sel:
            if add: al.add(x["id"])
            else: al.discard(x["id"])
        cfg_set("allowed_findings", sorted(al))
        self.refresh_proxyware(self._prox_data)
        self._status("Permitidos: %d. Ya no cuentan como problema ni avisa la vigilancia." if add else "Permiso quitado: %d.", len(sel))
        probs = [x for x in self._prox_data if is_problem(x, al)]
        if self._prox_data: self._setcard("prox", len(probs), len(self._prox_data))

    def neutralize_proxyware(self):
        if not is_admin(): self._warn("Ejecuta OptiShield como administrador para neutralizar."); return
        sel = self._sel_findings()
        if not sel: self._info("Selecciona en la lista lo que quieras neutralizar."); return
        allowed = self._allowed()
        in_db = [x for x in sel if x.get("in_db")]
        not_db = [x for x in sel if not x.get("in_db")]
        info = [x for x in in_db if x.get("cat") != "proxyware" or x["id"] in allowed]
        if info and not self._ask("Esto NO es proxyware: es un servicio de proxy/VPN que usas, o algo que marcaste como permitido:\n\n• %s\n\n¿Neutralizarlo igualmente?",
                                  "\n• ".join(finding_name(x) for x in info)):
            in_db = [x for x in in_db if x not in info]
        expl = []
        for x in not_db:
            if x.get("cat", "").startswith("socks"):
                p = (x.get("procs") or [{}])[0]
                expl.append(fmt("• %s: es el programa «%s» (PID %s%s). Si no lo reconoces, ciérralo desde el Administrador de tareas y desinstálalo desde Configuración → Aplicaciones. Tor, Clash, v2rayN o «ssh -D» abren proxies así a propósito.",
                                (finding_name(x), p.get("name") or "?", p.get("pid") or "?", (", " + p["path"]) if p.get("path") else "")))
            else:
                expl.append(fmt("• %s: hay una DLL de proxyware cargada dentro de otra app. OptiShield no puede quitarla sin romper esa app: desinstala la extensión o programa que la trajo y reinicia la app.", (finding_name(x),)))
        if not in_db:
            if expl: messagebox.showinfo(APP, tr("Sobre lo que no está en la base de datos (no se hace nada automático):") + "\n\n" + "\n\n".join(expl), parent=self)
            return
        if not self._ask("Se hará, con copia de seguridad (se puede deshacer):\n• Bloquear en el firewall (salida) los programas encontrados\n• Detener SOLO esos procesos (por PID y ruta)\n• Desactivar sus servicios (guardando su modo de arranque)\n• Bloquear sus dominios en hosts\n\nNo se borra ningún archivo. ¿Continuar?"):
            return
        self._status("Trabajando…")
        def done(r):
            if isinstance(r, Exception): self._err("No se pudo completar: %s", str(r)); self._status("Error: %s", str(r)); return
            lines, path = r
            msg = tr("Resumen de la neutralización:") + "\n\n" + "\n".join(fmt(k, a) for k, a in lines)
            msg += "\n\n" + fmt("Copia guardada en: %s", (path,))
            if expl: msg += "\n\n" + tr("Sobre lo que no está en la base de datos (no se hace nada automático):") + "\n" + "\n".join(expl)
            messagebox.showinfo(APP, msg, parent=self)
            self._status("Hecho."); self.scan_prox()
        self._runbg(lambda: neutralize(in_db), done)

    def undo_neutralization(self):
        if not is_admin(): self._warn("Ejecuta OptiShield como administrador para neutralizar."); return
        path = last_neutralize_backup()
        if not path: self._info("No hay ninguna neutralización pendiente de deshacer."); return
        bk = read_json(path, {}) or {}
        if not self._ask("Se deshará la neutralización del %s:\n\n• %s\n\n(servicios a su modo original, reglas de firewall y líneas de hosts de esa vez). ¿Continuar?",
                         bk.get("when", "?"), "\n• ".join(i.get("name", "?") for i in bk.get("items", []))):
            return
        self._status("Trabajando…")
        def done(lines):
            if isinstance(lines, Exception): self._err("No se pudo completar: %s", str(lines)); return
            messagebox.showinfo(APP, tr("Resumen de deshacer:") + "\n\n" + "\n".join(fmt(k, a) for k, a in lines), parent=self)
            self._status("Hecho."); self.scan_prox()
        self._runbg(lambda: undo_neutralize(path), done)

    # ---------- Red ----------
    def _build_network(self):
        f = self.tab_net
        top = tk.Frame(f, bg=BG); top.pack(fill="x", padx=16, pady=12)
        ttk.Label(top, text="Conexiones de red activas", style="H.TLabel").pack(side="left")
        ttk.Button(top, text="🔎 Escanear", style="Teal.TButton", command=self.scan_net).pack(side="right")
        self._mut(f, "En rojo = un programa (contado por PID) con muchas conexiones salientes, excepto navegadores/Steam/torrent/servicios de Windows, o destino de una red de proxyware conocida. En ámbar = destino que parece un proxy o VPN (normal si usas uno). La columna Organización sale del DNS inverso: solo consultas DNS normales, sin enviar nada a terceros.").pack(anchor="w", padx=16)
        self.net_tree = self._tree(f, ("remote", "org", "pid", "note"), 16, "browse", 10)
        for c, t in (("#0", "Proceso"), ("remote", "Destino"), ("org", "Organización (DNS inverso)"), ("pid", "PID"), ("note", "Nota")): self.net_tree.heading(c, text=t)
        self.net_tree.column("#0", width=190); self.net_tree.column("remote", width=210); self.net_tree.column("org", width=330)
        self.net_tree.column("pid", width=60); self.net_tree.column("note", width=220)
        self.net_tree.tag_configure("flag", foreground=RED); self.net_tree.tag_configure("info", foreground=AMBER)

    def scan_net(self):
        self._status("Escaneando…")
        def done(d):
            if isinstance(d, Exception): self._status("Error: %s", str(d)); return
            self._net_data = d; self.refresh_network(d); self._status("Hecho.")
        self._runbg(scan_network, done)

    def refresh_network(self, data):
        if isinstance(data, Exception) or not hasattr(self, "net_tree"): return
        self.net_tree.delete(*self.net_tree.get_children())
        for x in sorted(data or [], key=lambda c: (not c.get("flag"), not c.get("info"), (c.get("proc") or "").lower())):
            org = x.get("org") or tr("(desconocida)")
            host = x.get("host") or tr("(sin DNS inverso)")
            notes = []
            if x.get("many"): notes.append(fmt("muchas conexiones (%d)", (x.get("count", 0),)))
            k = x.get("kind")
            if k == "proxyware": notes.append(tr("red de proxyware"))
            elif k == "proxy": notes.append(tr("proxy (normal si usas uno)"))
            elif k == "vpn": notes.append(tr("VPN"))
            tag = "flag" if x.get("flag") else ("info" if x.get("info") else "")
            self.net_tree.insert("", "end", text=x["proc"], values=(x["remote"], "%s · %s" % (org, host), x["pid"], ", ".join(notes)),
                                 tags=(tag,) if tag else ())

    # ---------- Red local (IoT / Badbox) ----------
    def _build_iot(self):
        f = self.tab_iot
        top = tk.Frame(f, bg=BG); top.pack(fill="x", padx=16, pady=12)
        ttk.Label(top, text="Red local — dispositivos y IoT (Badbox)", style="H.TLabel").pack(side="left")
        ttk.Button(top, text="🔎 Escaneo rápido (ARP)", style="Teal.TButton", command=self.quick_scan).pack(side="right")
        ttk.Button(top, text="🔬 Escaneo profundo", style="Ghost.TButton", command=self.deep_scan).pack(side="right", padx=8)
        self._mut(f, "Rápido = dispositivos ya vistos (tabla ARP). Profundo = barrido activo de TODA tu subred (ping .1-.254 + fabricante por MAC), tarda ~30-60 s. En rojo = puertos de depuración abiertos (5555 ADB, Telnet, FTP…) en un equipo NO marcado de confianza — típico de TV-box/IoT comprometidos por Badbox. Selecciona un equipo y pulsa «Detalles»; marca tus propios equipos como «de confianza» para que dejen de salir en rojo.").pack(anchor="w", padx=16)
        self.iot_tree = self._tree(f, ("mac", "vendor", "host", "open"), 14, "extended", (10, 4))
        for c, t in (("#0", "IP"), ("mac", "MAC"), ("vendor", "Fabricante"), ("host", "Nombre / dispositivo"), ("open", "Puertos de depuración abiertos")): self.iot_tree.heading(c, text=t)
        self.iot_tree.column("#0", width=120); self.iot_tree.column("mac", width=135); self.iot_tree.column("vendor", width=160)
        self.iot_tree.column("host", width=220); self.iot_tree.column("open", width=340)
        self.iot_tree.tag_configure("risk", foreground=RED); self.iot_tree.tag_configure("trusted", foreground=TEAL2)
        self._iot_data = {}
        self.iot_tree.bind("<Double-1>", lambda e: self.iot_details())
        abar = tk.Frame(f, bg=BG); abar.pack(fill="x", padx=16, pady=(0, 4))
        ttk.Button(abar, text="✓ Marcar de confianza", style="Ghost.TButton", command=lambda: self.iot_trust(True)).pack(side="left")
        ttk.Button(abar, text="✕ Quitar de confianza", style="Ghost.TButton", command=lambda: self.iot_trust(False)).pack(side="left", padx=8)
        ttk.Button(abar, text="🔎 Detalles del equipo", style="Ghost.TButton", command=self.iot_details).pack(side="left")
        tk.Label(abar, text="(doble clic = detalles)", bg=BG, fg=MUT, font=("Segoe UI", 8)).pack(side="left", padx=8)
        ipbar = tk.Frame(f, bg=BG); ipbar.pack(fill="x", padx=16, pady=(0, 14))
        self.ip_lbl = tk.Label(ipbar, text="", bg=BG, fg=MUT, font=("Segoe UI", 10)); self.ip_lbl.pack(side="left")
        self._set_text(self.ip_lbl, "Tu IP pública: (pulsa el botón)")
        ttk.Button(ipbar, text="🌐 Ver mi IP y reputación", style="Ghost.TButton", command=self.check_ip).pack(side="right")

    def quick_scan(self):
        self._status("Escaneando red local…")
        self._runbg(scan_local_network, self.refresh_iot)

    def deep_scan(self):
        self._status("Escaneo profundo en curso (barriendo toda tu subred)…")
        def prog(done, total): self._post(lambda: self._status("Escaneo profundo: %d/%d equipos sondeados…", done, total))
        self._runbg(lambda: scan_local_network_deep(progress=prog), self.refresh_iot)

    def refresh_iot(self, data):
        if isinstance(data, Exception): self._status("Error: %s", str(data)); return
        self._iot_list = data or []
        self._render_iot()
        self._status("Red local: %d dispositivos, %d con puertos de depuración (sin marcar de confianza).",
                     len(self._iot_list), len([x for x in self._iot_list if x.get("risk")]))

    def _render_iot(self):
        if not hasattr(self, "iot_tree"): return
        self.iot_tree.delete(*self.iot_tree.get_children()); self._iot_data = {}
        if not self._iot_list:
            self.iot_tree.insert("", "end", text=tr("(sin dispositivos)"), values=("", "", "", "")); return
        for d in self._iot_list:
            tag = "risk" if d.get("risk") else ("trusted" if d.get("trusted") else "")
            opentxt = " · ".join(d.get("open", [])) or "—"
            if d.get("trusted") and d.get("open"): opentxt += "  " + tr("(de confianza)")
            iid = self.iot_tree.insert("", "end", text=d["ip"], values=(d.get("mac", ""), tr(d.get("vendor", "")), tr(d.get("host", "")) or "—", opentxt),
                                       tags=(tag,) if tag else ())
            self._iot_data[iid] = d

    def iot_trust(self, add):
        sel = self.iot_tree.selection()
        if not sel: self._info("Selecciona uno o varios equipos en la lista."); return
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
        for d in self._iot_list:
            d["trusted"] = is_trusted(t, d["ip"], d.get("mac")) or d.get("host") == "(este PC)"
            d["risk"] = bool(d.get("open")) and not d["trusted"]
        self._render_iot()
        self._status("Marcados de confianza: %d equipo(s). Ya no saldrán en rojo." if add else "Quitados de confianza: %d equipo(s).", len(sel))

    def iot_details(self):
        sel = self.iot_tree.selection()
        if not sel: self._info("Selecciona un equipo para ver sus detalles."); return
        d = self._iot_data.get(sel[0])
        if not d: return
        Lns = ["IP:  %s" % d["ip"], "MAC:  %s" % (d.get("mac") or "—"),
               fmt("Fabricante:  %s", (tr(d.get("vendor") or "—"),)),
               fmt("Nombre (DNS inverso):  %s", (tr(d.get("host") or "(no resuelve)"),)),
               fmt("Marcado de confianza:  %s", (tr("Sí") if d.get("trusted") else tr("No"),)), ""]
        if d.get("open"):
            Lns.append(tr("Puertos de depuración abiertos:"))
            for op in d["open"]:
                try: port = int(op.split()[0])
                except Exception: port = None
                Lns.append("• %s\n    %s" % (op, tr(PORT_INFO.get(port, "Puerto de depuración/administración; conviene revisarlo."))))
            if not d.get("trusted"):
                Lns.append("\n" + tr("➡ Si este equipo es TUYO y abriste ese puerto a propósito, márcalo de confianza para que deje de salir en rojo."))
        else:
            Lns.append(tr("Sin puertos de depuración abiertos. ✔"))
        messagebox.showinfo(tr("Detalles del dispositivo"), "\n".join(Lns), parent=self)

    def check_ip(self):
        if not self._ask("Para saber tu IP pública, OptiShield preguntará a api.ipify.org (un servicio externo: verá tu IP, como cualquier web que visitas). No se envía nada más. ¿Continuar?"):
            return
        self._set_text(self.ip_lbl, "Consultando…")
        def done(ip):
            if not ip or isinstance(ip, Exception): self._set_text(self.ip_lbl, "No pude obtener la IP (¿sin internet?)"); return
            self._set_text(self.ip_lbl, "Tu IP pública: %s", ip)
            if self._ask("Tu IP pública es %s.\n\n¿Abrir su reputación en AbuseIPDB (en tu navegador)?\nSirve para ver si tu IP figura como abusiva (a veces por otro usuario de tu proveedor).", ip):
                webbrowser.open("https://www.abuseipdb.com/check/%s" % ip)
        self._runbg(public_ip, done)

    # ---------- Limpiar TV (ADB) ----------
    def _build_tv(self):
        f = self.tab_tv
        self._adb = None; self._tv_serial = None
        top = tk.Frame(f, bg=BG); top.pack(fill="x", padx=16, pady=12)
        ttk.Label(top, text="Limpiar TV / TV-box Android (ADB)", style="H.TLabel").pack(side="left")
        self._mut(f, "Conecta tu TV por USB o por red (activando temporalmente la Depuración). OptiShield lista sus apps y marca las instaladas fuera de una tienda o con nombres sospechosos. Lo recomendado es DESACTIVAR (se puede reactivar y conserva los datos); desinstalar borra los datos de esa app. Al terminar, CIERRA la depuración. Todo con tu aprobación.").pack(anchor="w", padx=16)
        cbar = tk.Frame(f, bg=BG); cbar.pack(fill="x", padx=16, pady=8)
        self.tv_status = tk.Label(cbar, text="", bg=BG, fg=MUT, font=("Segoe UI", 9)); self.tv_status.pack(side="left")
        self._set_text(self.tv_status, "Pulsa «Detectar» cuando tengas el TV conectado (no se ejecuta ADB hasta entonces).")
        ttk.Button(cbar, text="↻ Detectar", style="Ghost.TButton", command=self.tv_detect).pack(side="right")
        ttk.Button(cbar, text="🔌 Conectar por red", style="Ghost.TButton", command=self.tv_connect).pack(side="right", padx=6)
        self.tv_ip = tk.Entry(cbar, width=16, bg=CARD, fg=INK, insertbackground=INK, relief="flat"); self.tv_ip.pack(side="right", padx=6); self.tv_ip.insert(0, "192.168.")
        tk.Label(cbar, text="IP del TV (red):", bg=BG, fg=MUT, font=("Segoe UI", 9)).pack(side="right", padx=(0, 4))
        self.tv_tree = self._tree(f, ("risk", "inst"), 13, "extended", 10)
        for c, t in (("#0", "Paquete (app)"), ("risk", "Riesgo"), ("inst", "Instalador")): self.tv_tree.heading(c, text=t)
        self.tv_tree.column("#0", width=460); self.tv_tree.column("risk", width=90); self.tv_tree.column("inst", width=300)
        self.tv_tree.tag_configure("ALTO", foreground=RED); self.tv_tree.tag_configure("revisar", foreground=AMBER)
        bar = tk.Frame(f, bg=BG); bar.pack(fill="x", padx=16, pady=(0, 14))
        ttk.Button(bar, text="📋 Listar apps", style="Teal.TButton", command=self.tv_list).pack(side="left")
        ttk.Button(bar, text="🚫 Desactivar (recomendado)", style="Ghost.TButton", command=lambda: self.tv_act("disable")).pack(side="left", padx=6)
        ttk.Button(bar, text="🗑 Desinstalar (borra datos)", style="Ghost.TButton", command=lambda: self.tv_act("uninstall")).pack(side="left")
        ttk.Button(bar, text="🔒 Cerrar depuración del TV", style="Ghost.TButton", command=self.tv_close).pack(side="right")

    def tv_detect(self):
        self._adb = _find_adb()
        if not self._adb:
            self._set_text(self.tv_status, "⚠ No encuentro ADB. Pon platform-tools junto al programa o instálalo.", fg="#ffb4b4"); return
        adb = self._adb
        def work():
            devs = adb_devices(adb)
            ready = [s for s, st in devs if st == "device"]
            if ready: return ("ok", ready[0], adb_model(adb, ready[0]))
            if any(st == "unauthorized" for _, st in devs): return ("unauth", None, None)
            if any(st == "offline" for _, st in devs): return ("offline", None, None)
            return ("none", None, None)
        def done(r):
            self._tv_serial = None
            if isinstance(r, Exception) or r[0] == "none":
                self._set_text(self.tv_status, "ADB OK. Sin dispositivos. Conecta el TV por USB o pulsa «Conectar por red».", fg=MUT); return
            if r[0] == "unauth": self._set_text(self.tv_status, "⚠ Acepta el aviso de depuración en la TV (marca «Permitir siempre») y pulsa «Detectar».", fg=AMBER); return
            if r[0] == "offline": self._set_text(self.tv_status, "⚠ El TV aparece «offline»: desconecta y vuelve a conectar, o reinicia la depuración.", fg=AMBER); return
            self._tv_serial = r[1]
            self._set_text(self.tv_status, "✅ Conectado: %s  [%s]", r[1], r[2], fg=TEAL2)
        self._runbg(work, done)

    def tv_connect(self):
        self._adb = self._adb or _find_adb()
        if not self._adb: self._warn("No encuentro ADB (platform-tools)."); return
        ip = self.tv_ip.get().strip()
        if not ip or ip == "192.168.": self._info("Escribe la IP del TV (mira Ajustes → Red del TV)."); return
        self._set_text(self.tv_status, "Conectando a %s…", ip)
        adb = self._adb
        def work(): adb_connect(adb, ip); return adb_devices(adb)
        def done(devs):
            if isinstance(devs, Exception) or not devs:
                self._set_text(self.tv_status, "No pude conectar. ¿Activaste «Depuración por red» en el TV y aceptaste el aviso?", fg="#ffb4b4"); return
            self.tv_detect()
        self._runbg(work, done)

    def tv_list(self):
        if not self._adb or not self._tv_serial: self._info("Primero conecta el TV (USB o red) y pulsa «Detectar»."); return
        self._status("Listando apps del TV…")
        adb, serial = self._adb, self._tv_serial
        self._runbg(lambda: adb_list_packages(adb, serial), self._tv_fill)

    def _tv_fill(self, pkgs):
        if isinstance(pkgs, Exception): self._status("Error: %s", str(pkgs)); return
        self._tv_pkgs = pkgs; self._render_tv()
        self._status("TV: %d apps de terceros (%d para revisar/altas).", len(pkgs), len([p for p in pkgs if p["flag"]]))

    def _render_tv(self):
        if not hasattr(self, "tv_tree"): return
        self.tv_tree.delete(*self.tv_tree.get_children())
        for p in self._tv_pkgs:
            self.tv_tree.insert("", "end", iid=p["pkg"], text=p["pkg"], values=(tr(p["risk"]), tr(p["installer"])),
                                tags=(p["risk"],) if p["risk"] in ("ALTO", "revisar") else ())

    def tv_act(self, mode):
        if not self._adb or not self._tv_serial: self._info("Conecta el TV primero."); return
        sel = list(self.tv_tree.selection())
        if not sel: self._info("Selecciona en la lista las apps a tratar."); return
        lst = "\n• ".join(sel[:25]) + ("\n• …(+%d)" % (len(sel) - 25) if len(sel) > 25 else "")
        if mode == "disable":
            if not self._ask("Vas a DESACTIVAR %d app(s) del TV (se pueden reactivar; los datos se conservan):\n\n• %s\n\n¿Continuar?", len(sel), lst): return
        else:
            if not self._ask("Vas a DESINSTALAR %d app(s) del TV. Esto BORRA sus datos y no se puede deshacer desde aquí. Si solo quieres que dejen de funcionar, mejor «Desactivar».\n\n• %s\n\n¿Desinstalar igualmente?", len(sel), lst): return
        adb, serial = self._adb, self._tv_serial
        def work():
            ok = 0
            for pkg in sel:
                r = adb_disable(adb, serial, pkg) if mode == "disable" else adb_uninstall(adb, serial, pkg)
                if "success" in r.lower() or "disabled" in r.lower() or "new state: disabled" in r.lower(): ok += 1
                log("TV %s %s -> %s" % (mode, pkg, r.strip()[:80]))
            return ok
        def done(ok):
            if isinstance(ok, Exception): self._err("No se pudo completar: %s", str(ok)); return
            self._info("Hecho: %d/%d app(s) desactivadas." if mode == "disable" else "Hecho: %d/%d app(s) desinstaladas.", ok, len(sel))
            self.tv_list()
        self._runbg(work, done)

    def tv_close(self):
        if not self._adb or not self._tv_serial: self._info("Conecta el TV primero."); return
        if not self._ask("Se DESACTIVARÁ la depuración (primero la depuración por red y después la USB) del TV para cerrarlo bien.\n(Recomendado al terminar.) ¿Continuar?"): return
        adb, serial = self._adb, self._tv_serial
        def done(r):
            if isinstance(r, Exception): self._err("No se pudo completar: %s", str(r)); return
            wifi_ok, adb_ok = r
            self._info("Depuración por red: %s\nDepuración ADB: %s\n\nRecuerda desactivar también «Opciones de desarrollador» en el TV.",
                       tr("desactivada ✔") if wifi_ok else tr("no confirmada ✖"),
                       tr("orden enviada (la conexión se cierra) ✔") if adb_ok else tr("no confirmada ✖"))
            if wifi_ok and adb_ok:
                self._set_text(self.tv_status, "🔒 Depuración cerrada en el TV.", fg=TEAL2); self._tv_serial = None
            else:
                self._set_text(self.tv_status, "⚠ Cierre de depuración incompleto: revisa Opciones de desarrollador en el TV.", fg=AMBER)
        self._runbg(lambda: adb_close_debug(adb, serial), done)

    # ---------- Privacidad ----------
    def _build_privacy(self):
        f = self.tab_priv
        ttk.Label(f, text="Blindaje de privacidad y telemetría", style="H.TLabel").pack(anchor="w", padx=16, pady=(14, 2))
        self._mut(f, "Marca lo que quieras cambiar. NO se toca Defender, Firewall ni UAC. Al aplicar se guarda el valor ORIGINAL de cada ajuste; «Revertir» devuelve exactamente ese valor (o lo borra si antes no existía). Si un ajuste no tiene copia, no se toca.").pack(anchor="w", padx=16)
        wrap = tk.Frame(f, bg=CARD, highlightbackground=LINE, highlightthickness=1); wrap.pack(fill="both", expand=True, padx=16, pady=12)
        self.priv_vars = {}; self.priv_status_lbl = {}
        for i, tw in enumerate(PRIVACY_TWEAKS):
            v = tk.BooleanVar(value=False); self.priv_vars[tw["id"]] = v
            ttk.Checkbutton(wrap, text=tw["name"], variable=v, style="TCheckbutton").grid(row=i, column=0, sticky="w", padx=14, pady=4)
            lb = tk.Label(wrap, text="", bg=CARD, fg=MUT, font=("Segoe UI", 9)); lb.grid(row=i, column=1, sticky="w", padx=14)
            self._dyn[lb] = ("", ()); self.priv_status_lbl[tw["id"]] = lb
        wrap.columnconfigure(1, weight=1)
        sel = tk.Frame(f, bg=BG); sel.pack(fill="x", padx=16)
        for key, mode in (("Marcar los no aplicados", "notapplied"), ("Marcar los aplicados (para revertir)", "applied"), ("Desmarcar todo", "none")):
            tk.Button(sel, text=key, bd=0, relief="flat", bg=BG, fg=TEAL, activebackground=BG, activeforeground=TEAL2, cursor="hand2",
                      font=("Segoe UI", 9, "underline"), command=lambda m=mode: self._priv_select(m)).pack(side="left", padx=(0, 14))
        bar = tk.Frame(f, bg=BG); bar.pack(fill="x", padx=16, pady=(6, 14))
        ttk.Button(bar, text="🔒 Aplicar seleccionados", style="Teal.TButton", command=lambda: self.apply_privacy(True)).pack(side="left")
        ttk.Button(bar, text="↩ Revertir seleccionados", style="Ghost.TButton", command=lambda: self.apply_privacy(False)).pack(side="left", padx=8)
        self._priv_state = {}
        self._reload_privacy_status()

    def _reload_privacy_status(self):
        def done(st):
            if isinstance(st, Exception): return
            self._priv_state = st; self._refresh_privacy_status()
        self._runbg(privacy_status, done)

    def _refresh_privacy_status(self):
        for tid, lb in getattr(self, "priv_status_lbl", {}).items():
            st, when = self._priv_state.get(tid, ("default", ""))
            if st == "applied": self._set_text(lb, "✔ Aplicado por OptiShield (%s) — se puede revertir", when, fg=TEAL2)
            elif st == "private": self._set_text(lb, "Ya está en modo privado (sin copia de OptiShield: no se puede revertir desde aquí)", fg=MUT)
            else: self._set_text(lb, "Sin aplicar", fg=MUT)

    def _priv_select(self, mode):
        for tid, v in self.priv_vars.items():
            st = self._priv_state.get(tid, ("default", ""))[0]
            v.set(mode == "applied" and st == "applied" or mode == "notapplied" and st == "default")

    def apply_privacy(self, enable_privacy):
        if not is_admin(): self._warn("Ejecuta OptiShield como administrador para cambiar estos ajustes."); return
        ids = [tid for tid, v in self.priv_vars.items() if v.get()]
        if not ids: self._info("Marca al menos una opción."); return
        if not enable_privacy and not any(self._priv_state.get(i, ("",))[0] == "applied" for i in ids):
            self._info("Ninguno de los marcados tiene copia de OptiShield, así que no hay nada que revertir (no se toca nada)."); return
        self._status("Trabajando…")
        def work():
            if enable_privacy: return ("apply",) + privacy_apply(ids)
            return ("revert",) + privacy_revert(ids)
        def done(r):
            if isinstance(r, Exception): self._err("No se pudo completar: %s", str(r)); self._status("Error: %s", str(r)); return
            parts = []
            if r[0] == "apply":
                _, nreg, nsvc, fails = r
                parts.append(fmt("Privacidad aplicada: %d valores cambiados, %d servicios desactivados.", (nreg, nsvc)))
            else:
                _, nreg, nsvc, fails, nocopy = r
                parts.append(fmt("Privacidad revertida: %d valores restaurados, %d servicios restaurados.", (nreg, nsvc)))
                if nocopy: parts.append(fmt("Sin copia (no se tocó): %s", (", ".join(tr(n) for n in nocopy),)))
            if fails: parts.append(fmt("Fallos: %s", (", ".join(fails),)))
            parts.append(tr("Reinicia el PC para que todo quede aplicado."))
            messagebox.showinfo(APP, "\n\n".join(parts), parent=self)
            self._status("Hecho."); self._reload_privacy_status()
        self._runbg(work, done)

    # ---------- Arranque ----------
    def _build_startup(self):
        f = self.tab_start
        top = tk.Frame(f, bg=BG); top.pack(fill="x", padx=16, pady=12)
        ttk.Label(top, text="Auditoría de arranque", style="H.TLabel").pack(side="left")
        ttk.Button(top, text="🔎 Escanear", style="Teal.TButton", command=self.scan_start).pack(side="right")
        self.show_ms_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Mostrar tareas de Windows", variable=self.show_ms_var, style="Bg.TCheckbutton",
                        command=lambda: self.refresh_startup(self._start_items)).pack(side="right", padx=12)
        self._mut(f, "Programas, tareas y entradas que arrancan con Windows (Run 64/32 bits, RunOnce, carpeta Inicio y tareas). En rojo = sospechoso (Temp, comandos ofuscados). En ámbar = OBSOLETO: apunta a un archivo que ya no existe. «Desconocido» = no se pudo comprobar (no se toca). Antes de cualquier cambio se guarda copia; «Restaurar arranque» lo devuelve.").pack(anchor="w", padx=16)
        self.start_tree = self._tree(f, ("type", "loc", "estado", "cmd"), 15, "extended", (10, 4))
        for c, t in (("#0", "Nombre"), ("type", "Tipo"), ("loc", "Ubicación"), ("estado", "Estado"), ("cmd", "Comando")): self.start_tree.heading(c, text=t)
        self.start_tree.column("#0", width=220); self.start_tree.column("type", width=120); self.start_tree.column("loc", width=150)
        self.start_tree.column("estado", width=170); self.start_tree.column("cmd", width=420)
        self.start_tree.tag_configure("susp", foreground=RED); self.start_tree.tag_configure("orphan", foreground=AMBER); self.start_tree.tag_configure("disabled", foreground=GRAY)
        self._start_data = {}
        bar = tk.Frame(f, bg=BG); bar.pack(fill="x", padx=16, pady=(0, 14))
        ttk.Button(bar, text="⛔ Desactivar", style="Ghost.TButton", command=lambda: self.start_toggle(False)).pack(side="left")
        ttk.Button(bar, text="✅ Activar", style="Ghost.TButton", command=lambda: self.start_toggle(True)).pack(side="left", padx=8)
        ttk.Button(bar, text="🧹 Limpiar obsoletas", style="Teal.TButton", command=self.start_clean_orphans).pack(side="left", padx=8)
        ttk.Button(bar, text="🗑 Eliminar", style="Ghost.TButton", command=self.start_remove).pack(side="left")
        ttk.Button(bar, text="↩ Restaurar arranque", style="Ghost.TButton", command=self.start_restore).pack(side="right")

    def scan_start(self):
        self._status("Escaneando…")
        def done(d):
            if isinstance(d, Exception): self._status("Error: %s", str(d)); return
            self._start_items = d; self.refresh_startup(d); self._status("Hecho.")
        self._runbg(scan_startup, done)

    def refresh_startup(self, data):
        if isinstance(data, Exception) or not hasattr(self, "start_tree"): return
        self.start_tree.delete(*self.start_tree.get_children()); self._start_data = {}
        show_ms = self.show_ms_var.get()
        for x in data or []:
            if x.get("is_ms") and not show_ms: continue
            o = x.get("orphan")
            base = "⚠ obsoleto (no existe)" if o == "orphan" else ("sospechoso" if x.get("susp") else ("desconocido" if o == "unknown" and x["type"] != "Tarea" else "OK"))
            estado = tr(base) if x.get("enabled", True) else ((tr(base) + " · ") if base != "OK" else "") + tr("desactivado")
            if not x.get("enabled", True): tag = "disabled"
            else: tag = "orphan" if o == "orphan" else ("susp" if x.get("susp") else "")
            iid = self.start_tree.insert("", "end", text=x["name"], values=(tr(x.get("label", x["type"])), x["loc"], estado, x["cmd"][:160]),
                                         tags=(tag,) if tag else ())
            self._start_data[iid] = x

    def _sel_start(self):
        return [self._start_data[i] for i in self.start_tree.selection() if i in self._start_data]

    def _confirm_ms(self, items):
        ms = [x for x in items if x.get("is_ms")]
        if not ms: return True
        return self._ask("Vas a tocar %d tarea(s) de WINDOWS (carpeta \\Microsoft\\):\n\n• %s\n\nDesactivar tareas del sistema puede romper actualizaciones, copias o funciones de Windows. Hazlo solo si sabes qué es. ¿Continuar?",
                         len(ms), "\n• ".join(x["tn"] for x in ms[:15]))

    def _show_results(self, results, backup=None):
        lines = [fmt("✔ %s", (n,)) if ok else fmt("✖ %s: %s", (n, msg)) for n, ok, msg in results]
        msg = tr("Resultado:") + "\n\n" + "\n".join(lines[:40]) + ("\n…" if len(lines) > 40 else "")
        if backup: msg += "\n\n" + fmt("Copia guardada en: %s", (backup,))
        messagebox.showinfo(APP, msg, parent=self)

    def start_toggle(self, enable):
        if not is_admin(): self._warn("Ejecuta OptiShield como administrador para cambiar el arranque."); return
        items = self._sel_start()
        if not items: self._info("Selecciona en la lista las entradas a tratar."); return
        if not self._confirm_ms(items): return
        names = "\n• ".join(x["name"] for x in items[:20]) + ("\n• …" if len(items) > 20 else "")
        if not self._ask("Se ACTIVARÁN %d entrada(s) (se guarda copia):\n\n• %s\n\n¿Continuar?" if enable else "Se DESACTIVARÁN %d entrada(s) (se guarda copia):\n\n• %s\n\n¿Continuar?", len(items), names): return
        self._status("Trabajando…")
        def done(r):
            if isinstance(r, Exception): self._err("No se pudo completar: %s", str(r)); return
            self._show_results(*r); self.scan_start()
        self._runbg(lambda: startup_set_enabled(items, enable), done)

    def start_remove(self):
        if not is_admin(): self._warn("Ejecuta OptiShield como administrador para cambiar el arranque."); return
        items = self._sel_start()
        if not items: self._info("Selecciona en la lista las entradas a tratar."); return
        if not self._confirm_ms(items): return
        names = "\n• ".join(x["name"] for x in items[:20]) + ("\n• …" if len(items) > 20 else "")
        if not self._ask("Se ELIMINARÁN %d entrada(s) (se guarda copia exacta para «Restaurar arranque»; las tareas solo se DESACTIVAN y los accesos de la carpeta Inicio se mueven a la copia):\n\n• %s\n\n¿Continuar?", len(items), names): return
        self._do_delete(items)

    def _do_delete(self, items):
        self._status("Trabajando…")
        def done(r):
            if isinstance(r, Exception): self._err("No se pudo completar: %s", str(r)); return
            self._show_results(*r); self.scan_start()
        self._runbg(lambda: startup_delete(items), done)

    def start_clean_orphans(self):
        if not is_admin(): self._warn("Ejecuta OptiShield como administrador para cambiar el arranque."); return
        cands = [x for x in self._start_items if x["type"] in ("Run", "RunOnce") and x.get("orphan") == "orphan"]
        if not cands: self._info("No hay entradas obsoletas (que apunten a un archivo que ya no existe). Pulsa «Escanear» primero."); return
        dlg = tk.Toplevel(self); dlg.title(tr("Entradas de arranque obsoletas")); dlg.configure(bg=BG); dlg.transient(self); dlg.grab_set()
        tk.Label(dlg, text=tr("Estas entradas apuntan a un archivo que YA NO EXISTE. Marca las que quieras eliminar (se guarda copia exacta; «Restaurar arranque» las devuelve):"),
                 bg=BG, fg=INK, wraplength=760, justify="left", font=("Segoe UI", 10)).pack(anchor="w", padx=14, pady=(12, 6))
        box = tk.Frame(dlg, bg=CARD); box.pack(fill="both", expand=True, padx=14)
        vars_ = []
        for x in cands:
            v = tk.BooleanVar(value=True); vars_.append((v, x))
            ttk.Checkbutton(box, text="%s  —  %s\\%s\n      %s" % (x["name"], x["hive"], x["regpath"].split("\\")[-1], x["cmd"][:110]),
                            variable=v, style="TCheckbutton").pack(anchor="w", padx=10, pady=3)
        bar = tk.Frame(dlg, bg=BG); bar.pack(fill="x", padx=14, pady=12)
        def go():
            chosen = [x for v, x in vars_ if v.get()]
            dlg.destroy()
            if chosen: self._do_delete(chosen)
        ttk.Button(bar, text=tr("Eliminar las marcadas"), style="Teal.TButton", command=go).pack(side="left")
        ttk.Button(bar, text=tr("Cancelar"), style="Ghost.TButton", command=dlg.destroy).pack(side="left", padx=8)

    def start_restore(self):
        if not is_admin(): self._warn("Ejecuta OptiShield como administrador para cambiar el arranque."); return
        bks = list_startup_backups()
        if not bks: self._info("No hay copias de arranque."); return
        dlg = tk.Toplevel(self); dlg.title(tr("Restaurar arranque")); dlg.configure(bg=BG); dlg.transient(self); dlg.grab_set()
        tk.Label(dlg, text=tr("Elige la copia a restaurar (la primera es la más reciente):"), bg=BG, fg=INK, font=("Segoe UI", 10)).pack(anchor="w", padx=14, pady=(12, 6))
        lb = tk.Listbox(dlg, width=90, height=min(14, len(bks)), bg=CARD, fg=INK, selectbackground=LINE, font=("Consolas", 9))
        lb.pack(fill="both", expand=True, padx=14)
        for p, d in bks:
            lb.insert("end", fmt("%s — %s — %d entrada(s)", (d.get("when", "?")[:15], tr({"disable": "desactivar", "enable": "activar", "delete": "eliminar"}.get(d.get("action"), d.get("action", "?"))), len(d.get("items", [])))))
        lb.selection_set(0)
        bar = tk.Frame(dlg, bg=BG); bar.pack(fill="x", padx=14, pady=12)
        def go():
            s = lb.curselection()
            if not s: return
            path = bks[s[0]][0]; dlg.destroy()
            self._status("Trabajando…")
            def done(r):
                if isinstance(r, Exception): self._err("No se pudo completar: %s", str(r)); return
                self._show_results(r); self.scan_start()
            self._runbg(lambda: startup_restore(path), done)
        ttk.Button(bar, text=tr("Restaurar"), style="Teal.TButton", command=go).pack(side="left")
        ttk.Button(bar, text=tr("Cancelar"), style="Ghost.TButton", command=dlg.destroy).pack(side="left", padx=8)

    # ---------- Integridad ----------
    def _build_integrity(self):
        f = self.tab_integ
        top = tk.Frame(f, bg=BG); top.pack(fill="x", padx=16, pady=12)
        ttk.Label(top, text="Integridad del sistema", style="H.TLabel").pack(side="left")
        ttk.Button(top, text="🔎 Escanear", style="Teal.TButton", command=self.scan_integ).pack(side="right")
        self.integ_txt = self._text(f, bg=CARD, fg=INK, font=("Consolas", 9))
        bar = tk.Frame(f, bg=BG); bar.pack(fill="x", padx=16, pady=(0, 14))
        ttk.Button(bar, text="🧽 Quitar bloqueos hosts", style="Ghost.TButton", command=self.clean_hosts).pack(side="left")
        ttk.Button(bar, text="🧯 Quitar reglas firewall", style="Ghost.TButton", command=self.clean_firewall).pack(side="left", padx=8)
        ttk.Button(bar, text="📄 Exportar informe", style="Ghost.TButton", command=self.export_report).pack(side="right")

    def scan_integ(self):
        self._status("Escaneando…")
        def done(r):
            if isinstance(r, Exception): self._status("Error: %s", str(r)); return
            self._integ = r; self.refresh_integrity(r); self._status("Hecho.")
        self._runbg(scan_integrity, done)

    def _integrity_text(self, r):
        out = []
        out.append(fmt("PROXY DEL SISTEMA: %s", (fmt("ACTIVO → %s", (r["proxy_server"],)) if r["proxy_enabled"] else tr("sin proxy de sistema"),)))
        out.append("")
        out.append(tr("SERVIDORES DNS:"))
        if not r["dns"]: out.append(tr("  (no leído)"))
        dflt = [d for d in r["dns"] if d["servers"] and all(x.lower().startswith("fec0:0:0:ffff::") for x in d["servers"])]
        if dflt: out.append(fmt("  %d adaptador(es) solo con los DNS IPv6 predeterminados de Windows (fec0::, sin uso): %s", (len(dflt), ", ".join(d["alias"] for d in dflt))))
        for d in r["dns"]:
            if d in dflt: continue
            sv = []
            for s in d["servers"]:
                lab = KNOWN_DNS.get(s) or (tr("predeterminado de Windows, sin uso") if s.lower().startswith("fec0:0:0:ffff::") else (tr("router/red local") if _is_private(s) else ""))
                sv.append(s + (" (%s)" % lab if lab else ""))
            out.append("  %s (%s): %s" % (d["alias"], d["family"], ", ".join(sv)))
        out.append("")
        if r["ioc_hits"]: out += [tr("⚠ DOMINIOS IOC EN HOSTS (revisar):")] + r["ioc_hits"]
        else: out.append(tr("✔ Sin dominios IOC sospechosos en hosts."))
        out.append("")
        out.append(fmt("ENTRADAS ACTIVAS EN HOSTS (%d, de ellas %d de OptiShield):", (len(r["hosts"]), r.get("optishield_lines", 0))))
        out += (r["hosts"][:80] or [tr("  (vacío)")])
        out.append(""); out.append(tr("Nota: hosts no bloquea subdominios ni el DNS seguro (DoH) del navegador."))
        return "\n".join(out)

    def refresh_integrity(self, r):
        if isinstance(r, Exception) or not r: return
        t = self.integ_txt; t.delete("1.0", "end"); t.insert("end", self._integrity_text(r))

    def clean_hosts(self):
        if not is_admin(): self._warn("Requiere administrador."); return
        if not self._ask("Se quitarán las líneas marcadas «# OptiShield» del archivo hosts (se guarda copia antes). ¿Continuar?"): return
        def work():
            n, bk = hosts_remove(None); flush_dns(); return n, bk
        def done(r):
            if isinstance(r, Exception): self._err("No pude editar hosts: %s", str(r)); return
            self._info("Bloqueos de OptiShield retirados del archivo hosts: %d líneas. Copia: %s", r[0], r[1] or "—"); self.scan_integ()
        self._runbg(work, done)

    def clean_firewall(self):
        if not is_admin(): self._warn("Requiere administrador."); return
        if not self._ask("Se borrarán SOLO las reglas de firewall creadas por OptiShield («OptiShield block …»). ¿Continuar?"): return
        def work():
            names = [n.strip() for n in ps("Get-NetFirewallRule -DisplayName 'OptiShield block*' -ErrorAction SilentlyContinue | "
                                           "Select-Object -ExpandProperty DisplayName").splitlines() if n.strip().startswith("OptiShield block")]
            names = sorted(set(names))
            ok = sum(1 for n in names if firewall_delete_rule(n))
            return ok, len(names)
        def done(r):
            if isinstance(r, Exception): self._err("No se pudo completar: %s", str(r)); return
            self._info("Reglas de firewall de OptiShield eliminadas: %d de %d.", r[0], r[1])
        self._runbg(work, done)

    def export_report(self):
        p = filedialog.asksaveasfilename(parent=self, defaultextension=".txt", initialfile="OptiShield-%s.txt" % tr("informe"),
                                         filetypes=[(tr("Texto"), "*.txt")])
        if not p: return
        prox, net, start, integ = list(self._prox_data), list(self._net_data), list(self._start_items), self._integ
        intentional = bool(self.def_var.get()); allowed = self._allowed()
        def work():
            d = defender_status()
            L_ = ["OptiShield %s — %s %s — %s" % (VERSION, tr("informe"), datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), SIGNATURE), ""]
            L_.append(tr("=== Proxyware ==="))
            if not prox: L_.append(tr("(sin datos: pulsa «Analizar todo» antes)"))
            for x in prox:
                L_.append("- %s [%s] %s | %s" % (finding_name(x), tr(RISK_LABEL.get(x["risk"], x["risk"])),
                                                 tr(V_ALLOWED if x["id"] in allowed else x["verdict"]), finding_evidence(x)))
            L_.append(""); L_.append(tr("=== Red (conexiones en rojo) ==="))
            fl = [c for c in net if c.get("flag")]
            L_ += ["- %s (PID %s) → %s %s" % (c["proc"], c["pid"], c["remote"], c.get("host", "")) for c in fl] or [tr("(nada)")]
            L_.append(""); L_.append(tr("=== Arranque (sospechoso u obsoleto) ==="))
            st = [x for x in start if (x.get("susp") or x.get("orphan") == "orphan") and not x.get("is_ms")]
            L_ += ["- %s [%s] %s" % (x["name"], tr(x.get("label", x["type"])), x["cmd"]) for x in st] or [tr("(nada)")]
            L_.append(""); L_.append(tr("=== Integridad ==="))
            L_.append(self._integrity_text(integ) if integ else tr("(sin datos: pulsa «Analizar todo» antes)"))
            L_.append(""); L_.append(tr("=== Defender ==="))
            if d.get("av"): L_.append(fmt("Defender: encendido (antivirus=%s, tiempo real=%s)", (tr("Sí"), tr("Sí") if d.get("rt") else tr("No"))))
            elif intentional: L_.append(tr("Defender: apagado a propósito (marcado por ti). No cuenta como problema."))
            elif d.get("av") is None: L_.append(tr("Defender: no pude leer su estado (puede estar desinstalado o desactivado por directiva)."))
            else: L_.append(tr("Defender: apagado. Si usas otro antivirus o lo apagaste a propósito, márcalo en la casilla de arriba."))
            if d.get("others"): L_.append(fmt("Antivirus registrado en Windows: %s", (", ".join(d["others"]),)))
            L_.append(tr("OptiShield no sustituye a un antivirus."))
            L_.append(""); L_.append(tr("Generado en tu PC. OptiShield no tiene telemetría: solo consultas DNS normales y, si pulsas el botón, ipify.org / AbuseIPDB."))
            with open(p, "w", encoding="utf-8") as f: f.write("\n".join(L_) + "\n")
            return True
        def done(r):
            if isinstance(r, Exception): self._err("No se pudo completar: %s", str(r)); return
            self._info("Informe guardado.")
        self._runbg(work, done)

    # ---------- Apoyo OptiSuite ----------
    def _build_help(self):
        f = self.tab_help
        box = tk.Frame(f, bg=CARD, highlightbackground=LINE, highlightthickness=1); box.pack(fill="both", expand=True, padx=40, pady=24)
        tk.Label(box, text="🛡️ OptiShield %s" % VERSION, bg=CARD, fg=INK, font=("Segoe UI", 22, "bold")).pack(pady=(20, 2))
        tk.Label(box, text="Una herramienta gratuita de OptiSuite para proteger tu privacidad y seguridad.", bg=CARD, fg=MUT, font=("Segoe UI", 11)).pack()
        tk.Label(box, text=SIGNATURE, bg=CARD, fg=INK, font=("Segoe UI", 10, "bold")).pack(pady=(6, 0))
        tk.Label(box, text="Defensiva · reversible · Sin telemetría. Solo consultas DNS normales y, si pulsas el botón, ipify.org / AbuseIPDB.",
                 bg=CARD, fg=TEAL2, font=("Segoe UI", 10, "bold"), wraplength=900).pack(pady=(4, 2))
        tk.Label(box, text="OptiShield no sustituye a un antivirus.", bg=CARD, fg=MUT, font=("Segoe UI", 9)).pack(pady=(0, 12))
        tk.Label(box, text="Es gratis y sin anuncios. Si te ayuda, una estrella en GitHub o una aportación por Binance\nmantienen OptiSuite vivo. ¡Gracias! 🙌",
                 bg=CARD, fg=INK, font=("Segoe UI", 10), justify="center").pack(pady=(0, 10))
        btns = tk.Frame(box, bg=CARD); btns.pack(pady=4)
        ttk.Button(btns, text="⭐ Estrella en GitHub", style="Teal.TButton", command=lambda: webbrowser.open(GITHUB)).pack(side="left", padx=6)
        ttk.Button(btns, text="🌐 Visitar OptiSuite", style="Ghost.TButton", command=lambda: webbrowser.open("https://" + WEB)).pack(side="left", padx=6)
        tk.Label(box, text="Donaciones por Binance (toca para copiar):", bg=CARD, fg=MUT, font=("Segoe UI", 9)).pack(pady=(16, 4))
        crow = tk.Frame(box, bg=CARD); crow.pack()
        def copy_btn(label, value):
            ttk.Button(crow, text="%s:  %s" % (label, value), style="Ghost.TButton",
                       command=lambda: (self.clipboard_clear(), self.clipboard_append(value), self._status("Copiado al portapapeles: %s", value))).pack(side="left", padx=6)
        copy_btn("Binance Pay ID", BINANCE_ID)
        copy_btn("USDT · BSC (BEP-20)", USDT_BSC)
        tk.Label(box, text="✉  %s      🌐  %s" % (EMAIL, WEB), bg=CARD, fg=MUT, font=("Segoe UI", 10)).pack(pady=(16, 2))
        tk.Label(box, text="© OptiSuite · OptiShield es gratuito. Si te ayuda, compártelo.", bg=CARD, fg=MUT, font=("Segoe UI", 9)).pack(side="bottom", pady=14)


class _Lazy:
    """Valor que se calcula al formatear (p. ej. nombre traducido de un hallazgo)."""
    def __init__(self, fn, *a): self.fn = fn; self.a = a
    def __str__(self): return str(self.fn(*self.a))


def main():
    if not is_admin() and "--noelevate" not in sys.argv:
        # intentar elevar para poder aplicar cambios; si el usuario cancela, sigue en modo lectura
        try:
            exe = sys.executable
            params = "--noelevate" if getattr(sys, "frozen", False) else '"%s" --noelevate' % os.path.abspath(sys.argv[0])
            r = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
            if r > 32: sys.exit(0)
        except Exception: pass
    app = OptiShield(); app.mainloop()

if __name__ == "__main__":
    main()
