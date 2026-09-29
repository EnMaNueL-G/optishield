# 🛡️ OptiShield 1.2.0 — Enmanuel Gil · OptiSuite

Herramienta **gratuita** de escritorio (Windows) para **proteger tu privacidad y seguridad**:
detecta *proxyware* (apps que comparten tu conexión a cambio de dinero) y SDK que convierten tu PC en
nodo de proxy residencial (tipo **NetNut / Badbox**), blinda la telemetría y la ubicación, audita el
arranque y revisa la integridad del sistema.

**Principios:** defensiva · reversible (con copia de seguridad antes de cada cambio) ·
**sin telemetría**: solo consultas DNS normales y, si pulsas el botón, **ipify.org / AbuseIPDB** ·
no toca Windows Defender, la configuración del Firewall ni UAC (solo añade reglas propias etiquetadas
«OptiShield block …», que puedes quitar cuando quieras).

> **OptiShield no sustituye a un antivirus.** Si tienes Defender apagado a propósito (u otro antivirus),
> marca «Defender: lo desactivé a propósito» en el Panel y no contará como problema.

---

## ✅ Qué hace

| Pestaña | Función |
|---|---|
| **🏠 Panel** | Resumen + «Analizar todo» (si una parte falla, el resto sigue y se dice cuál falló). Vigilancia opcional cada 15 min. Casilla «Defender: lo desactivé a propósito». |
| **🕵 Proxyware** | Detecta ~33 familias por proceso, servicio, carpeta y registro. **Proxyware** (comparte tu conexión: Honeygain, Pawns, EarnApp, PacketStream, Peer2Profit, Traffmonetizer, Repocket, PacketShare, Proxyrack PeerConnect, Grass, Nodepay, Bytelixir, EarnFM, ProxyLite, Bitping, Salad, Mysterium **nodo**, Hola, Tuxler, Infatica, NetNut SDK…). Los **proxies de pago que tú usas** (Decodo/Smartproxy, IPRoyal, Oxylabs, Bright Data, Proxy-Cheap, 922 S5/IP2World, Asocks, Proxifier) y las **VPN normales** (Mysterium VPN, Psiphon, Betternet, TouchVPN) salen como **informativo**. Sonda **SOCKS5**: si escucha solo en 127.0.0.1 es un **proxy local (informativo)** y dice qué programa es (Tor, Clash, v2rayN, ssh -D…). Detecta **SDK** de proxyware cargados en navegadores/Spotify/Discord. Botón **«Permitir»** para lo que instalaste a propósito. **Neutralizar** (con copia): regla de firewall por ruta del programa, detiene solo esos procesos (por PID y ruta), desactiva sus servicios guardando su modo de arranque y bloquea sus dominios en *hosts*. **«↩ Deshacer neutralización»** lo devuelve. |
| **🌐 Red** | Conexiones activas + organización por DNS inverso (en paralelo y con límite de tiempo). Rojo = un programa (contado **por PID**) con muchas conexiones (excepto navegadores, Steam, torrent, servicios de Windows) o destino de una red de proxyware. Ámbar = destino que parece proxy/VPN (normal si usas uno). |
| **🏘 Red local** | Escaneo rápido (ARP) o profundo (tu subred /24) + fabricante por MAC + puertos de depuración (5555 ADB, Telnet, FTP…). Equipos «de confianza». IP pública (avisa antes de consultar ipify.org). |
| **📺 TV** | TV/TV-box Android por **ADB** (USB o red): lista apps, marca las de fuera de tienda. Recomienda **Desactivar** (reversible) antes que desinstalar (borra datos). Cierra la depuración (primero la de red y luego la USB, comprobando). ADB no se ejecuta hasta que pulsas «Detectar». |
| **🔒 Privacidad** | Telemetría, ID de publicidad, ubicación, historial, Bing en Inicio… Al aplicar se guarda el **valor original exacto** (tipo y dato, o «no existía») y el modo de arranque de los servicios. «Revertir» devuelve exactamente eso; si un ajuste no tiene copia, no se toca. |
| **🧹 Arranque** | Run 64/32 bits, RunOnce, carpeta Inicio (usuario y común) y tareas (las de Windows ocultas salvo que marques «Mostrar tareas de Windows»; tocar una pide confirmación). «Limpiar obsoletas» muestra una lista para que elijas; todo cambio guarda copia y **«↩ Restaurar arranque»** lo devuelve. |
| **🛡 Integridad** | Proxy del sistema, servidores DNS (por adaptador), *hosts* y dominios IOC. Quitar bloqueos de hosts (con copia) y reglas de firewall de OptiShield. Exportar informe. |
| **💬 Apoyo** | Contacto, estrella en GitHub y donaciones **solo por Binance**. |

---

## 🆕 Cambios en 1.2.0 (honestos)

**Seguridad de los cambios (lo más importante)**
- «Limpiar obsoletas» ya **no** borra entradas como `ctfmon.exe`, `rundll32 shell32.dll,…` o `wscript.exe //B …`: los programas sin ruta se buscan en PATH, System32 y SysWOW64; si no se puede comprobar, queda «desconocido» y no se toca. Solo cuenta como obsoleto una ruta completa que ya no existe. Ahora enseña la lista y actúa solo sobre lo que marques.
- Todo cambio de arranque guarda copia en `%ProgramData%\OptiShield\backups` con el **tipo de valor** (REG_SZ / REG_EXPAND_SZ) y el dato; nuevo botón **«↩ Restaurar arranque»**.
- **Privacidad «Revertir»** ya no escribe valores fijos (la 1.1 dejaba, por ejemplo, `AllowTelemetry=1` como directiva y Windows mostraba «las administra tu organización»). Ahora restaura la copia: si el valor no existía, lo borra. Los servicios vuelven a su modo de arranque original. Las casillas ya no vienen todas marcadas. *Ojo:* lo que aplicaste con la 1.1 no tiene copia, así que la 1.2 no lo revierte (sale como «Ya está en modo privado (sin copia…)»).
- **Neutralizar** guarda copia y se puede **deshacer**; termina procesos por PID y ruta (nunca por nombres genéricos como `tm.exe`), el resumen dice qué funcionó y qué no, y no dice «firewall» si no se creó la regla. Para SOCKS5/SDK (sin entrada en la base de datos) explica qué hacer en vez de fingir.
- **hosts**: copia antes de escribir, se conserva la codificación (UTF-8 o ANSI) y el salto de línea, se vacía la caché DNS. Aviso: hosts no cubre subdominios ni el DNS seguro (DoH) del navegador; por eso se prefiere el firewall por ruta de programa.

**Menos falsos positivos**
- Proxies de pago y VPN normales = **informativo**, no proxyware. Se quitó la firma «Grasshopper» (esa carpeta es de Rhino 3D). Nombres genéricos (`tm.exe`, `s5.exe`, `psclient.exe`, `p2papp.exe`…) solo cuentan dentro de la carpeta del producto.
- SOCKS5 en 127.0.0.1 = proxy local (informativo) con el nombre del programa. En la TV, palabras sueltas como *proxy/peer/hidden/silent* = «revisar», no «ALTO».
- Red: conexiones contadas por PID con lista de exclusión; «vpn» en el nombre ya no marca riesgo.
- Vigilancia: lista de **Permitidos**, mira también servicios y no repite el aviso si no cambia nada.
- Nuevas familias: Grass, Nodepay, Bytelixir, EarnFM, ProxyLite, Bitping, Salad, Tuxler, Mysterium nodo (separado de Mysterium VPN). Las firmas nuevas son por carpeta/nombre de producto: pueden no reconocer todas las versiones.

**Otros arreglos**
- El `.exe` busca `data\proxyware_db.json` y `platform-tools` **primero junto al .exe**. Una base de datos anterior a 1.2.0 se ignora.
- Todo lo lento va en segundo plano y la ventana ya no se congela; «Analizar todo» sigue aunque falle una parte.
- Textos de comandos con acentos bien leídos (página de códigos OEM / UTF-8 en PowerShell); DNS primario y secundario bien leídos; DNS inverso en paralelo con límite de tiempo.
- Pestañas que salían cortadas, textos que faltaban en inglés (mensajes, registro del Panel, estados…) y el cambio de idioma ya no borra el texto dinámico.
- Defender: casilla «Lo desactivé a propósito» (tarjeta gris, no cuenta como problema). Sin ella: «Apagado», sin alarmismo.
- Donaciones: solo Binance (se quitaron Ko-fi y Liberapay).
- Se quitó la frase «100 % local»: OptiShield hace consultas DNS normales y, **solo si pulsas el botón**, pregunta a ipify.org / abre AbuseIPDB.

---

## ▶️ Cómo usar (desde el código)

1. Requiere **Python 3** (con «Add to PATH»). Sin dependencias externas.
2. Doble clic en **`OptiShield.bat`** — o `python OptiShield.py`.
3. Acepta el **UAC** (administrador) para poder aplicar cambios. Sin admin funciona en **modo solo-lectura**.
4. Pruebas sin tocar el sistema: `python tools/selftest.py` (debe decir `SELFTEST_OK`). Capturas: `python tools/shots.py [--scan] [--en]`.

> La base de datos de proxyware es ampliable sin recompilar: edita `data/proxyware_db.json` (junto al `.exe`).

---

## 📦 Distribución (ejecutable)

```
pip install pyinstaller
pyinstaller OptiShield.spec
```

El `.exe` queda en `dist\OptiShield.exe`. Copia la carpeta `data` junto al `.exe` si quieres poder editar la base de datos.

**Pestaña «TV» (ADB):** necesita `platform-tools` de Google. OptiShield lo busca junto a `OptiShield.exe`, en el PATH o en el SDK de Android.

**Notas honestas:**
- Los `.exe` de PyInstaller **pueden dar falso positivo** en algunos antivirus (escanea procesos, toca *hosts* y registro). Mitigación: subirlo a **VirusTotal** antes de publicar y, si es posible, **firmar el ejecutable**.
- Si aparece «*Failed to load Python DLL*» en otro PC: falta el **Visual C++ Redistributable** o se movió el `.exe` fuera de su carpeta.

---

## ⚠️ Alcance / límites honestos

- **No hace análisis de kernel/driver ni inspección de tráfico (MITM), a propósito:** un fallo en un driver es un pantallazo azul, un driver sin firmar exige debilitar Windows, y ver tráfico cifrado obliga a espiarte a ti mismo. La pestaña **Red** usa DNS inverso sin tocar tu tráfico.
- Las firmas se basan en nombres de proceso, servicios, carpetas y claves conocidas: un proxyware renombrado o nuevo puede no detectarse.
- La **limpieza del TV** usa **ADB**. Si el malware está en el **firmware de fábrica** (típico de Badbox), una app no lo quita.
- El **escaneo profundo** solo barre **tu propia subred** (/24).
- La **vigilancia** funciona **mientras la app está abierta** (no es un servicio, a propósito).
- «Neutralizar» **no borra archivos**; la desinstalación la decides tú.
- Copias y registros: `%ProgramData%\OptiShield\` (`backups\`, `logs\`, `config.json`).

## 🆚 OptiShield y el antivirus

Son cosas distintas. El antivirus caza *malware* conocido en tiempo real. OptiShield cubre lo que un antivirus suele dejar pasar porque «es legal» (proxyware, telemetría, nodos residenciales) y te da **control manual y reversible**. **OptiShield no sustituye a un antivirus**; tú decides si usas Defender, otro antivirus o ninguno.

---

**Apoyo:** gratis y sin anuncios. Estrella en GitHub o donación **solo por Binance** — Pay ID `1165745950` · USDT (BSC · BEP-20) `0xb6f6731a4ea87f8e1fd6f44f48b5bc4204571f08`.

✉ support@optisuite.app · 🌐 optisuite.app

© Enmanuel Gil · OptiSuite · OptiShield es gratuito. Si te ayuda, compártelo.
