# 🛡️ OptiShield — by OptiSuite

Herramienta **gratuita** de escritorio (Windows) para **proteger tu privacidad y seguridad**:
detecta y neutraliza *proxyware* / participación en botnets residenciales (tipo **NetNut / Badbox**),
blinda la telemetría y la ubicación, audita el arranque y verifica la integridad del sistema.

**Principios:** defensiva · reversible · 100 % local (no envía tus datos a ningún servidor) ·
**nunca** debilita tu seguridad (no toca Windows Defender, Firewall ni UAC — solo informa de su estado).

---

## ✅ Qué hace

| Pestaña | Función |
|---|---|
| **🏠 Panel** | Semáforo general + «Analizar todo» en una pasada. |
| **🕵️ Anti-proxyware** | Detecta ~20 familias (Honeygain, IPRoyal Pawns, EarnApp/Bright Data, PacketStream, Peer2Profit, Traffmonetizer, Repocket, PacketShare, Proxyrack, 922proxy, Infatica, Asocks, Mysterium, Smartproxy, Oxylabs, Proxy-Cheap, Grasshopper, Hola VPN, NetNut SDK, VPN-gratis P2P…) por proceso, servicio, carpeta y registro. Sonda **SOCKS5** en puertos locales. Detecta **SDK embebido** (DLLs de proxyware cargadas en Chrome/Edge/Firefox/Spotify/Discord…). Distingue *instalado a propósito* de *oculto/sospechoso*. **Neutraliza** lo que marques: detiene procesos, deshabilita servicios, **bloquea dominios (hosts) y crea regla de firewall saliente** (reversible; no borra archivos). |
| **🌐 Red** | Conexiones activas; marca en rojo los procesos con **muchas** salidas (posible nodo). |
| **🏘️ Red local** | Dispositivos de tu red (ARP) con sondeo de **puertos de depuración** (5555 ADB, Telnet, FTP…) típicos de TV-box/IoT comprometidos por **Badbox**. Botón de **reputación de tu IP pública** (AbuseIPDB). Solo informa. |
| **🔒 Privacidad** | Casillas para **desactivar/revertir**: telemetría, ID de publicidad, ubicación, historial de actividad, experiencias personalizadas, contenido/anuncios sugeridos, búsqueda web/Bing en Inicio, etc. **Con copia de seguridad** previa. |
| **🧹 Arranque** | Programas y tareas que arrancan con Windows; marca en rojo lo sospechoso (Temp, comandos ofuscados). |
| **🛡️ Integridad** | Proxy del sistema, DNS, archivo *hosts* y **dominios IOC**. Quitar bloqueos de hosts y **reglas de firewall** de OptiShield. Exportar informe. |
| **💬 Apoyo OptiSuite** | Contacto y soporte. |

**Vigilancia continua (opcional):** casilla en el Panel que cada 15 min revisa si arranca proxyware y te avisa.

---

## ▶️ Cómo usar (desde el código)

1. Requiere **Python 3** (con «Add to PATH»).
2. Doble clic en **`OptiShield.bat`** — o `python OptiShield.py`.
3. Acepta el **UAC** (administrador) para poder aplicar cambios. Sin admin funciona en **modo solo-lectura**.

> La base de datos de proxyware es ampliable sin recompilar: edita `data/proxyware_db.json`.

---

## 📦 Distribución en la web (ejecutable)

Para que cualquier usuario lo use **sin instalar Python**, se empaqueta a `.exe`:

```
pip install pyinstaller
pyinstaller --onefile --windowed --name OptiShield --add-data "data;data" OptiShield.py
```

El `.exe` queda en `dist\OptiShield.exe`.

**Notas honestas (importante):**
- Los `.exe` empaquetados con PyInstaller **pueden dar falso positivo** en algunos antivirus (por escanear procesos, tocar *hosts* y registro). Mitigación: subirlo a **VirenTotal** antes de publicar, documentarlo, y (opcional) **firmar el ejecutable** con un certificado de código.
- Si aparece «*Failed to load Python DLL*» en otro PC: falta el **Visual C++ Redistributable** o se movió el `.exe` fuera de su carpeta. Esta app se hizo **sin dependencias externas** justo para minimizar ese problema.

---

## ⚠️ Alcance / límites honestos

- **No** hace análisis a nivel kernel/driver ni inspección de tráfico con WinDivert (fuera de alcance: riesgo de BSOD/complejidad).
- El escáner de red doméstica sondea puertos de depuración de los dispositivos **ya vistos en la tabla ARP**; no hace barrido activo de toda la subred (menos intrusivo).
- La vigilancia continua funciona **mientras la app está abierta** (no es un servicio de Windows, a propósito: más simple y fácil de quitar).
- «Neutralizar» **no borra archivos**: detiene, deshabilita, bloquea dominios y crea regla de firewall. La desinstalación completa la decides tú.
- Todo cambio de privacidad/red guarda copia en `%ProgramData%\OptiShield\backups` y es **reversible**.

© OptiSuite · OptiShield es gratuito. Si te ayuda, compártelo.
