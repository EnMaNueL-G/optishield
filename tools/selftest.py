# -*- coding: utf-8 -*-
r"""Autotest de OptiShield SIN tocar el sistema.
Solo escribe en HKCU\Software\OptiShieldTest (se borra al terminar) y en una carpeta temporal.
Uso: python tools/selftest.py   → imprime SELFTEST_OK si todo pasa."""
import os, sys, json, socket, tempfile, threading, shutil, importlib.util, winreg

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = next(p for p in (os.path.join(HERE, "..", "OptiShield.py"), os.path.join(HERE, "..", "fuente", "OptiShield.py")) if os.path.exists(p))  # proyecto o repo
spec = importlib.util.spec_from_file_location("osh", SRC)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

TEST_KEY = "Software\\OptiShieldTest"
TMP = tempfile.mkdtemp(prefix="optishield_selftest_")
fails = []

def check(cond, what):
    print(("  ok   " if cond else "  FAIL ") + what)
    if not cond: fails.append(what)

def delete_tree(root, path):
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_ALL_ACCESS) as k:
            while True:
                try: sub = winreg.EnumKey(k, 0)
                except OSError: break
                delete_tree(root, path + "\\" + sub)
        winreg.DeleteKey(root, path)
    except FileNotFoundError: pass

def main():
    # --- A: obsoletos ---
    print("[A] _is_orphan / orphan_state")
    check(m._is_orphan("ctfmon.exe") is False, "ctfmon.exe no es obsoleto")
    check(m.orphan_state("ctfmon.exe") == "ok", "ctfmon.exe se resuelve (System32)")
    check(m._is_orphan("rundll32 shell32.dll,Control_RunDLL desk.cpl") is False, "rundll32 shell32.dll,… no es obsoleto")
    check(m._is_orphan("wscript.exe //B x.vbs") is False, "wscript.exe //B x.vbs no es obsoleto")
    check(m._is_orphan(r'"C:\NoExiste_OptiShield\zzz\app.exe" --x') is True, "ruta absoluta inexistente = obsoleto")
    check(m._is_orphan(r"C:\NoExiste_OptiShield\zzz\app.exe /min") is True, "ruta absoluta sin comillas inexistente = obsoleto")
    check(m.orphan_state("programa_que_no_existe_zz9.exe") == "unknown", "nombre sin ruta no encontrado = desconocido")
    check(m.orphan_state(r"%windir%\system32\SecurityHealthSystray.exe") == "ok", "%windir% se expande")
    check(m.orphan_state(r"C:\Program") == "unknown", "ruta cortada sin extensión = desconocido (nunca obsoleto)")
    check(not m.is_suspicious_cmd('powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\\x.ps1"'), "-ExecutionPolicy no se confunde con -enc")
    check(m.is_suspicious_cmd("powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi"), "PowerShell con comando codificado = sospechoso")

    # --- registro: copia exacta y restauración ---
    print("[B] copia/restauración de registro en HKCU\\" + TEST_KEY)
    delete_tree(winreg.HKEY_CURRENT_USER, TEST_KEY)
    m.reg_set("HKCU", TEST_KEY, "Expand", "REG_EXPAND_SZ", r"%windir%\x.exe")
    s1 = m.reg_snapshot("HKCU", TEST_KEY, "Expand"); s2 = m.reg_snapshot("HKCU", TEST_KEY, "NoExistia")
    m.reg_set("HKCU", TEST_KEY, "Expand", "REG_SZ", "cambiado"); m.reg_set("HKCU", TEST_KEY, "NoExistia", "REG_DWORD", 1)
    m.reg_restore(s1); m.reg_restore(s2)
    ex, t, v = m.reg_get("HKCU", TEST_KEY, "Expand")
    check(ex and t == winreg.REG_EXPAND_SZ and v == r"%windir%\x.exe", "REG_EXPAND_SZ conserva tipo y dato")
    check(m.reg_get("HKCU", TEST_KEY, "NoExistia")[0] is False, "valor que no existía se borra al restaurar")
    json.dumps([s1, s2])  # la copia debe ser serializable

    # privacidad con ajustes de prueba (sin servicios)
    tweaks = [{"id": "t1", "name": "prueba 1", "reg": [("HKCU", TEST_KEY + "\\Priv", "A", "dword", 1, 0),
                                                       ("HKCU", TEST_KEY + "\\Priv", "B", "sz", "Allow", "Deny")]},
              {"id": "t2", "name": "prueba 2", "reg": [("HKCU", TEST_KEY + "\\Priv", "C", "dword", 1, 0)]}]
    m.reg_set("HKCU", TEST_KEY + "\\Priv", "B", "REG_EXPAND_SZ", "%USERPROFILE%")   # B existía (tipo raro), A no
    sf = os.path.join(TMP, "privacy_state.json")
    m.privacy_apply(["t1"], tweaks, sf, TMP, do_services=False)
    check(m.reg_read("HKCU", TEST_KEY + "\\Priv", "A") == 0 and m.reg_read("HKCU", TEST_KEY + "\\Priv", "B") == "Deny", "aplicar privacidad escribe valores privados")
    st = m.privacy_status(tweaks, sf)
    check(st["t1"][0] == "applied" and st["t2"][0] == "default", "estado: solo t1 aplicado (t2 no se marca para revertir)")
    m.privacy_apply(["t1"], tweaks, sf, TMP, do_services=False)   # 2ª vez: NO debe pisar la copia original
    nreg, nsvc, fl, nocopy = m.privacy_revert(["t1", "t2"], tweaks, sf, do_services=False)
    check(m.reg_get("HKCU", TEST_KEY + "\\Priv", "A")[0] is False, "revertir: A (no existía) se borra")
    ex, t, v = m.reg_get("HKCU", TEST_KEY + "\\Priv", "B")
    check(ex and t == winreg.REG_EXPAND_SZ and v == "%USERPROFILE%", "revertir: B vuelve con su tipo y dato originales")
    check(nocopy == ["prueba 2"] and m.reg_get("HKCU", TEST_KEY + "\\Priv", "C")[0] is False, "revertir sin copia: no se toca y se informa")

    # arranque: borrar y restaurar, desactivar y restaurar (StartupApproved de prueba)
    print("[A/E] arranque: copia y restauración")
    run_path = TEST_KEY + "\\Run"; sa_path = TEST_KEY + "\\StartupApproved\\Run"
    m.reg_set("HKCU", run_path, "App1", "REG_EXPAND_SZ", r'"%ProgramFiles%\NoExiste\app1.exe" /min')
    item = {"type": "Run", "name": "App1", "hive": "HKCU", "regpath": run_path, "sa": ["HKCU", sa_path], "cmd": "", "enabled": True}
    res, bk = m.startup_delete([item], TMP)
    check(res[0][1] and m.reg_get("HKCU", run_path, "App1")[0] is False, "eliminar entrada Run")
    d = json.load(open(bk, encoding="utf-8"))
    check(d["items"][0]["snap"]["type"] == "REG_EXPAND_SZ", "la copia guarda el TIPO de valor")
    m.startup_restore(bk)
    ex, t, v = m.reg_get("HKCU", run_path, "App1")
    check(ex and t == winreg.REG_EXPAND_SZ and v.startswith('"%ProgramFiles%'), "restaurar: vuelve con REG_EXPAND_SZ")
    res, bk2 = m.startup_set_enabled([item], False, TMP)
    check(res[0][1] and m.startup_enabled("HKCU", sa_path, "App1") is False, "desactivar vía StartupApproved")
    m.startup_restore(bk2)
    check(m.reg_get("HKCU", sa_path, "App1")[0] is False and m.startup_enabled("HKCU", sa_path, "App1"), "restaurar: StartupApproved vuelve a no existir (activado)")
    ro = dict(item, type="RunOnce", sa=None)
    res, _ = m.startup_set_enabled([ro], False, TMP)
    check(res[0][1] is False, "RunOnce: desactivar se rechaza con explicación")

    # --- I: ids duplicados ---
    print("[I] deduplicado / OEM")
    fs = [{"id": "sdk_chrome_netnut", "evidence": [["DLL", "a.dll"]], "procs": [], "domains": []},
          {"id": "sdk_chrome_netnut", "evidence": [["DLL", "b.dll"]], "procs": [], "domains": []},
          {"id": "socks5_9050", "evidence": [["puerto", "x"]]}]
    dd = m.dedupe_findings(fs)
    check(len(dd) == 2 and len(dd[0]["evidence"]) == 2, "ids duplicados se fusionan")
    enc = m.OEM_ENC
    check(m.decode_oem("Configuración IP ñ".encode(enc), enc) == "Configuración IP ñ", "decodificación OEM (%s)" % enc)
    rc, out, err = m.run_ex(["cmd", "/c", "echo", "hola"])
    check(rc == 0 and "hola" in out, "run_ex devuelve código y texto")
    check("OK_UTF8_ñ" in m.ps("Write-Output 'OK_UTF8_ñ'"), "PowerShell en UTF-8")

    # --- G: clasificación ---
    print("[G] clasificación (falsos positivos)")
    base = os.path.join(TMP, "pf")
    for sub in ("Smartproxy", "IPRoyal", "Honeygain", "Grasshopper", "Decodo"): os.makedirs(os.path.join(base, sub))
    fs = {f["id"]: f for f in m.scan_proxyware(procs=[], svcs={}, dirs=[base], include_ports=False, include_sdk=False)}
    check(fs.get("smartproxy_decodo", {}).get("cat") == "paid" and fs["smartproxy_decodo"]["risk"] == "info", "carpeta Smartproxy/Decodo = informativo")
    check(fs.get("iproyal", {}).get("cat") == "paid" and not fs["iproyal"]["domains"], "carpeta IPRoyal = informativo (sin bloquear dominios)")
    check(fs.get("honeygain", {}).get("cat") == "proxyware" and m.is_problem(fs["honeygain"]), "Honeygain = proxyware")
    check(not m.is_problem(fs["honeygain"], {"honeygain"}), "Honeygain permitido no cuenta como problema")
    check(not any("Grasshopper" in m.finding_evidence(f) for f in fs.values()), "carpeta Grasshopper (Rhino) no se detecta")
    procs = [{"pid": "10", "name": "tm.exe", "path": r"C:\Tools\tm.exe"}]
    check("traffmonetizer" not in {f["id"] for f in m.scan_proxyware(procs=procs, svcs={}, dirs=[], include_ports=False, include_sdk=False)}, "tm.exe fuera de su carpeta NO cuenta")
    procs = [{"pid": "10", "name": "tm.exe", "path": r"C:\Program Files\Traffmonetizer\tm.exe"}]
    f2 = {f["id"]: f for f in m.scan_proxyware(procs=procs, svcs={}, dirs=[], include_ports=False, include_sdk=False)}
    check("traffmonetizer" in f2 and f2["traffmonetizer"]["running"], "tm.exe dentro de Traffmonetizer\\ SÍ cuenta")
    check(m.classify_package("com.foo.proxyapp", "com.android.vending") == "revisar", "TV: 'proxy' en el nombre = revisar (no ALTO)")
    check(m.classify_package("com.triada.x", "com.android.vending") == "ALTO", "TV: familia conocida = ALTO")

    # SOCKS5 local en 127.0.0.1 = informativo
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1); port = srv.getsockname()[1]
    def serve():
        try:
            c, _ = srv.accept(); c.recv(3); c.sendall(b"\x05\x00"); c.close()
        except Exception: pass
    threading.Thread(target=serve, daemon=True).start()
    check(m._is_socks5(port), "handshake SOCKS5 detectado")
    srv.close()
    sf_ = m.socks_finding(port, {"127.0.0.1"}, "1234", "tor.exe")
    check(sf_["cat"] == "socks_local" and sf_["risk"] == "info" and not m.is_problem(sf_), "SOCKS5 en 127.0.0.1 = informativo (Tor)")
    check("Tor" in m.finding_name(sf_), "nombra el programa dueño del puerto")
    sf2 = m.socks_finding(port, {"0.0.0.0"}, "1234", "x.exe")
    check(sf2["cat"] == "socks_lan" and m.is_problem(sf2), "SOCKS5 abierto a la red = revisar")

    # red: por PID con exclusiones; 'vpn' no marca riesgo
    conns = [{"pid": "1", "proc": "chrome.exe", "kind": ""}] * 30 + [{"pid": "2", "proc": "chrome.exe", "kind": ""}] * 30
    conns = [dict(c) for c in conns] + [dict(pid="3", proc="raro.exe", kind="") for _ in range(30)]
    conns += [dict(pid="4", proc="a.exe", kind="vpn"), dict(pid="5", proc="b.exe", kind="proxyware")]
    m.flag_connections(conns)
    check(not any(c["flag"] for c in conns if c["proc"] == "chrome.exe"), "navegador con muchas conexiones no se marca")
    check(all(c["flag"] for c in conns if c["pid"] == "3"), "programa desconocido con 30 conexiones (mismo PID) se marca")
    check(not conns[-2]["flag"] and conns[-2]["info"] and conns[-1]["flag"], "'vpn' solo = informativo; red de proxyware = rojo")
    check(m.classify_host("nl-ams.vpn.example.net")[0] == "vpn" and m.classify_host("gate.decodo.com")[0] == "proxy", "clasificación de hosts")

    # --- D: hosts en archivo de prueba (codificación ANSI conservada) ---
    print("[D] hosts (archivo de prueba)")
    hp = os.path.join(TMP, "hosts")
    orig = "# Comentario con eñe y acentos: año\r\n127.0.0.1 localhost\r\n"
    open(hp, "wb").write(orig.encode("cp1252"))
    added, bkp = m.hosts_block(["honeygain.com"], hp, TMP)
    raw = open(hp, "rb").read()
    check(len(added) == 2 and b"0.0.0.0 honeygain.com # OptiShield\r\n" in raw and "eñe".encode("cp1252") in raw, "hosts: añade líneas y conserva ANSI/CRLF")
    check(open(bkp, "rb").read() == orig.encode("cp1252"), "hosts: copia previa idéntica")
    check(m.hosts_block(["honeygain.com"], hp, TMP)[0] == [], "hosts: no duplica")
    n, _ = m.hosts_remove(added, hp, TMP)
    check(n == 2 and open(hp, "rb").read() == orig.encode("cp1252"), "hosts: quitar deja el archivo como estaba")

    # --- C: neutralizar/deshacer en seco (sin procesos, servicios ni firewall; hosts de prueba; sin vaciar DNS) ---
    print("[C] neutralizar / deshacer (en seco)")
    real_flush = m.flush_dns; m.flush_dns = lambda: True
    try:
        fake = {"id": "honeygain", "name": "Honeygain", "cat": "proxyware", "procs": [], "svcs": [], "folders": [], "domains": ["honeygain.com"]}
        lines, bkn = m.neutralize([fake], backup_dir=TMP, hosts_path=hp)
        keys = [k for k, a in lines]
        check("• Sin ruta de programa conocida: no se creó regla de firewall." in keys, "sin ruta: lo dice y NO crea regla")
        check(b"honeygain.com # OptiShield" in open(hp, "rb").read(), "neutralizar bloquea dominios en hosts (prueba)")
        check(m.last_neutralize_backup(TMP) == bkn, "copia de neutralización localizable")
        m.undo_neutralize(bkn, hosts_path=hp, backup_dir=TMP)
        check(open(hp, "rb").read() == orig.encode("cp1252") and m.last_neutralize_backup(TMP) is None, "deshacer quita las líneas y marca la copia como deshecha")
        check(m.kill_pid_if_path(999999, r"C:\x\y.exe")[0] == "gone", "PID inexistente: no se mata nada")
    finally:
        m.flush_dns = real_flush

    # --- i18n ---
    print("[M] i18n")
    m.LANG = "en"
    check(m.fmt("Tu IP pública: %s", ("1.2.3.4",)) == "Your public IP: 1.2.3.4", "fmt traduce y formatea")
    check(str(m.L("Apagado (a propósito)")) == "Off (on purpose)", "texto perezoso L() traduce")
    m.LANG = "es"
    check("100%%" not in open(SRC, encoding="utf-8").read(), "sin '100%%' en el código")

def cleanup():
    delete_tree(winreg.HKEY_CURRENT_USER, TEST_KEY)
    shutil.rmtree(TMP, ignore_errors=True)
    try:
        winreg.OpenKey(winreg.HKEY_CURRENT_USER, TEST_KEY); print("  FAIL limpieza HKCU"); fails.append("cleanup")
    except FileNotFoundError:
        print("  ok   HKCU\\%s borrado" % TEST_KEY)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback; traceback.print_exc(); fails.append("excepción: %r" % e)
    finally:
        cleanup()
    if fails:
        print("SELFTEST_FAIL (%d): %s" % (len(fails), "; ".join(fails))); sys.exit(1)
    print("SELFTEST_OK")
