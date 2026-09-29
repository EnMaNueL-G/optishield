r"""Capturas de cada pestaña de OptiShield (solo lectura: no pulsa ningún botón que cambie el sistema).
Uso: python tools/shots.py [--scan] [--en]   → PNG en %USERPROFILE%\Salidas-Logs\optishield-ui
--scan ejecuta «Analizar todo» del Panel (solo escanea) antes de capturar."""
import os, sys, time, importlib.util
from PIL import ImageGrab

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("osh", os.path.join(HERE, "..", "OptiShield.py"))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
if "--en" in sys.argv: m.LANG = "en"
else: m.LANG = "es"
out = os.path.join(os.path.expanduser("~"), "Salidas-Logs", "optishield-ui"); os.makedirs(out, exist_ok=True)

app = m.OptiShield()
app.attributes("-topmost", True); app.geometry("1180x760+40+40")

def grab(name):
    app.update(); time.sleep(0.4); app.update()
    x, y = app.winfo_rootx(), app.winfo_rooty()
    ImageGrab.grab((x, y, x + app.winfo_width(), y + app.winfo_height())).save(os.path.join(out, name + ".png"))
    print("shot", name)

def run():
    if "--scan" in sys.argv and hasattr(app, "scan_all"):
        app.scan_all()
        for _ in range(240):            # hasta 2 min a que terminen los hilos de escaneo
            app.update(); time.sleep(0.5)
            if not getattr(app, "_busy", False) and _ > 20: break
    tabs = app.nb.tabs()
    suf = "-en" if "--en" in sys.argv else ""
    for i, t in enumerate(tabs):
        app.nb.select(t); grab(f"{i:02d}-{app.nb.tab(t, 'text').strip().split()[-1].lower()}{suf}")
    app.destroy()

app.after(800, run)
app.mainloop()
