@echo off
title OptiShield - by OptiSuite
cd /d "%~dp0"
rem Lanzador de OptiShield (pide admin automaticamente desde la propia app)
where pythonw >nul 2>&1
if %errorlevel%==0 (
  start "" pythonw "%~dp0OptiShield.py"
) else (
  where python >nul 2>&1
  if %errorlevel%==0 (
    start "" python "%~dp0OptiShield.py"
  ) else (
    echo No se encontro Python. Instala Python 3 desde python.org y marca "Add to PATH".
    pause
  )
)
