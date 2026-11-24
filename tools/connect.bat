@echo off
REM ============================================================
REM  BambooSense - connexion a l'imprimante (double-clic)
REM  Verifie Python, installe cryptography + paho-mqtt,
REM  puis lance le script de pilotage de la P2S.
REM ============================================================
setlocal
cd /d "%~dp0"

echo.
echo === BambooSense - connexion imprimante ===
echo.

set PY=
where py >nul 2>nul && set PY=py
if not defined PY where python >nul 2>nul && set PY=python

if not defined PY (
  echo [!] Python n'est pas installe.
  echo     https://www.python.org/downloads/  ^(coche "Add Python to PATH"^)
  echo.
  pause
  exit /b 1
)

%PY% -c "import cryptography, paho.mqtt.client" >nul 2>nul
if errorlevel 1 (
  echo [*] Installation des dependances ^(cryptography + paho-mqtt^)...
  %PY% -m pip install --user cryptography paho-mqtt
  if errorlevel 1 (
    echo [!] Installation echouee. Tape : pip install cryptography paho-mqtt
    pause
    exit /b 1
  )
)

%PY% "%~dp0keyforge_connect.py" %*

echo.
pause
endlocal
