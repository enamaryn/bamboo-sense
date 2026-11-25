@echo off
REM ============================================================
REM  BambooSense Keyforge - lanceur Windows (double-clic)
REM  Verifie Python, installe "cryptography" si besoin,
REM  puis lance le script qui ecrit la cle sur ta cle USB.
REM ============================================================
setlocal
cd /d "%~dp0"

echo.
echo === BambooSense Keyforge ===
echo.

REM -- trouver Python (py launcher d'abord, sinon python) --
set PY=
where py >nul 2>nul && set PY=py
if not defined PY where python >nul 2>nul && set PY=python

if not defined PY (
  echo [!] Python n'est pas installe.
  echo     Installe-le depuis https://www.python.org/downloads/
  echo     ^(coche "Add Python to PATH" pendant l'installation^)
  echo.
  pause
  exit /b 1
)

REM -- s'assurer que "cryptography" est present --
%PY% -c "import cryptography" >nul 2>nul
if errorlevel 1 (
  echo [*] Installation de la dependance "cryptography"...
  %PY% -m pip install --user cryptography
  if errorlevel 1 (
    echo [!] L'installation a echoue. Lance manuellement : pip install cryptography
    pause
    exit /b 1
  )
)

REM -- lancer le script (passe tous les arguments eventuels) --
%PY% "%~dp0keyforge_usb.py" %*

echo.
pause
endlocal
