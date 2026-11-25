@echo off
REM ============================================================
REM  BambooSense - recupere la cle Studio partagee (double-clic)
REM  Extrait slicer_key.pem de Bambu Studio EN COURS d'execution,
REM  puis lance le pilotage de l'imprimante.
REM ============================================================
setlocal
cd /d "%~dp0"

echo.
echo === Extraction de la cle Studio partagee ===
echo.
echo  Prerequis : Bambu Studio doit etre LANCE et CONNECTE a ton compte.
echo.
pause

set PY=
where py >nul 2>nul && set PY=py
if not defined PY where python >nul 2>nul && set PY=python
if not defined PY (
  echo [!] Python n'est pas installe. https://www.python.org/downloads/
  pause & exit /b 1
)

%PY% -c "import cryptography" >nul 2>nul || %PY% -m pip install --user cryptography

%PY% "%~dp0extract_studio_key.py" --out-dir "%~dp0"
if errorlevel 1 (
  echo.
  echo [!] Extraction echouee. Verifie que Bambu Studio est lance + connecte.
  echo     Si besoin, relance cette fenetre en tant qu'Administrateur.
  pause & exit /b 1
)

echo.
echo [OK] Cle extraite. Lancement du pilotage de l'imprimante...
echo.
call "%~dp0connect.bat"

endlocal
