@echo off
setlocal
cd /d "%~dp0"
echo ==========================================
echo          ThreatLens automatic setup
echo ==========================================
where py >nul 2>nul
if %errorlevel%==0 (set PY=py) else (set PY=python)
%PY% --version
if errorlevel 1 (
  echo Python 3.10 or newer was not found. Install Python from https://www.python.org/downloads/
  echo During installation, enable "Add Python to PATH".
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  echo [1/3] Creating isolated Python environment...
  %PY% -m venv .venv
  if errorlevel 1 goto :error
)
echo [2/3] Installing required packages...
".venv\Scripts\python.exe" -m pip install --upgrade pip
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto :error
echo [3/3] Starting ThreatLens. The database and synthetic data initialize automatically.
".venv\Scripts\python.exe" run.py
goto :eof
:error
echo Setup failed. Check the error above and verify internet access for package installation.
pause
exit /b 1
