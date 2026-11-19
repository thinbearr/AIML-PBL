@echo off
rem Starts the demo website. server.py is both the backend (API) and the frontend (serves web\).
rem Usage: start.bat [port]      default port 8000. Close this window or press Ctrl+C to stop.
setlocal
cd /d "%~dp0"
set "PORT=%~1"
if "%PORT%"=="" set "PORT=8000"

where python >nul 2>&1 || (echo [error] Python not found on PATH. & pause & exit /b 1)

python -c "import numpy, pandas, scipy, sklearn, pyarrow, joblib, yaml, networkx" >nul 2>&1
if errorlevel 1 (
    echo [setup] Installing Python dependencies...
    python -m pip install -r requirements.txt || (echo [error] pip install failed. & pause & exit /b 1)
)

if not exist "data\processed\model.joblib" (
    echo [setup] Model files missing - running the pipeline first, about 10 minutes...
    python run_pipeline.py || (echo [error] Pipeline failed. & pause & exit /b 1)
)

rem Stop any old demo server (server.py, e.g. left over from start_demo.bat) still holding the port,
rem then use the first port from %PORT% upward that nothing else is listening on.
for /f %%p in ('powershell -NoProfile -Command ^
  "$p=%PORT%; foreach($c in @(Get-NetTCPConnection -LocalPort $p -State Listen -EA SilentlyContinue)){ $pr=Get-CimInstance Win32_Process -Filter ('ProcessId='+$c.OwningProcess); if($pr.CommandLine -match 'server\.py'){ Stop-Process -Id $pr.ProcessId -Force; Write-Host ('[info] Stopped old demo server, PID '+$pr.ProcessId) -Fore Yellow } }; Start-Sleep -Milliseconds 500; while(Get-NetTCPConnection -LocalPort $p -State Listen -EA SilentlyContinue){ $p++ }; $p"') do set "PORT=%%p"

title AIML-PBL demo - http://127.0.0.1:%PORT%
echo Starting backend + frontend at http://127.0.0.1:%PORT%  (browser opens when it is ready)
python server.py %PORT%
echo.
echo Server stopped.
pause
