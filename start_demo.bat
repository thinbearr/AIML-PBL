@echo off
rem Starts the demo in the background (no window). Double-click to start; it keeps running until you log off or restart.
rem Open http://localhost:8000
cd /d "%~dp0"
start "" /b pythonw server.py 8000 --no-browser
start "" /b pythonw server.py 8080 --no-browser
