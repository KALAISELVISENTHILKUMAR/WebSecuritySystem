@echo off
echo =========================================
echo Starting NEXAF Security Dashboard...
echo =========================================

echo 1. Starting Backend...
start cmd /k "title NEXAF Backend (API) && for /f "tokens=1,* delims==" %%a in (.env) do set %%a=%%b && python -m uvicorn backend.main:app --reload"

echo 2. Starting Frontend...
start cmd /k "title NEXAF Frontend (Web) && python -m http.server 5500 --directory frontend"

echo.
echo Waiting for servers to spin up...
timeout /t 3 /nobreak >nul

echo 3. Opening dashboard in your browser...
start http://127.0.0.1:5500/index.html

echo.
echo Done! You can close this window now. The servers are running in the other windows.
