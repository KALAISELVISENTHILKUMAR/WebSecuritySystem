@echo off
echo =========================================
echo NEXAF Cloud AI Configuration
echo =========================================
echo.
set /p key="Enter your NVIDIA API Key: "
if "%key%"=="" goto end

echo AI_API_KEY=%key% > .env
echo AI_PROVIDER=openai-compatible >> .env
echo AI_API_BASE=https://integrate.api.nvidia.com/v1 >> .env
echo AI_MODEL=meta/llama-3.1-70b-instruct >> .env
echo DEMO_MODE=0 >> .env
echo.
echo [SUCCESS] Saved API Key to .env! NEXAF will now use the Cloud AI.
echo Please restart the backend (start_dashboard.bat) for changes to take effect.
echo.
pause
goto :eof

:end
echo Setup skipped.
pause
