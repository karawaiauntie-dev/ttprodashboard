@echo off
title TTPRO - Live Server + Public Link
color 0A
echo ================================================
echo    TTPRO - START SERVER + PUBLIC LINK
echo ================================================
echo.
cd /d "%~dp0"

REM Kill any old process on port 3000
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":3000" ^| findstr "LISTENING"') do (
    taskkill /PID %%a /F >nul 2>&1
)

REM Start the server in its own window
echo [1/3] Starting TTPRO server...
start "TTPRO-SERVER" cmd /k "node server.js"
timeout /t 4 /nobreak >nul

REM Start cloudflared tunnel, log to file
echo [2/3] Starting public tunnel... please wait up to 30 seconds
start /b cloudflared.exe tunnel --url http://localhost:3000 --no-autoupdate > tunnel.log 2>&1

echo [3/3] Waiting for your public link...
set URL=
for /l %%i in (1,1,30) do (
    timeout /t 1 /nobreak >nul
    for /f "delims=" %%u in ('findstr /r "trycloudflare" tunnel.log') do set "URL=%%u"
    if defined URL goto :found
)
echo.
echo WARNING: No link found yet. Check tunnel.log or wait longer.
goto :done

:found
echo.
echo ================================================
echo   YOUR PUBLIC LINK:
echo.
echo   %URL%
echo.
echo ================================================
echo   - Copy the link above - that is your backend link
echo   - Keep this window and TTPRO-SERVER window OPEN
echo   - Close this window to STOP the public link
echo ================================================
echo.

REM Try to copy the URL to clipboard automatically (clean, URL only)
for /f "usebackq delims=" %%u in (`powershell -NoProfile -Command "(Select-String -Path tunnel.log -Pattern 'https://[a-z0-9-]+.trycloudflare.com' -AllMatches).Matches.Value | Select-Object -First 1"`) do set "CLEANURL=%%u"
if defined CLEANURL (
    echo %CLEANURL%| clip
    echo (Link copied to clipboard - just press Ctrl+V to paste it!)
)

:done
echo.
echo Local app: http://localhost:3000
echo.
pause
