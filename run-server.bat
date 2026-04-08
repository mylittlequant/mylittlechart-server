@echo off
REM Wrapper script: runs zengeld-server in a restart loop.
REM
REM Key trick: copies the binary to a versioned name before running,
REM so cargo can always overwrite target\release\zengeld-server.exe
REM without "access denied" — the running process uses the copy.
REM
REM Deploy: cargo build --release, then POST /api/admin/restart
REM To stop permanently: create file "data\stop-server" before restart.

cd /d "%~dp0"

set SOURCE_BINARY=target\release\zengeld-server.exe
set RUNNING_BINARY=target\release\zengeld-server-running.exe
set STOP_FILE=data\stop-server

:loop
if exist "%STOP_FILE%" (
    echo [wrapper] Stop file detected — exiting permanently.
    del "%STOP_FILE%" 2>nul
    exit /b 0
)

REM Copy binary so cargo can freely overwrite the original
copy /Y "%SOURCE_BINARY%" "%RUNNING_BINARY%" >nul 2>nul

echo [wrapper] Starting zengeld-server...
"%RUNNING_BINARY%"
echo [wrapper] Server exited with code %ERRORLEVEL%

REM Clean up the running copy
del "%RUNNING_BINARY%" 2>nul

if exist "%STOP_FILE%" (
    echo [wrapper] Stop file detected — exiting permanently.
    del "%STOP_FILE%" 2>nul
    exit /b 0
)

echo [wrapper] Restarting in 1 second...
timeout /t 1 /nobreak >nul
goto loop
