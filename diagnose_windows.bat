@echo off
setlocal EnableExtensions
chcp 65001 >nul
cd /d "%~dp0"
title Diagnosis BagoesWP OLS Manager

if not exist "logs" mkdir "logs"
set "LOG_FILE=%CD%\logs\diagnostic.txt"
set "HAS_ERROR=0"

>"%LOG_FILE%" echo BagoesWP Windows Diagnostic v0.2.7
>>"%LOG_FILE%" echo Waktu: %DATE% %TIME%
>>"%LOG_FILE%" echo Folder: %CD%
>>"%LOG_FILE%" echo.

where py >>"%LOG_FILE%" 2>&1
if not errorlevel 1 (
    py -3 --version >>"%LOG_FILE%" 2>&1
) else (
    where python >>"%LOG_FILE%" 2>&1
    if errorlevel 1 set "HAS_ERROR=1"
    python --version >>"%LOG_FILE%" 2>&1
    if errorlevel 1 set "HAS_ERROR=1"
)

if not exist ".venv\Scripts\python.exe" (
    >>"%LOG_FILE%" echo ERROR: .venv belum dibuat. Jalankan run_windows.bat.
    set "HAS_ERROR=1"
) else (
    >>"%LOG_FILE%" echo.
    >>"%LOG_FILE%" echo [VENV]
    ".venv\Scripts\python.exe" --version >>"%LOG_FILE%" 2>&1
    if errorlevel 1 set "HAS_ERROR=1"
    ".venv\Scripts\python.exe" -c "import tkinter; print('Tkinter OK:', tkinter.TkVersion)" >>"%LOG_FILE%" 2>&1
    if errorlevel 1 set "HAS_ERROR=1"
    ".venv\Scripts\python.exe" -c "import paramiko; print('Paramiko OK:', paramiko.__version__)" >>"%LOG_FILE%" 2>&1
    if errorlevel 1 set "HAS_ERROR=1"
    ".venv\Scripts\python.exe" -c "import cryptography, argon2.low_level; from importlib.metadata import version; print('PPK crypto OK:', cryptography.__version__, version('argon2-cffi'))" >>"%LOG_FILE%" 2>&1
    if errorlevel 1 set "HAS_ERROR=1"
    set "PYTHONPATH=%CD%\src"
    ".venv\Scripts\python.exe" -c "import bagoeswp.app; from bagoeswp.orchestrator import resource_path; p=resource_path('resources/remote_agent.py'); print('App import OK'); print('Remote agent:', p); assert p.is_file()" >>"%LOG_FILE%" 2>&1
    if errorlevel 1 set "HAS_ERROR=1"
)

>>"%LOG_FILE%" echo.
if exist "dist\BagoesWP-OLS-Manager.exe" (
    for %%F in ("dist\BagoesWP-OLS-Manager.exe") do >>"%LOG_FILE%" echo EXE ditemukan: %%~fF ^(%%~zF bytes^)
) else (
    >>"%LOG_FILE%" echo INFO: EXE belum ditemukan. Jalankan build_windows.bat.
)
if exist "%LOCALAPPDATA%\BagoesWP\logs\app.log" (
    >>"%LOG_FILE%" echo.
    >>"%LOG_FILE%" echo [APP LOG]
    type "%LOCALAPPDATA%\BagoesWP\logs\app.log" >>"%LOG_FILE%" 2>&1
)

cls
echo ============================================================
echo              HASIL DIAGNOSIS BAGOESWP
echo ============================================================
type "%LOG_FILE%"
echo.
if "%HAS_ERROR%"=="1" (
    echo Ada pemeriksaan yang gagal. Kirim file berikut kepada saya:
) else (
    echo Pemeriksaan dasar lulus. Jika aplikasi tetap tidak muncul, kirim file berikut:
)
echo "%LOG_FILE%"
echo.
pause
exit /b %HAS_ERROR%
