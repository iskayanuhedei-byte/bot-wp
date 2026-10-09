@echo off
setlocal EnableExtensions
chcp 65001 >nul
cd /d "%~dp0"
title BagoesWP OLS Manager - Launcher

if not exist "logs" mkdir "logs"
set "LOG_FILE=%CD%\logs\launcher.log"
>"%LOG_FILE%" echo BagoesWP launcher dimulai: %DATE% %TIME%

echo ============================================================
echo              BagoesWP OLS Manager v0.2.7
echo ============================================================
echo.
echo [1/5] Mencari Python 3.11 atau lebih baru...
call :find_python
if errorlevel 1 (
    set "FAIL_REASON=Python 3.11+ tidak ditemukan. Instal Python dari python.org dan centang Add Python to PATH."
    goto :failed
)
%PY_CMD% --version
%PY_CMD% --version >>"%LOG_FILE%" 2>&1

echo [2/5] Memeriksa virtual environment...
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -c "import sys; raise SystemExit(0 if sys.version_info.major == 3 and sys.version_info.minor in range(11, 16) else 1)" >nul 2>&1
    if errorlevel 1 (
        echo Virtual environment rusak atau terlalu lama. Membuat ulang...
        rmdir /s /q ".venv"
    )
)
if not exist ".venv\Scripts\python.exe" (
    %PY_CMD% -m venv ".venv" >>"%LOG_FILE%" 2>&1
    if errorlevel 1 (
        set "FAIL_REASON=Gagal membuat virtual environment."
        goto :failed
    )
)

echo [3/5] Memeriksa dependency aplikasi...
".venv\Scripts\python.exe" -c "import paramiko, cryptography, argon2.low_level; from importlib.metadata import version; raise SystemExit(0 if paramiko.__version__ == '5.0.0' and cryptography.__version__ == '50.0.2' and version('argon2-cffi') == '25.1.0' else 1)" >nul 2>&1
if errorlevel 1 (
    echo Dependency belum lengkap. Mengunduh dependency SSH dan PPK...
    ".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r "requirements-runtime.txt"
    if errorlevel 1 (
        set "FAIL_REASON=Gagal memasang dependency. Periksa internet, antivirus, atau firewall Windows."
        goto :failed
    )
)

echo [4/5] Memeriksa Tkinter dan modul aplikasi...
set "PYTHONPATH=%CD%\src"
".venv\Scripts\python.exe" -c "import tkinter; import bagoeswp.app; from bagoeswp.orchestrator import resource_path; assert resource_path('resources/remote_agent.py').is_file()" >>"%LOG_FILE%" 2>&1
if errorlevel 1 (
    set "FAIL_REASON=Tkinter atau modul aplikasi gagal dimuat."
    goto :failed
)

echo [5/5] Membuka aplikasi...
echo Jika jendela belum terlihat, periksa taskbar atau tekan Alt+Tab.
".venv\Scripts\python.exe" -m bagoeswp.app >>"%LOG_FILE%" 2>&1
if errorlevel 1 (
    set "FAIL_REASON=Aplikasi berhenti karena error saat dijalankan."
    goto :failed
)
exit /b 0

:find_python
set "PY_CMD="
py -3 -c "import sys; raise SystemExit(0 if sys.version_info.major == 3 and sys.version_info.minor in range(11, 16) else 1)" >nul 2>&1
if not errorlevel 1 set "PY_CMD=py -3"
if defined PY_CMD exit /b 0
python -c "import sys; raise SystemExit(0 if sys.version_info.major == 3 and sys.version_info.minor in range(11, 16) else 1)" >nul 2>&1
if not errorlevel 1 set "PY_CMD=python"
if defined PY_CMD exit /b 0
exit /b 1

:failed
echo.
echo ============================================================
echo GAGAL: %FAIL_REASON%
echo ============================================================
echo Log: "%LOG_FILE%"
echo.
if exist "%LOG_FILE%" type "%LOG_FILE%"
echo.
echo Jalankan diagnose_windows.bat jika masalah masih terjadi.
pause
exit /b 1
