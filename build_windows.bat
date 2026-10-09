@echo off
setlocal EnableExtensions
chcp 65001 >nul
cd /d "%~dp0"
title BagoesWP OLS Manager - Build EXE

if not exist "logs" mkdir "logs"
set "LOG_FILE=%CD%\logs\build.log"
>"%LOG_FILE%" echo BagoesWP build dimulai: %DATE% %TIME%

echo ============================================================
echo          Build BagoesWP OLS Manager v0.2.7
echo ============================================================
echo.
echo [1/4] Mencari Python 3.11 atau lebih baru...
call :find_python
if errorlevel 1 (
    set "FAIL_REASON=Python 3.11+ tidak ditemukan. Instal Python dari python.org dan centang Add Python to PATH."
    goto :failed
)
%PY_CMD% --version
%PY_CMD% --version >>"%LOG_FILE%" 2>&1

echo [2/4] Menyiapkan virtual environment...
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

echo [3/4] Memasang dependency build jika diperlukan...
".venv\Scripts\python.exe" -c "import paramiko, PyInstaller, cryptography, argon2.low_level; from importlib.metadata import version; raise SystemExit(0 if paramiko.__version__ == '5.0.0' and PyInstaller.__version__ == '6.22.2' and cryptography.__version__ == '50.0.2' and version('argon2-cffi') == '25.1.0' else 1)" >nul 2>&1
if errorlevel 1 (
    ".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r "requirements.txt"
    if errorlevel 1 (
        set "FAIL_REASON=Gagal memasang dependency build. Periksa koneksi internet."
        goto :failed
    )
)

echo [4/4] Membuat file EXE. Mohon tunggu, proses dapat beberapa menit...
set "PYTHONPATH=%CD%\src"
".venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean --onefile --windowed ^
  --name BagoesWP-OLS-Manager ^
  --paths "%CD%\src" ^
  --collect-all argon2 ^
  --collect-all _argon2_cffi_bindings ^
  --add-data "%CD%\src\bagoeswp\resources\remote_agent.py;bagoeswp\resources" ^
  "%CD%\src\bagoeswp\app.py" >>"%LOG_FILE%" 2>&1
if errorlevel 1 (
    set "FAIL_REASON=PyInstaller gagal membuat EXE."
    goto :failed
)
if not exist "dist\BagoesWP-OLS-Manager.exe" (
    set "FAIL_REASON=Build selesai tetapi file EXE tidak ditemukan."
    goto :failed
)

echo.
echo Build berhasil: "%CD%\dist\BagoesWP-OLS-Manager.exe"
echo Membuka aplikasi hasil build...
start "" "%CD%\dist\BagoesWP-OLS-Manager.exe"
if errorlevel 1 (
    set "FAIL_REASON=EXE berhasil dibuat tetapi tidak dapat dibuka."
    goto :failed
)
echo Aplikasi sudah diperintahkan untuk terbuka. Periksa taskbar atau Alt+Tab.
timeout /t 4 /nobreak >nul
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
echo BUILD GAGAL: %FAIL_REASON%
echo ============================================================
echo Log: "%LOG_FILE%"
echo.
if exist "%LOG_FILE%" type "%LOG_FILE%"
echo.
echo Jalankan diagnose_windows.bat jika masalah masih terjadi.
pause
exit /b 1
