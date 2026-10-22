@echo off
cd /d "%~dp0"
echo Starting PhishShield backend on http://127.0.0.1:8000
if exist "..\..\.venv\Scripts\python.exe" (
  "..\..\.venv\Scripts\python.exe" -m uvicorn main:app --host 127.0.0.1 --port 8000
) else (
  python -m uvicorn main:app --host 127.0.0.1 --port 8000
)
echo.
echo Backend stopped. Press any key to close.
pause >nul