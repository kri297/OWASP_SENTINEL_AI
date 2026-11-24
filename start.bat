@echo off
echo ============================================
echo   OWASP Sentinel AI - Starting Services
echo ============================================
echo.

echo [1/2] Starting Backend Server...
cd backend
start "OWASP Sentinel AI - Backend" cmd /k "if exist .venv\Scripts\activate.bat (call .venv\Scripts\activate.bat) & python app.py"
cd ..

echo [2/2] Starting Frontend Dev Server...
cd frontend
start "OWASP Sentinel AI - Frontend" cmd /k "npm run dev"
cd ..

echo.
echo ============================================
echo   Services Starting...
echo   Backend:  http://localhost:5000
echo   Frontend: http://localhost:5173
echo ============================================
echo.
pause
