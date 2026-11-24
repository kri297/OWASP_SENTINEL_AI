# ============================================
#   OWASP Sentinel AI - Starting Services
# ============================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  OWASP Sentinel AI - Starting Services" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Start Backend Server
Write-Host "[1/2] Starting Backend Server..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$PSScriptRoot\backend'; if (Test-Path '.venv\Scripts\Activate.ps1') { . .venv\Scripts\Activate.ps1 }; Write-Host 'Starting Flask Backend...' -ForegroundColor Green; python app.py" -WindowStyle Normal

Start-Sleep -Seconds 2

# Start Frontend Dev Server
Write-Host "[2/2] Starting Frontend Dev Server..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$PSScriptRoot\frontend'; Write-Host 'Starting Vite Dev Server...' -ForegroundColor Green; npm run dev" -WindowStyle Normal

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  Services Starting..." -ForegroundColor Green
Write-Host "  Backend:  http://localhost:5000" -ForegroundColor White
Write-Host "  Frontend: http://localhost:5173" -ForegroundColor White
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
