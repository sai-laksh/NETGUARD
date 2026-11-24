Write-Host "======================================================================" -ForegroundColor Green
Write-Host " NETGUARD - SMART CAMPUS NETWORK MONITORING AND SECURITY SYSTEM" -ForegroundColor Green
Write-Host " Theme: Dark Emerald Green SOC Dashboard" -ForegroundColor DarkGreen
Write-Host " Capstone Project | Computer Networks (CN)" -ForegroundColor Gray
Write-Host "======================================================================" -ForegroundColor Green

$pythonPath = $null

if (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonPath = "python"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonPath = "py"
} elseif (Test-Path "$env:LOCALAPPDATA\Programs\Python\Python39\python.exe") {
    $pythonPath = "$env:LOCALAPPDATA\Programs\Python\Python39\python.exe"
}

if ($pythonPath) {
    Write-Host "[INFO] Starting Flask Server using $pythonPath..." -ForegroundColor Cyan
    Write-Host "[INFO] Open your browser at http://127.0.0.1:5000" -ForegroundColor Yellow
    Start-Process "http://127.0.0.1:5000"
    & $pythonPath app.py
} else {
    Write-Host "[INFO] Launching index.html directly in default browser..." -ForegroundColor Yellow
    Start-Process "index.html"
}
