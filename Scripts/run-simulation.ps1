Write-Host "============================================"
Write-Host " CYBERSECURITY HOME LAB - SOC SIMULATION"
Write-Host "============================================"
Write-Host ""

$replayLog = "logs\replay-auth.log"

Write-Host "[1] Preparing simulated authentication logs..."
Copy-Item "logs\sample-auth.log" $replayLog -Force

Write-Host "[2] Removing successful login from replay..."
(Get-Content $replayLog) |
    Where-Object { $_ -notmatch "Accepted password for admin from 203.0.113.50" } |
    Set-Content $replayLog

Write-Host ""
Write-Host "[3] Running brute-force detection..."
python scripts\log-analyzer.py $replayLog

Write-Host ""
Write-Host "[4] Simulating successful authentication..."
Add-Content $replayLog "Oct 05 12:35:10 server sshd[2001]: Accepted password for admin from 203.0.113.50 port 22 ssh2"

Write-Host ""
Write-Host "[5] Re-running detection after successful login..."
python scripts\log-analyzer.py $replayLog

Write-Host ""
Write-Host "[6] Cleaning up temporary simulation log..."
Remove-Item $replayLog -Force

Write-Host ""
Write-Host "============================================"
Write-Host " SIMULATION COMPLETE"
Write-Host "============================================"
