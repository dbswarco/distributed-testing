# Run this from your project folder
$workDir  = (Get-Location).Path
$activate = Join-Path $workDir ".venv\Scripts\Activate.ps1"   # <-- your specified path
$script   = Join-Path $workDir "loop_detector_events.py"
$ip       = "10.1.110.181"

# Launch one new PowerShell window per intersection (8 total)
ForEach ($i in 1..8) {
    $cmd = @"
Set-Location '$workDir'; 
. '$activate'; 
python '$script' --snmp-port ($i + 10000) --host $ip
"@

    # Keep each window open (-NoExit) and bypass policy for activation
    Start-Process -FilePath "powershell.exe" `
      -ArgumentList "-NoExit -ExecutionPolicy Bypass -Command $cmd" `
      -WorkingDirectory $workDir
}