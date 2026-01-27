
# Run this from your project folder
$workDir  = (Get-Location).Path
$activate = Join-Path $workDir ".venv\bin\Activate.ps1"   # <-- your specified path
$script   = Join-Path $workDir "ntcip_spat_generator.py"
$ip       = "172.29.99.126"

# Launch one new PowerShell window per JSON
Get-ChildItem -Path $workDir -Filter *.json | ForEach-Object {
    $cfg = $_.FullName

    $cmd = @"
Set-Location '$workDir'; 
. '$activate'; 
python3.13 '$script' --config '$cfg' --ip $ip
"@

    # Keep each window open (-NoExit) and bypass policy for activation
    Start-Process -FilePath "powershell.exe" `
      -ArgumentList "-NoExit -ExecutionPolicy Bypass -Command $cmd" `
      -WorkingDirectory $workDir
}
