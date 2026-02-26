$f = Join-Path $env:TEMP "claude_rtl_patch.ps1"
$w = Join-Path $env:TEMP "claude_rtl_wrapper.ps1"
Invoke-RestMethod -Uri "https://raw.githubusercontent.com/shraga100/claude-desktop-rtl-patch/main/patch.ps1" -OutFile $f
Set-Content -Path $w -Value @"
try { & '$f' } catch { Write-Host `$_.Exception.Message -ForegroundColor Red }
Read-Host 'Press Enter to close'
"@
Start-Process -FilePath PowerShell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$w`""
