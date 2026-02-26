$f = Join-Path $env:TEMP "claude_rtl_patch.ps1"
Invoke-RestMethod -Uri "https://raw.githubusercontent.com/shraga100/claude-desktop-rtl-patch/main/patch.ps1" -OutFile $f
Start-Process -FilePath PowerShell.exe -Verb RunAs -ArgumentList "-NoProfile -NoExit -ExecutionPolicy Bypass -File `"$f`""
