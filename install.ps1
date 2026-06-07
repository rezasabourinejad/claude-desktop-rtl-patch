# Claude RTL Patch -- verified installer.
#
# Downloads patch.ps1 and patch.ps1.sig from GitHub, verifies the signature
# against an RSA-4096 public key hardcoded below (private key lives offline on
# the maintainer's machine -- see C1 mitigation), then elevates to install.
#
# A compromised GitHub repository alone is NOT enough to ship malicious code to
# users -- the attacker would also need the maintainer's offline private key.
#
# Public-key fingerprint (SHA-256 over the embedded JSON blob below):
#   94:e0:2b:e5:ec:f5:75:57:86:18:b5:01:d2:2e:03:7c:62:83:0a:26:91:a4:b1:32:09:0e:f6:2e:4e:48:57:cf
# Cross-check this at the project README and any out-of-band channel (e.g.
# release notes, social) before trusting a fresh install.
$ExpectedPubKey = 'eyJNb2R1bHVzIjoidFlNMWdTcGZKYVQrY2VvOUwyRTV6dHZ5aDlsTnp5cjVNNE5oNUdLOUJLeXMwNnZOMzZQTlVzWW40alNCUjA5QzRVVm5DTWwxbjY2MVI2Kys2bVpQZVppOVR4YSs4ZCt1QnpLRFJ1MDQzREEvY2ErT0JDTWg3eFNkVSs4bDAyWFU5V1VvQ0pvdHN5TkR1ZVY2NmtaUERhVzdJV1orNXlsZSs5S3RPZXlyTmlJQWNFSUttTlcrYWtiYkJaVUgxQVR0OCs3MDlZd3l0WThSQmxidi91dmdTSDVPWnZCMXdRd0lOTlVJNUtCOGZoM1UwdWlpVEowOUN6UGJGYSsxSTg5OWVNT2lwODdFTm1JaWwzL1ZqRi8rUWMxdHVQNVM3VXNrS0tsWnczUDBGdHVzVlRQMCt1Y1o3ZUxiZWtlSURKYUMzTExpS3hxaWg1MEFFTkk2K09sem5HNHpoYi9QdTRvL2RlYm9EdjNrb1d5N0dnenRDSmorVS92Sm1yVGphajlHMGF3WjVWVDJQRDhpYk9VcFllVjd5UitTSXNsQW1YbEVyUkMzMXI0bmJjWXFOdjFCSEIySkR6RXFJSWQ4eDA4TFh4bWRYdUJjTWZoUVBSVVAxa0RTOVh5U3MxbDBNT1FYVXZseGhWWGFWRlF6S2syK0p3aWpCS3Z3MEYyRXdWWkFLanBJNys3ZjhuTC9jaEZBZDJhTnVodmNoWDYxY3VJdktKaGk0VHFLdlBrLzY3TW1yZlhvcGpCdUtJdXFXZ0dSbmk0N01BTzVWNHVEYWt0VENabEtPVHNyVVBWOWJ5aHdQRGxWWW1CUkx3MzV2UFJFNmZGSk9yc29oV3BJL0ozY1Z1bXJ6N1VQSkl4UFZDTmw4TnQzUE5yMGdvZ2IrOGYzZXpTYVl0TG5LN0U9IiwiRXhwb25lbnQiOiJBUUFCIn0='

$RepoBase = 'https://raw.githubusercontent.com/rezasabourinejad/claude-desktop-rtl-patch/main'
$TmpFile  = Join-Path $env:TEMP 'claude_rtl_patch.ps1'

# PS 5.1 defaults to TLS 1.0; GitHub requires 1.2+.
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

# Download patch.ps1 as RAW bytes -- Invoke-RestMethod would decode and silently
# normalize the BOM, breaking the signature byte-for-byte. WebClient gives us
# the exact bytes the maintainer signed.
$client = New-Object System.Net.WebClient
try {
    $patchBytes = $client.DownloadData("$RepoBase/patch.ps1")
    $sigB64     = $client.DownloadString("$RepoBase/patch.ps1.sig").Trim()
} catch {
    Write-Host ""
    Write-Host "Network error downloading patch: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Check connectivity and retry." -ForegroundColor Yellow
    return
}

# Decode pubkey (custom JSON format; see tools/sign-release.ps1 for the rationale).
try {
    $pubJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ExpectedPubKey))
    $pubObj  = $pubJson | ConvertFrom-Json
    $params = New-Object System.Security.Cryptography.RSAParameters
    $params.Modulus  = [Convert]::FromBase64String($pubObj.Modulus)
    $params.Exponent = [Convert]::FromBase64String($pubObj.Exponent)
    $rsa = [System.Security.Cryptography.RSA]::Create()
    $rsa.ImportParameters($params)
} catch {
    Write-Host "Internal error: bundled public key is malformed ($($_.Exception.Message))." -ForegroundColor Red
    Write-Host "Do NOT proceed -- this means install.ps1 itself was tampered with." -ForegroundColor Red
    return
}

# Decode signature.
try {
    $sigBytes = [Convert]::FromBase64String($sigB64)
} catch {
    Write-Host ""
    Write-Host "Downloaded signature is not valid base64. Aborting." -ForegroundColor Red
    return
}

# The actual signature check.
$valid = $rsa.VerifyData(
    $patchBytes, $sigBytes,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
)

if (-not $valid) {
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host "  SIGNATURE VERIFICATION FAILED -- REFUSING TO RUN patch.ps1     " -ForegroundColor Red
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "The downloaded patch does not match the maintainer's signature." -ForegroundColor Yellow
    Write-Host "Possible causes:" -ForegroundColor Yellow
    Write-Host "  * The GitHub repository was compromised." -ForegroundColor Yellow
    Write-Host "  * Your network or proxy is intercepting traffic." -ForegroundColor Yellow
    Write-Host "  * A maintainer pushed patch.ps1 without re-signing." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Cross-check the public-key fingerprint at:" -ForegroundColor Cyan
    Write-Host "  https://github.com/rezasabourinejad/claude-desktop-rtl-patch#verification" -ForegroundColor Cyan
    return
}

# Decode bytes to string and strip BOM (we'll re-add it on write). PS 5.1 needs
# the file to start with a UTF-8 BOM to parse Hebrew/box-drawing characters.
$content = [System.Text.Encoding]::UTF8.GetString($patchBytes)
if ($content.Length -gt 0 -and $content[0] -eq [char]0xFEFF) { $content = $content.Substring(1) }
[System.IO.File]::WriteAllText($TmpFile, $content, [System.Text.UTF8Encoding]::new($true))

Write-Host "Patch verified ($($patchBytes.Length) bytes). Elevating..." -ForegroundColor Green

# Hand the elevated patch.ps1 the pubkey blob we just verified against, as a
# -TrustedPubKey PARAMETER. patch.ps1 uses it to pin the trust anchor for the
# auto-update watcher (see Save-TrustedPubkey in patch.ps1). It MUST be a
# parameter, not an env var: environment variables set here do NOT survive the
# Start-Process -Verb RunAs UAC elevation boundary, so the elevated child would
# never see them. Passing the verified blob (rather than letting patch.ps1
# re-download install.ps1 itself) also avoids a TOCTOU window where the repo
# could change between our verify and patch.ps1's pin.

# Same launch line as the original installer -- nothing user-facing has changed.
# -NoExit keeps the elevated window open so the user can read the patch log.
Start-Process -FilePath PowerShell.exe -Verb RunAs -ArgumentList "-NoProfile -NoExit -ExecutionPolicy Bypass -File `"$TmpFile`" -TrustedPubKey `"$ExpectedPubKey`""
