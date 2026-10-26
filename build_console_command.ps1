$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'configure_reality.py') -Raw
$header = @'
(
set -eu
read -r -p 'VPS public IPv4 (not a password): ' VPS_PUBLIC_IP
sudo env VPS_PUBLIC_IP="$VPS_PUBLIC_IP" python3 - <<'XRAY_SETUP_PY'
'@
$footer = @'
XRAY_SETUP_PY
)
'@
$command = $header.TrimEnd() + "`n" + $source.TrimEnd() + "`n" + $footer
$command = $command.Replace("`r`n", "`n")
[System.IO.File]::WriteAllText(
    (Join-Path $PSScriptRoot 'vps-console-setup.txt'),
    $command,
    [System.Text.UTF8Encoding]::new($false)
)
Write-Output 'Generated vps-console-setup.txt; no credentials are included.'
