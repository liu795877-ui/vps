$ErrorActionPreference = 'Stop'
$baseSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'configure_reality.py') -Raw
$exitSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'configure_static_exits.py') -Raw
$baseChunks = for ($offset = 0; $offset -lt $baseSource.Length; $offset += 512) {
    $length = [Math]::Min(512, $baseSource.Length - $offset)
    '    ' + (ConvertTo-Json -InputObject $baseSource.Substring($offset, $length) -Compress)
}
$header = @'
(
set -eu
read -r -p 'VPS public IPv4 (not a password): ' VPS_PUBLIC_IP
sudo env VPS_PUBLIC_IP="$VPS_PUBLIC_IP" python3 - <<'XRAY_STATIC_PY'
import sys
import types
_base_module = types.ModuleType("configure_reality")
'@
$bootstrap = "exec(`n" + ($baseChunks -join "`n") + "`n    , _base_module.__dict__`n)`n" +
    'sys.modules["configure_reality"] = _base_module'
$footer = @'
XRAY_STATIC_PY
)
'@
$command = $header.TrimEnd() + "`n" + $bootstrap + "`n" +
    $exitSource.TrimEnd() + "`n" + $footer
$command = $command.Replace("`r`n", "`n")
[System.IO.File]::WriteAllText(
    (Join-Path $PSScriptRoot 'vps-console-static-exits.txt'),
    $command,
    [System.Text.UTF8Encoding]::new($false)
)
Write-Output 'Generated vps-console-static-exits.txt; no credentials are included.'
