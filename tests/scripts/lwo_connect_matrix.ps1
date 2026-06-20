#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Phase 9 LWO transport integration matrix (Windows VM).

.EXAMPLE
  .\lwo_connect_matrix.ps1 -InstallPath "C:\Program Files\RouteGuard"
#>
param(
    [string]$InstallPath = "C:\Program Files\RouteGuard"
)

$ErrorActionPreference = "Stop"

function Test-LwoCapabilities {
    $cli = Join-Path $InstallPath "routeguard-cli.exe"
    if (-not (Test-Path $cli)) {
        Write-Warning "routeguard-cli.exe not found at $cli"
        return $false
    }

    $caps = & $cli service capabilities 2>$null | ConvertFrom-Json -ErrorAction SilentlyContinue
    if (-not $caps.result) {
        Write-Warning "service.capabilities returned no result"
        return $false
    }

    $schema = $caps.result.schemaVersion
    if ($schema -ge 3) {
        Write-Host "OK  schemaVersion = $schema"
    } else {
        Write-Warning "schemaVersion = $schema (expected >= 3 for LWO)"
    }

    if ($caps.result.features.lwo) {
        Write-Host "OK  features.lwo = true"
    } else {
        Write-Warning "features.lwo = false"
        return $false
    }

    if ($caps.result.features.transports) {
        Write-Host "OK  features.transports = true"
    }

    $lwoCap = $caps.result.transportCapabilities | Where-Object { $_.kind -eq "lwo" }
    if ($lwoCap) {
        Write-Host "OK  transportCapabilities[lwo] available=$($lwoCap.available) wireFormat=$($lwoCap.wireFormat)"
        if ($lwoCap.wireFormat -ne "mullvad") {
            Write-Warning "expected wireFormat=mullvad, got $($lwoCap.wireFormat)"
        }
    } else {
        Write-Warning "transportCapabilities missing lwo entry"
        return $false
    }

    return $true
}

Write-Host "=== RouteGuard LWO transport matrix ==="
if (Test-LwoCapabilities) {
    Write-Host "PASS LWO capabilities present"
    exit 0
}
Write-Host "FAIL LWO capabilities check"
exit 1
