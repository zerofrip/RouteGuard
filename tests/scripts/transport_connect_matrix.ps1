#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Phase 8 transport layer integration matrix (Windows VM).

.EXAMPLE
  .\transport_connect_matrix.ps1 -InstallPath "C:\Program Files\RouteGuard"
#>
param(
    [string]$InstallPath = "C:\Program Files\RouteGuard"
)

$ErrorActionPreference = "Stop"

function Test-PhantunBinary {
    $exe = Join-Path $InstallPath "phantun_client.exe"
    if (-not (Test-Path $exe)) {
        Write-Warning "phantun_client.exe not found at $exe"
        return $false
    }
    Write-Host "OK  phantun_client.exe present"
    return $true
}

function Test-RouteGuardTransportCapabilities {
    $cli = Join-Path $InstallPath "routeguard-cli.exe"
    if (-not (Test-Path $cli)) { return }
    $caps = & $cli service capabilities 2>$null | ConvertFrom-Json -ErrorAction SilentlyContinue
    if ($caps.result.features.transports) {
        Write-Host "OK  service.capabilities.features.transports = true"
    } else {
        Write-Warning "service.capabilities.features.transports = false"
    }
    if ($caps.result.transportCapabilities) {
        foreach ($t in $caps.result.transportCapabilities) {
            Write-Host "    transport $($t.kind) available=$($t.available)"
        }
    }
    if ($caps.result.features.phantun) {
        Write-Host "OK  service.capabilities.features.phantun = true"
    } else {
        Write-Warning "service.capabilities.features.phantun = false (binary may be missing)"
    }
}

Write-Host "=== RouteGuard transport matrix ==="
$phantun = Test-PhantunBinary
Test-RouteGuardTransportCapabilities

if ($phantun) {
    Write-Host "PASS phantun binary present"
    exit 0
}
Write-Host "PARTIAL — install phantun_client.exe for full Phantun transport"
exit 1
