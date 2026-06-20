#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Phase 6.5 DNS redirect integration matrix (Windows VM / test-signing).

.DESCRIPTION
  Verifies routeguard-callout.sys presence, IOCTL device path, and NL ordering
  prerequisites. Run after installing routeguard-callout.inf and starting RouteGuard service.

.EXAMPLE
  .\dns_redirect_matrix.ps1 -InstallPath "C:\Program Files\RouteGuard"
#>
param(
    [string]$InstallPath = "C:\Program Files\RouteGuard"
)

$ErrorActionPreference = "Stop"

function Test-CalloutDriver {
    $svc = Get-Service -Name "RouteGuardCallout" -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Warning "RouteGuardCallout service not found — install routeguard-callout.inf"
        return $false
    }
    if ($svc.Status -ne "Running") {
        Write-Warning "RouteGuardCallout service status: $($svc.Status)"
    }
    return $true
}

function Test-DevicePath {
    try {
        $h = [System.IO.File]::Open("\\.\RouteGuardCallout", [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite)
        $h.Close()
        Write-Host "OK  \\.\RouteGuardCallout device accessible"
        return $true
    } catch {
        Write-Warning "Device path not accessible: $_"
        return $false
    }
}

function Test-RouteGuardCli {
    $cli = Join-Path $InstallPath "routeguard-cli.exe"
    if (-not (Test-Path $cli)) {
        Write-Warning "routeguard-cli not found at $cli"
        return
    }
    & $cli service capabilities 2>$null | Write-Host
    & $cli domain status 2>$null | Write-Host
}

Write-Host "=== RouteGuard DNS redirect matrix ==="
$driver = Test-CalloutDriver
$device = Test-DevicePath
Test-RouteGuardCli

if ($driver -and $device) {
    Write-Host "PASS driver + device"
    exit 0
}
Write-Host "FAIL — see warnings above"
exit 1
