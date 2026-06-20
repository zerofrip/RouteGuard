#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Phase 7 AWG backend integration matrix (Windows VM).

.EXAMPLE
  .\awg_connect_matrix.ps1 -InstallPath "C:\Program Files\RouteGuard"
#>
param(
    [string]$InstallPath = "C:\Program Files\RouteGuard"
)

$ErrorActionPreference = "Stop"

function Test-AwgDll {
    $dll = Join-Path $InstallPath "tunnel.dll"
    if (-not (Test-Path $dll)) {
        Write-Warning "tunnel.dll not found at $dll"
        return $false
    }
    Write-Host "OK  tunnel.dll present"
    return $true
}

function Test-WgDll {
    $dll = Join-Path $InstallPath "wireguard.dll"
    if (-not (Test-Path $dll)) {
        Write-Warning "wireguard.dll not found"
        return $false
    }
    Write-Host "OK  wireguard.dll present"
    return $true
}

function Test-RouteGuardCapabilities {
    $cli = Join-Path $InstallPath "routeguard-cli.exe"
    if (-not (Test-Path $cli)) { return }
    $caps = & $cli service capabilities 2>$null | ConvertFrom-Json -ErrorAction SilentlyContinue
    if ($caps.result.features.awg) {
        Write-Host "OK  service.capabilities.awg = true"
    } else {
        Write-Warning "service.capabilities.awg = false"
    }
}

Write-Host "=== RouteGuard AWG matrix ==="
$awg = Test-AwgDll
$wg = Test-WgDll
Test-RouteGuardCapabilities

if ($awg -and $wg) {
    Write-Host "PASS AWG + WGNT DLLs present"
    exit 0
}
Write-Host "PARTIAL — install missing DLLs"
exit 1
