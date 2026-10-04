#requires -Version 5.1
<#
.SYNOPSIS
    Removes Dropper from this Windows account.

.PARAMETER RemoveData
    Also deletes settings, history, pairings and this PC's identity key (TPM or
    software). Paired phones will then need to pair again with a fresh install.

    Run:  powershell -ExecutionPolicy Bypass -File pc\uninstall.ps1 [-RemoveData]
#>
param([switch]$RemoveData)
$ErrorActionPreference = 'Stop'
$dest = Join-Path $env:LOCALAPPDATA 'Programs\Dropper'
$exe = Join-Path $dest 'Dropper.exe'

Get-Process Dropper -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $exe } | ForEach-Object { $_.Kill(); $_.WaitForExit(5000) | Out-Null }

Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'Dropper' -ErrorAction SilentlyContinue
foreach ($lnk in @(
        (Join-Path ([Environment]::GetFolderPath('Programs')) 'Dropper.lnk'),
        (Join-Path ([Environment]::GetFolderPath('SendTo')) 'Dropper (phone).lnk'))) {
    if (Test-Path $lnk) { Remove-Item $lnk }
}

if (Test-Path $exe) {
    try { Start-Process -FilePath $exe -ArgumentList '--remove-firewall' -Verb RunAs -Wait }
    catch { Write-Warning 'Firewall rules were not removed (UAC cancelled).' }
}

if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }

if ($RemoveData) {
    $data = Join-Path $env:LOCALAPPDATA 'Dropper'
    if (Test-Path $data) { Remove-Item $data -Recurse -Force }
    foreach ($provider in 'Microsoft Platform Crypto Provider', 'Microsoft Software Key Storage Provider') {
        try {
            $p = New-Object System.Security.Cryptography.CngProvider $provider
            if ([System.Security.Cryptography.CngKey]::Exists('Dropper-Identity-v1', $p)) {
                [System.Security.Cryptography.CngKey]::Open('Dropper-Identity-v1', $p).Delete()
                Write-Host "Deleted identity key from $provider"
            }
        } catch { }
    }
}
Write-Host 'Dropper was removed.' -ForegroundColor Green
