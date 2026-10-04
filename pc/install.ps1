#requires -Version 5.1
<#
.SYNOPSIS
    Builds Dropper and installs it for the current Windows user.

.DESCRIPTION
    - Publishes a single-file Dropper.exe to %LOCALAPPDATA%\Programs\Dropper
    - Adds a Start menu shortcut, and "Dropper (phone)" to Explorer's Send to menu
    - Starts Dropper in the tray when you sign in
    - Adds inbound firewall rules for THIS program that only accept your local
      subnet on private networks (one UAC prompt; Dropper.exe writes them through
      the firewall API). Any older rules for the same program (e.g. ones Windows
      created from its "allow access?" prompt, which accept every address) are
      removed first.

    Run from a source checkout (builds it) or from the unzipped release download
    (uses the Dropper.exe next to this script):
        powershell -ExecutionPolicy Bypass -File install.ps1
#>
param(
    [switch]$NoStartup,
    [switch]$NoSendTo,
    [switch]$NoFirewall,
    [switch]$NoLaunch
)
$ErrorActionPreference = 'Stop'

$project = Join-Path $PSScriptRoot 'Dropper.App\Dropper.App.csproj'
$dest = Join-Path $env:LOCALAPPDATA 'Programs\Dropper'
$exe = Join-Path $dest 'Dropper.exe'

function Step($text) { Write-Host "`n==> $text" -ForegroundColor Cyan }

Step 'Checking prerequisites'
$runtimes = & dotnet --list-runtimes 2>$null
if (-not ($runtimes -match 'Microsoft\.WindowsDesktop\.App 8\.')) {
    throw '.NET 8 Desktop Runtime is missing. Install it with:  winget install Microsoft.DotNet.DesktopRuntime.8'
}
Write-Host '.NET 8 Desktop Runtime found.'

$prebuilt = Join-Path $PSScriptRoot 'Dropper.exe'
$out = Join-Path $env:TEMP ('dropper-publish-' + [guid]::NewGuid().ToString('N'))
if (Test-Path $prebuilt) {
    # Release download: Dropper.exe ships next to this script.
    Step 'Using the prebuilt Dropper.exe from this folder'
    New-Item -ItemType Directory -Force -Path $out | Out-Null
    Copy-Item $prebuilt $out
} else {
    # Source checkout: build it (needs the .NET 8 SDK).
    Step 'Building Dropper (Release, single file)'
    & dotnet publish $project -c Release -r win-x64 --self-contained false `
        -p:PublishSingleFile=true -p:DebugType=none -p:IncludeNativeLibrariesForSelfExtract=true `
        -o $out --nologo -v q
    if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
}

Step "Installing to $dest"
Get-Process Dropper -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $exe } | ForEach-Object {
    Write-Host 'Stopping the running copy...'
    $_.Kill()
    $_.WaitForExit(5000) | Out-Null
}
New-Item -ItemType Directory -Force -Path $dest | Out-Null
Copy-Item -Path (Join-Path $out '*') -Destination $dest -Recurse -Force
Remove-Item $out -Recurse -Force
Write-Host "Installed $exe"

Step 'Creating shortcuts'
$shell = New-Object -ComObject WScript.Shell
$start = $shell.CreateShortcut((Join-Path ([Environment]::GetFolderPath('Programs')) 'Dropper.lnk'))
$start.TargetPath = $exe
$start.WorkingDirectory = $dest
$start.IconLocation = "$exe,0"
$start.Description = 'Send files and text between this PC and your phone'
$start.Save()
Write-Host 'Start menu: Dropper'
$sendTo = Join-Path ([Environment]::GetFolderPath('SendTo')) 'Dropper (phone).lnk'
if ($NoSendTo) {
    if (Test-Path $sendTo) { Remove-Item $sendTo }
} else {
    $s = $shell.CreateShortcut($sendTo)
    $s.TargetPath = $exe
    $s.Arguments = '--send'
    $s.WorkingDirectory = $dest
    $s.IconLocation = "$exe,0"
    $s.Description = 'Send to your phone with Dropper'
    $s.Save()
    Write-Host 'Explorer: Send to > Dropper (phone)'
}

$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
if ($NoStartup) {
    Remove-ItemProperty -Path $runKey -Name 'Dropper' -ErrorAction SilentlyContinue
} else {
    Set-ItemProperty -Path $runKey -Name 'Dropper' -Value "`"$exe`" --minimized"
    Write-Host 'Starts in the tray when you sign in (turn off in Dropper > Settings).'
}

if (-not $NoFirewall) {
    Step 'Allowing Dropper through Windows Firewall (local subnet, private networks only)'
    $port = 47823
    $config = Join-Path $env:LOCALAPPDATA 'Dropper\config.json'
    if (Test-Path $config) {
        try { $p = (Get-Content $config -Raw | ConvertFrom-Json).Port; if ($p) { $port = [int]$p } } catch { }
    }
    # Dropper.exe writes the rules itself through the firewall COM API (no shell or
    # command strings), running elevated just for this.
    try {
        Write-Host 'Windows will ask for administrator approval...'
        $p = Start-Process -FilePath $exe -ArgumentList '--configure-firewall', $port -Verb RunAs -Wait -PassThru
        if ($p.ExitCode -eq 0) {
            Write-Host "Firewall: TCP $port and UDP 47823 allowed from your local subnet only." -ForegroundColor Green
        } else {
            Write-Warning "The firewall rules were not created (code $($p.ExitCode)). Retry from Dropper > Settings > Network."
        }
    } catch {
        Write-Warning 'Firewall setup was cancelled. You can do it later from Dropper > Settings > Network.'
    }
}

Step 'Checking your network'
$public = Get-NetConnectionProfile -ErrorAction SilentlyContinue | Where-Object { $_.NetworkCategory -eq 'Public' }
foreach ($n in $public) {
    Write-Warning ("Network '{0}' ({1}) is set to Public. Dropper's firewall rules only apply to Private networks. " +
        'If this is your home network, set it to Private: Settings > Network & internet > (your connection) > Private network.') -f $n.Name, $n.InterfaceAlias
}
if (-not $public) { Write-Host 'Your active networks are Private. Good.' }

if (-not $NoLaunch) {
    Step 'Starting Dropper'
    Start-Process $exe
}
Write-Host "`nDone. Next: install the Android app on your phone, then click 'Pair a phone' in Dropper." -ForegroundColor Green
