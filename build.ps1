# build.ps1 - build helper for GhostChatter
# Usage: Run from the `chatter` folder in PowerShell
# Example: .\build.ps1 -Clean -BuildAll

param(
    [switch]$Clean,
    [switch]$BuildClient,
    [switch]$BuildChatServer,
    [switch]$BuildServer,
    [switch]$BuildUpdater,
    [switch]$BuildAll
)

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $projectRoot

$venv = Join-Path $projectRoot ".venv"

function Get-PythonExe {
    # Prefer explicit env var, then common commands
    if ($env:PYTHON) { return $env:PYTHON }
    $names = @('python3.13','python3','python','py')
    foreach ($n in $names) {
        $c = Get-Command $n -ErrorAction SilentlyContinue
        if ($c) { return $c.Source }
    }
    return $null
}

$pythonExe = Get-PythonExe
if (-not $pythonExe) {
    Write-Error "Python executable not found. Please install Python or set the PYTHON environment variable."
    exit 1
}

if (-not (Test-Path $venv)) {
    Write-Host "Creating virtualenv using $pythonExe..."
    & $pythonExe -m venv .venv
}

$python = Join-Path $venv "Scripts\python.exe"
if (-not (Test-Path $python)) { $python = $pythonExe }

Write-Host "Installing requirements..."
& $python -m pip install --upgrade pip
& $python -m pip install -r requirements.txt
& $python -m pip install pyinstaller --quiet

if ($Clean) {
    Write-Host "Cleaning build/dist/spec..."
    Remove-Item -Recurse -Force .\build -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force .\dist -ErrorAction SilentlyContinue
    Remove-Item -Force .\*.spec -ErrorAction SilentlyContinue
}

if ($BuildAll) { $BuildClient = $true; $BuildServer = $true; $BuildUpdater = $true }
if ($BuildAll) { $BuildChatServer = $true }

if ($BuildClient) {
    Write-Host "Building Client (GUI)..."
    & $python -m PyInstaller --onefile --noconsole --name GhostChatterClient `
        --add-data "version.txt;." `
        src/client/main.py
}

if ($BuildChatServer) {
    Write-Host "Building Chat Server (instance)..."
    & $python -m PyInstaller --onefile --console --name GhostChatterChatServer `
        --add-data "version.txt;." `
        --add-data "src/server/commands.py;." `
        src/server/chat_server.py
}

if ($BuildServer) {
    Write-Host "Building Server (console)..."
    & $python -m PyInstaller --onefile --console --name GhostChatterServer `
        --add-data "version.txt;." `
        --add-data "src/server/commands.py;." `
        src/server/main.py
}

if ($BuildUpdater) {
    Write-Host "Building Updater..."
    & $python -m PyInstaller --onefile --noconsole --name Updater `
        src/updater/updater.py
}

# Package release folder
$release = Join-Path $projectRoot "release"
if (-not (Test-Path $release)) { New-Item -ItemType Directory -Path $release | Out-Null }

if (Test-Path .\dist\GhostChatterClient.exe) { Copy-Item .\dist\GhostChatterClient.exe $release -Force }
if (Test-Path .\dist\GhostChatterServer.exe) { Copy-Item .\dist\GhostChatterServer.exe $release -Force }
if (Test-Path .\dist\Updater.exe) { Copy-Item .\dist\Updater.exe $release -Force }
if (Test-Path .\dist\GhostChatterChatServer.exe) { Copy-Item .\dist\GhostChatterChatServer.exe $release -Force }

# copy version and server-commands for convenience
Copy-Item version.txt $release -Force -ErrorAction SilentlyContinue
Copy-Item src/server/commands.py $release -Force -ErrorAction SilentlyContinue
Copy-Item requirements.txt $release -Force -ErrorAction SilentlyContinue

Write-Host "Build finished. Release folder: $release"