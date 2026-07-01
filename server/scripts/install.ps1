$ErrorActionPreference = "Stop"

$Version = "v.0.5.0"

$Arch = $env:PROCESSOR_ARCHITECTURE

switch ($Arch) {
    "AMD64" { $Platform = "windows_x86" }
    "ARM64" { $Platform = "windows_x86" }
    default { throw "Unsupported architecture: $Arch" }
}

$InstallDir = "$env:LOCALAPPDATA\Codesana"
$BinaryPath = Join-Path $InstallDir "codesana.exe"

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

$DownloadUrl = "https://github.com/NikitaKovalenko111/codesana/releases/download/$Version/codesana_$Platform.exe"

Write-Host "Downloading Codesana..."
Invoke-WebRequest `
    -Uri $DownloadUrl `
    -OutFile $BinaryPath

$userPath = [Environment]::GetEnvironmentVariable(
    "Path",
    "User"
)

if ($userPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable(
        "Path",
        "$userPath;$InstallDir",
        "User"
    )

    Write-Host "Added Codesana to PATH"
}

Write-Host ""
Write-Host "Codesana installed successfully!"
Write-Host "Location: $BinaryPath"
Write-Host ""
Write-Host "Open a new terminal and run:"
Write-Host "codesana help all"