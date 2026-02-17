# make_release.ps1
# Script to setup Rust with OpenSSL using Visual Studio tools on GitHub Actions windows-latest image
# Build Rust project with MSVC and Clang toolchain
# Archive the build artifacts

# Stop on first error
$ErrorActionPreference = "Stop"

Write-Host "Setting up Rust with OpenSSL (MSVC) environment..."

# Detect hardware architecture and set $arch to "x86_64" or "aarch64"
# Allow override via TARGET_ARCH environment variable
if ($env:TARGET_ARCH) {
    $arch = $env:TARGET_ARCH
    Write-Host "Using target architecture from environment: $arch"
} else {
    switch ($env:PROCESSOR_ARCHITECTURE) {
        "AMD64" { $arch = "x86_64" }
        "ARM64" { $arch = "aarch64" }
        default { $arch = $env:PROCESSOR_ARCHITECTURE }
    }
    Write-Host "Detected architecture: $arch"
}

# Ensure rustup is in PATH
$env:PATH = "$env:USERPROFILE\.cargo\bin;" + $env:PATH

Write-Host "Detecting Visual Studio installation..."
$vswhere_path = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-Not (Test-Path $vswhere_path)) {
    Write-Host "Error: vswhere.exe not found. Please ensure Visual Studio is installed." -ForegroundColor Red
    exit 1
}

$vs_installation_path = & $vswhere_path -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-Not $vs_installation_path) {
    Write-Host "Error: Could not detect Visual Studio installation. Ensure the required components are installed." -ForegroundColor Red
    exit 1
}
Write-Host "Visual Studio detected at: $vs_installation_path"

$VCVARS_PATH = Join-Path -Path $vs_installation_path -ChildPath "VC\Auxiliary\Build\vcvars64.bat"
if (-Not (Test-Path $VCVARS_PATH)) {
    Write-Host "Error: vcvars64.bat not found. Ensure Visual Studio is properly installed." -ForegroundColor Red
    exit 1
}


# Setup Visual Studio environment
Write-Host "Setting up Visual Studio environment..."
cmd.exe /c "call `"$VCVARS_PATH`" && set > %temp%\vcvars.txt"
Get-Content "$env:temp\vcvars.txt" | ForEach-Object {
    if ($_ -match "^(.*?)=(.*)$") {
        $name = $matches[1]
        $value = $matches[2]
        [Environment]::SetEnvironmentVariable($name, $value, [EnvironmentVariableTarget]::Process)
    }
}

# Add MSVC (cl.exe, link.exe) to PATH using detected Visual Studio path
$vsTools = Join-Path $vs_installation_path "VC\Tools\MSVC"
$msvcVersion = Get-ChildItem "$vsTools" | Sort-Object Name -Descending | Select-Object -First 1
$clPath = Join-Path $vsTools "$($msvcVersion.Name)\bin\Hostx64\x64"
$env:PATH = "$clPath;" + $env:PATH

# Add LLVM/Clang to PATH (prefer system LLVM, then VS LLVM)
$llvmPath = "C:\Program Files\LLVM\bin"
if (Test-Path $llvmPath) {
    $env:PATH = "$llvmPath;" + $env:PATH
} else {
    $vsLlvmPath = Join-Path $vs_installation_path "VC\Tools\Llvm\bin"
    if (Test-Path $vsLlvmPath) {
        $env:PATH = "$vsLlvmPath;" + $env:PATH
    }
}
Write-Host "LLVM/Clang detected at: $llvmPath"

# Print tool versions for verification
Write-Host "rustc version:"; rustc --version
Write-Host "cargo version:"; cargo --version
Write-Host "cl version:"; cl 2>&1 | Select-String "Version"
Write-Host "clang version:"; clang --version

Write-Host "`nEnvironment setup complete. You can now run 'make release'."

Write-Host "Building Rust project with msvc and clang toolchain ..."
rustup update stable-$arch-pc-windows-msvc
rustup target add $arch-pc-windows-msvc
cargo build --target="$arch-pc-windows-msvc" -p c2pa-c-ffi --release --no-default-features --features "rust_native_crypto, file_io"


# generate zip file with version and platform and add to artifacts folder
$platform = "$arch-pc-windows-msvc"
$ReleaseDir = "target\$platform\release"
$artifactsDir = "target\artifacts"
$includeDir = "$ReleaseDir\include"
$libDir = "$ReleaseDir\lib"

Write-Host "Reading version from $ReleaseDir\c2pa.h"
$versionLine = Select-String -Path "$ReleaseDir\c2pa.h" -Pattern "^// Version:" | Select-Object -First 1
if ($versionLine) {
    $version = $versionLine.Line -replace "^// Version:\s*", ""
    $version = $version.Trim()
} else {
    Write-Host "Could not find version in $ReleaseDir\c2pa.h" -ForegroundColor Red
    exit 1
}
Write-Host "Version: $version"
Write-Host "Platform: $platform"
Write-Host "Release directory: $ReleaseDir"
Write-Host "Artifacts directory: $artifactsDir"

New-Item -ItemType Directory -Force -Path $artifactsDir | Out-Null
New-Item -ItemType Directory -Force -Path $includeDir | Out-Null
New-Item -ItemType Directory -Force -Path $libDir | Out-Null

Copy-Item "$ReleaseDir\c2pa.h" $includeDir -Force
Copy-Item "$ReleaseDir\c2pa_c.*" $libDir -Force

$zipPath = "$artifactsDir\c2pa-v$version-$platform.zip"
Compress-Archive -Path "$includeDir", "$libDir" -DestinationPath $zipPath -Force

Write-Host "Zip file created: $zipPath"
Write-Host "Setup completed successfully!"