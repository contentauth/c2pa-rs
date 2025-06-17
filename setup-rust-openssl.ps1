# setup-rust-openssl.ps1
# Script to setup Rust with OpenSSL using Visual Studio tools on GitHub Actions windows-latest image

# Stop on first error
$ErrorActionPreference = "Stop"

Write-Host "Setting up Rust with OpenSSL (MSVC) environment..."

# Define variables
$OPENSSL_VERSION = "3.1.4"
$OPENSSL_DIR = "C:\OpenSSL"
$TEMP_DIR = "C:\openssl_build"
# Detect Visual Studio installation path using vswhere
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

$VCVARS_PATH = Join-Path -Path $vs_installation_path -ChildPath "VC\Auxiliary\Build\vcvars64.bat"
if (-Not (Test-Path $VCVARS_PATH)) {
    Write-Host "Error: vcvars64.bat not found. Ensure Visual Studio is properly installed." -ForegroundColor Red
    exit 1
}

Write-Host "Visual Studio detected at: $vs_installation_path"
Write-Host "Using vcvars64.bat at: $VCVARS_PATH"

# Create directories
New-Item -ItemType Directory -Force -Path $TEMP_DIR | Out-Null
New-Item -ItemType Directory -Force -Path $OPENSSL_DIR | Out-Null

# Change to temp directory
Push-Location $TEMP_DIR

try {
    # Download OpenSSL source
    Write-Host "Downloading OpenSSL source..."
    $openssl_url = "https://www.openssl.org/source/openssl-$OPENSSL_VERSION.tar.gz"
    Invoke-WebRequest -Uri $openssl_url -OutFile "openssl.tar.gz"
    
    # Extract OpenSSL
    Write-Host "Extracting OpenSSL source..."
    tar -xf openssl.tar.gz
    
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

    # Add LLVM (clang) to PATH (Ring requires this)
    $llvmBin = "C:\Program Files\LLVM\bin"
    if (Test-Path $llvmBin) {
        Write-Host "Adding LLVM (clang) to PATH: $llvmBin"
        $env:PATH = "$llvmBin;$env:PATH"
        [Environment]::SetEnvironmentVariable("PATH", "$llvmBin;$([Environment]::GetEnvironmentVariable('PATH', [EnvironmentVariableTarget]::User))", [EnvironmentVariableTarget]::User)
    } else {
        Write-Host "Warning: LLVM (clang) not found at $llvmBin"
    }
    
    # Configure and build OpenSSL
    Write-Host "Configuring and building OpenSSL..."
    cd "openssl-$OPENSSL_VERSION"
    
    # Configure OpenSSL for MSVC (not MinGW/GNU)
    perl Configure VC-WIN64A --prefix=$OPENSSL_DIR --openssldir=$OPENSSL_DIR\ssl

    # Set locale environment variables to avoid Perl warnings
    [Environment]::SetEnvironmentVariable("LC_ALL", "C", [EnvironmentVariableTarget]::Process)
    [Environment]::SetEnvironmentVariable("LANG", "C", [EnvironmentVariableTarget]::Process)
    
    
    # Set environment variables for Rust
    Write-Host "Setting environment variables for Rust..."
    [Environment]::SetEnvironmentVariable("OPENSSL_DIR", $OPENSSL_DIR, [EnvironmentVariableTarget]::User)
    [Environment]::SetEnvironmentVariable("OPENSSL_LIB_DIR", "$OPENSSL_DIR\lib", [EnvironmentVariableTarget]::User)
    [Environment]::SetEnvironmentVariable("OPENSSL_INCLUDE_DIR", "$OPENSSL_DIR\include", [EnvironmentVariableTarget]::User)
    
    # Set for current process as well
    $env:OPENSSL_DIR = $OPENSSL_DIR
    $env:OPENSSL_LIB_DIR = "$OPENSSL_DIR\lib"
    $env:OPENSSL_INCLUDE_DIR = "$OPENSSL_DIR\include"

    # Add OpenSSL bin to PATH for DLLs
    $current_path = [Environment]::GetEnvironmentVariable("PATH", [EnvironmentVariableTarget]::User)
    $new_path = "$OPENSSL_DIR\bin;$current_path"
    [Environment]::SetEnvironmentVariable("PATH", $new_path, [EnvironmentVariableTarget]::user)
    $env:PATH = "$OPENSSL_DIR\bin;$env:PATH"
    
    # Output summary
    Write-Host "`n=== Configuration Summary ===`n"
    Write-Host "OpenSSL installed to: $OPENSSL_DIR"
    Write-Host "OpenSSL version: $OPENSSL_VERSION"
    Write-Host "Rust toolchain: $(rustc --version)"
    Write-Host "Environment variables set:"
    Write-Host "  OPENSSL_DIR = $env:OPENSSL_DIR"
    Write-Host "  OPENSSL_LIB_DIR = $env:OPENSSL_LIB_DIR"
    Write-Host "  OPENSSL_INCLUDE_DIR = $env:OPENSSL_INCLUDE_DIR"
    Write-Host "`nSetup completed successfully!"

    # build with Rust msvc
    Write-Host "Building Rust project with msvc toolchain ..."
    rustup update stable-msvc
    rustup target add x86_64-pc-windows-msvc
    cargo build --target=x86_64-pc-windows-msvc --release

    # generate zip file with version and platform and add to artifacts folder
    $platform = "x86_64-pc-windows-msvc"
    $ReleaseDir = "target\$platform\release"
    $artifactsDir = "target\artifacts"
    $includeDir = "$ReleaseDir\include"
    $libDir = "$ReleaseDir\lib"

    Write-Host "Reading version from $ReleaseDir\c2pa.h"
    $versionLine = Select-String -Path "$ReleaseDir\c2pa.h" -Pattern "^// Version:" | Select-Object -First 1
    $version = $versionLine -replace "^// Version: ", ""

    New-Item -ItemType Directory -Force -Path $artifactsDir | Out-Null
    New-Item -ItemType Directory -Force -Path $includeDir | Out-Null
    New-Item -ItemType Directory -Force -Path $libDir | Out-Null

    Copy-Item "$ReleaseDir\c2pa.h" $includeDir -Force
    Copy-Item "$ReleaseDir\libc2pa_c.*" $libDir -Force

    # Add a delay to ensure files are fully written
    Start-Sleep -Seconds 5

    # Verify files exist before zipping
    if (-not (Test-Path "$libDir\libc2pa_c.dll")) {
        Write-Host "Error: libc2pa_c.dll not found in $libDir" -ForegroundColor Red
        exit 1
    }

    $zipPath = "$artifactsDir\c2pa-v$version-$platform.zip"
    Compress-Archive -Path "$includeDir", "$libDir" -DestinationPath $zipPath -Force

    Write-Host "Zip file created: $zipPath"

} catch {
    Write-Host "Error: $_" -ForegroundColor Red
    exit 1
} finally {
    # Return to original directory
    Pop-Location
}