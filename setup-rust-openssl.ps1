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
    
    # Configure and build OpenSSL
    Write-Host "Configuring and building OpenSSL..."
    cd "openssl-$OPENSSL_VERSION"
    
    # Configure OpenSSL for MSVC (not MinGW/GNU)
    perl Configure VC-WIN64A --prefix=$OPENSSL_DIR --openssldir=$OPENSSL_DIR\ssl

    # Set locale environment variables to avoid Perl warnings
    [Environment]::SetEnvironmentVariable("LC_ALL", "C", [EnvironmentVariableTarget]::Process)
    [Environment]::SetEnvironmentVariable("LANG", "C", [EnvironmentVariableTarget]::Process)
    
    # Build and install OpenSSL (not needed if rust will be compiling and embedding)
    #nmake
    #nmake install_sw
    
    # Set environment variables for Rust
    Write-Host "Setting environment variables for Rust..."
    [Environment]::SetEnvironmentVariable("OPENSSL_DIR", $OPENSSL_DIR, [EnvironmentVariableTarget]::User)
    [Environment]::SetEnvironmentVariable("OPENSSL_LIB_DIR", "$OPENSSL_DIR\lib", [EnvironmentVariableTarget]::User)
    [Environment]::SetEnvironmentVariable("OPENSSL_INCLUDE_DIR", "$OPENSSL_DIR\include", [EnvironmentVariableTarget]::User)
    
    # Set for current process as well
    $env:OPENSSL_DIR = $OPENSSL_DIR
    $env:OPENSSL_LIB_DIR = "$OPENSSL_DIR\lib"
    $env:OPENSSL_INCLUDE_DIR = "$OPENSSL_DIR\include"
    
    # Ensure Rust is using MSVC toolchain
    Write-Host "Configuring Rust to use MSVC toolchain..."
    rustup default stable-msvc
    rustup update stable-msvc
    
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
    
} catch {
    Write-Host "Error: $_" -ForegroundColor Red
    exit 1
} finally {
    # Return to original directory
    Pop-Location
}