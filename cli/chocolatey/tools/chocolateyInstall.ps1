$ErrorActionPreference = 'Stop'

$version = '__VERSION__'
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"

$packageArgs = @{
  packageName    = 'c2patool'
  unzipLocation  = $toolsDir
  fileType       = 'zip'
  url64bit       = "https://github.com/contentauth/c2pa-rs/releases/download/c2patool-${version}/c2patool-${version}-x86_64-pc-windows-msvc.zip"
  checksum64     = '__CHECKSUM__'
  checksumType64 = 'sha256'
}

Install-ChocolateyZipPackage @packageArgs
