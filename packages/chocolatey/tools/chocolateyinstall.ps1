$ErrorActionPreference = "Stop"
$packageName = "go-terraform-linter"
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$url64 = "https://github.com/heyimusa/go-terraform-linter/releases/download/v1.0.3/go-terraform-linter-windows-amd64.exe"

$packageArgs = @{
  packageName   = $packageName
  unzipLocation = $toolsDir
  url64bit      = $url64
  softwareName  = "go-terraform-linter*"
  checksum64    = "8b59f3c50c2c2da959a5b77f758a879c3f02a048564fb2815ccd2b728362b1c4"
  checksumType64= "sha256"
}

Get-ChocolateyWebFile @packageArgs
Install-ChocolateyPath "$toolsDir" "Machine"
