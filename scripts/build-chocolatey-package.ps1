# PowerShell script to build and validate Chocolatey package
# Run this on Windows with Chocolatey installed

param(
    [Parameter(Mandatory=$true)]
    [string]$Version
)

Write-Host "🍫 Building Chocolatey Package for version $Version" -ForegroundColor Green

# Set working directory to project root
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

# Clean previous builds
Write-Host "🧹 Cleaning previous builds..." -ForegroundColor Yellow
Remove-Item -Path "dist", "packages/chocolatey" -Recurse -Force -ErrorAction SilentlyContinue

# Build the package
Write-Host "📦 Building Chocolatey package..." -ForegroundColor Yellow
& make chocolatey VERSION=$Version

if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to build Chocolatey package"
    exit 1
}

# Navigate to chocolatey package directory
Set-Location "packages/chocolatey"

# Validate required files exist
Write-Host "✅ Validating package structure..." -ForegroundColor Yellow
$RequiredFiles = @(
    "go-terraform-linter.nuspec",
    "tools/chocolateyinstall.ps1",
    "tools/go-terraform-linter.exe",
    "tools/LICENSE.txt",
    "tools/VERIFICATION.txt"
)

foreach ($file in $RequiredFiles) {
    if (Test-Path $file) {
        Write-Host "✅ $file exists" -ForegroundColor Green
    } else {
        Write-Error "❌ $file is missing!"
        exit 1
    }
}

# Check checksum in install script
$InstallScript = Get-Content "tools/chocolateyinstall.ps1" -Raw
if ($InstallScript -match 'checksum64\s*=\s*"([a-fA-F0-9]{64})"') {
    Write-Host "✅ Valid SHA256 checksum found: $($matches[1])" -ForegroundColor Green
} else {
    Write-Error "❌ No valid checksum found in chocolateyinstall.ps1"
    exit 1
}

# Pack the package
Write-Host "📦 Creating .nupkg file..." -ForegroundColor Yellow
choco pack go-terraform-linter.nuspec

if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to pack Chocolatey package"
    exit 1
}

# List generated files
Write-Host "📄 Generated files:" -ForegroundColor Green
Get-ChildItem -Recurse | Format-Table Name, Length, LastWriteTime

Write-Host "🎉 Chocolatey package built successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Test locally: choco install go-terraform-linter.$Version.nupkg --source ." -ForegroundColor White
Write-Host "2. Upload to Chocolatey: https://community.chocolatey.org/packages/upload" -ForegroundColor White
Write-Host "3. Address reviewer feedback" -ForegroundColor White 