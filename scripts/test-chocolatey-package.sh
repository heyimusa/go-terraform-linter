#!/bin/bash

# Test script for Chocolatey package generation and validation
set -e

echo "🧪 Testing Chocolatey Package Generation..."

# Clean up any previous builds
rm -rf dist/ packages/chocolatey/

# Build the project
echo "📦 Building binaries..."
make build-all

# Generate Chocolatey package
echo "🍫 Generating Chocolatey package..."
make chocolatey VERSION=v1.0.3

echo "✅ Validating generated package..."

# Check if required files exist
REQUIRED_FILES=(
    "packages/chocolatey/go-terraform-linter.nuspec"
    "packages/chocolatey/tools/chocolateyinstall.ps1"
    "packages/chocolatey/tools/go-terraform-linter.exe"
    "packages/chocolatey/tools/LICENSE.txt"
    "packages/chocolatey/tools/VERIFICATION.txt"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [[ -f "$file" ]]; then
        echo "✅ $file exists"
    else
        echo "❌ $file is missing!"
        exit 1
    fi
done

# Check if checksum is properly set
if grep -q "REPLACE_WITH_CHECKSUM" packages/chocolatey/tools/chocolateyinstall.ps1; then
    echo "❌ Checksum not properly set in chocolateyinstall.ps1"
    exit 1
else
    echo "✅ Checksum properly set in chocolateyinstall.ps1"
fi

# Check nuspec content
echo "📋 Checking nuspec content..."
NUSPEC_CHECKS=(
    "iconUrl"
    "licenseUrl"
    "releaseNotes"
    "projectSourceUrl"
    "docsUrl"
    "bugTrackerUrl"
)

for check in "${NUSPEC_CHECKS[@]}"; do
    if grep -q "$check" packages/chocolatey/go-terraform-linter.nuspec; then
        echo "✅ $check found in nuspec"
    else
        echo "❌ $check missing from nuspec!"
        exit 1
    fi
done

echo ""
echo "🎉 All validation checks passed!"
echo "📄 Generated files:"
ls -la packages/chocolatey/
echo ""
ls -la packages/chocolatey/tools/
echo ""
echo "📝 Package ready for submission to Chocolatey!"
echo ""
echo "Next steps:"
echo "1. Test install locally: choco install packages/chocolatey/go-terraform-linter.1.0.3.nupkg"
echo "2. Upload to Chocolatey Community: https://community.chocolatey.org/packages/upload"
echo "3. Address any reviewer feedback" 