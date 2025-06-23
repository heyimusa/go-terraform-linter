#!/bin/bash

# Setup script for package publishing
set -e

echo "🚀 Setting up Package Publishing for Go Terraform Linter"
echo "========================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
}

# Function to setup Homebrew Tap
setup_homebrew() {
    echo -e "\n🍺 Setting up Homebrew Tap..."
    
    # Store original directory
    ORIGINAL_DIR=$(pwd)
    
    info "1. Create a new GitHub repository named 'homebrew-terraform-linter'"
    info "   Go to: https://github.com/new"
    info "   Repository name: homebrew-terraform-linter"
    info "   Make it public"
    
    read -p "Press Enter when you've created the repository..."
    
    if [ -d "../homebrew-terraform-linter" ]; then
        warning "Directory ../homebrew-terraform-linter already exists"
    else
        info "2. Cloning your Homebrew tap repository..."
        cd ..
        git clone https://github.com/heyimusa/homebrew-terraform-linter.git
        cd homebrew-terraform-linter
        
        info "3. Setting up Formula directory..."
        mkdir -p Formula
        
        # Generate a basic formula
        cat > Formula/terraform-linter.rb << 'EOF'
class TerraformLinter < Formula
  desc "A security-focused Terraform linter"
  homepage "https://github.com/heyimusa/go-terraform-linter"
  url "https://github.com/heyimusa/go-terraform-linter/releases/download/v1.0.0/terraform-linter-darwin-amd64"
  version "1.0.0"
  sha256 "REPLACE_WITH_ACTUAL_SHA256"

  def install
    bin.install "terraform-linter-darwin-amd64" => "terraform-linter"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/terraform-linter --version")
  end
end
EOF
        
        git add .
        git commit -m "Initial terraform-linter formula"
        git push origin main
        
        cd "$ORIGINAL_DIR"
        success "Homebrew tap repository created successfully!"
    fi
    
    info "4. Create a Personal Access Token for GitHub Actions:"
    info "   Go to: https://github.com/settings/tokens"
    info "   Create a token with 'repo' permissions"
    info "   Add it as 'HOMEBREW_TAP_TOKEN' secret in your repository settings"
    
    success "Homebrew setup complete! Users can install with:"
    echo "   brew tap heyimusa/terraform-linter"
    echo "   brew install terraform-linter"
}

# Function to setup Snap
setup_snap() {
    echo -e "\n📦 Setting up Snap Store Publishing..."
    
    if ! command -v snapcraft &> /dev/null; then
        info "Installing snapcraft..."
        sudo snap install snapcraft --classic
    else
        success "snapcraft is already installed"
    fi
    
    info "1. Login to your Ubuntu One account:"
    snapcraft login
    
    info "2. Registering snap name (this may fail if already taken):"
    if snapcraft register terraform-linter; then
        success "Snap name 'terraform-linter' registered successfully!"
    else
        warning "Snap name may already be registered or unavailable"
        info "Try a different name like 'go-terraform-linter' or 'tf-security-linter'"
    fi
    
    info "3. Export credentials for CI/CD:"
    info "Run this command and save the output as SNAPCRAFT_TOKEN secret:"
    echo "snapcraft export-login --snaps terraform-linter --channels stable -"
    
    success "Snap setup started! Complete the token export for full automation."
}

# Function to setup Chocolatey
setup_chocolatey() {
    echo -e "\n🍫 Setting up Chocolatey Publishing..."
    
    info "1. Create a Chocolatey account:"
    info "   Go to: https://chocolatey.org/account/Register"
    
    info "2. Get your API key:"
    info "   After login, go to: https://chocolatey.org/account"
    info "   Copy your API key"
    
    info "3. Test package generation:"
    if make chocolatey &> /dev/null; then
        success "Chocolatey package configuration created successfully!"
        info "Package files created in packages/chocolatey/"
    else
        error "Failed to generate Chocolatey package"
    fi
    
    info "4. Add your API key as 'CHOCOLATEY_API_KEY' secret in GitHub repository settings"
    
    success "Chocolatey setup instructions provided!"
    warning "Note: Chocolatey packages require manual review for first-time publishers"
}

# Function to update GitHub Actions workflow
update_workflow() {
    echo -e "\n🔄 Updating GitHub Actions Workflow..."
    
    if [ -f ".github/workflows/publish-packages.yml" ]; then
        warning "publish-packages.yml already exists"
    else
        info "Creating automated publishing workflow..."
        
        cat > .github/workflows/publish-packages.yml << 'EOF'
name: Publish Packages

on:
  release:
    types: [published]
  workflow_dispatch:
    inputs:
      version:
        description: 'Version to publish (e.g., v1.0.0)'
        required: true

jobs:
  publish-homebrew:
    runs-on: ubuntu-latest
    if: github.repository == 'heyimusa/go-terraform-linter'
    steps:
      - uses: actions/checkout@v4
      
      - name: Update Homebrew Tap
        uses: mislav/bump-homebrew-formula-action@v3
        with:
          formula-name: terraform-linter
          formula-path: Formula/terraform-linter.rb
          homebrew-tap: heyimusa/homebrew-terraform-linter
          base-branch: main
          download-url: https://github.com/heyimusa/go-terraform-linter/releases/download/${{ github.ref_name }}/terraform-linter-darwin-amd64
        env:
          COMMITTER_TOKEN: ${{ secrets.HOMEBREW_TAP_TOKEN }}

  publish-snap:
    runs-on: ubuntu-latest
    if: github.repository == 'heyimusa/go-terraform-linter'
    steps:
      - uses: actions/checkout@v4
      
      - name: Build Snap
        uses: snapcore/action-build@v1
        id: build
      
      - name: Upload to Snap Store
        uses: snapcore/action-publish@v1
        env:
          SNAPCRAFT_STORE_CREDENTIALS: ${{ secrets.SNAPCRAFT_TOKEN }}
        with:
          snap: ${{ steps.build.outputs.snap }}
          release: stable

  publish-chocolatey:
    runs-on: windows-latest
    if: github.repository == 'heyimusa/go-terraform-linter'
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Chocolatey
        run: |
          Set-ExecutionPolicy Bypass -Scope Process -Force
          [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
          iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
      
      - name: Generate Package
        run: make chocolatey
      
      - name: Publish to Chocolatey
        run: |
          choco apikey --key ${{ secrets.CHOCOLATEY_API_KEY }} --source https://push.chocolatey.org/
          choco push packages/chocolatey/terraform-linter.nupkg --source https://push.chocolatey.org/
EOF
        
        success "GitHub Actions workflow created at .github/workflows/publish-packages.yml"
    fi
}

# Main menu
main() {
    echo "Choose what you want to set up:"
    echo "1) Homebrew Tap (Recommended - start here)"
    echo "2) Snap Store"
    echo "3) Chocolatey Community"
    echo "4) Update GitHub Actions workflow"
    echo "5) All of the above"
    echo "6) Show summary of required secrets"
    
    read -p "Enter your choice (1-6): " choice
    
    case $choice in
        1)
            setup_homebrew
            ;;
        2)
            setup_snap
            ;;
        3)
            setup_chocolatey
            ;;
        4)
            update_workflow
            ;;
        5)
            setup_homebrew
            setup_snap
            setup_chocolatey
            update_workflow
            ;;
        6)
            show_secrets_summary
            ;;
        *)
            error "Invalid choice"
            exit 1
            ;;
    esac
}

# Function to show required secrets
show_secrets_summary() {
    echo -e "\n🔑 Required GitHub Secrets Summary"
    echo "=================================="
    echo ""
    echo "Add these secrets to your GitHub repository settings:"
    echo "Go to: https://github.com/heyimusa/go-terraform-linter/settings/secrets/actions"
    echo ""
    echo "1. HOMEBREW_TAP_TOKEN"
    echo "   - Personal Access Token with 'repo' permissions"
    echo "   - Get from: https://github.com/settings/tokens"
    echo ""
    echo "2. SNAPCRAFT_TOKEN"
    echo "   - Export from: snapcraft export-login --snaps terraform-linter --channels stable -"
    echo "   - Requires Ubuntu One account and registered snap name"
    echo ""
    echo "3. CHOCOLATEY_API_KEY"
    echo "   - Get from: https://chocolatey.org/account (after creating account)"
    echo ""
    echo "🚀 Once all secrets are added, your packages will auto-publish on release!"
}

# Run main function
main

echo ""
success "Package publishing setup complete!"
info "Next steps:"
echo "1. Add required secrets to GitHub repository settings"
echo "2. Create a release tag: git tag v1.0.0 && git push origin v1.0.0"
echo "3. Your packages will be automatically published!"
echo ""
info "For detailed instructions, see: docs/PUBLISHING_PACKAGES.md" 