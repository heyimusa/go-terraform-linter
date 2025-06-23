#!/bin/bash

# Test script to verify all installation methods work
set -e

echo "🔧 Testing Go Terraform Linter Installation Methods"
echo "=================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# Function to test Docker installation
test_docker() {
    echo -e "\n📦 Testing Docker Installation..."
    
    if ! command -v docker &> /dev/null; then
        warning "Docker not found, skipping Docker tests"
        return
    fi
    
    # Test if image exists or can be built
    if docker build -t terraform-linter-test . &> /dev/null; then
        success "Docker image builds successfully"
        
        # Test running the image
        if docker run --rm terraform-linter-test --version &> /dev/null; then
            success "Docker container runs successfully"
        else
            error "Docker container failed to run"
        fi
        
        # Cleanup
        docker rmi terraform-linter-test &> /dev/null || true
    else
        error "Docker image build failed"
    fi
}

# Function to test binary build
test_binary_build() {
    echo -e "\n🔨 Testing Binary Build..."
    
    if ! command -v go &> /dev/null; then
        warning "Go not found, skipping binary build test"
        return
    fi
    
    # Test building binary
    if go build -o terraform-linter-test ./cmd/linter; then
        success "Binary builds successfully"
        
        # Test running binary
        if ./terraform-linter-test --version &> /dev/null; then
            success "Binary runs successfully"
            VERSION_OUTPUT=$(./terraform-linter-test --version)
            echo "   Version output: $VERSION_OUTPUT"
        else
            error "Binary failed to run"
        fi
        
        # Cleanup
        rm -f terraform-linter-test
    else
        error "Binary build failed"
    fi
}

# Function to test Makefile targets
test_makefile() {
    echo -e "\n🛠️  Testing Makefile Targets..."
    
    if ! command -v make &> /dev/null; then
        warning "Make not found, skipping Makefile tests"
        return
    fi
    
    # Test basic build
    if make build &> /dev/null; then
        success "make build works"
        rm -f terraform-linter
    else
        error "make build failed"
    fi
    
    # Test package creation
    if make packages &> /dev/null; then
        success "make packages works"
        
        # Check if package files were created
        if [ -f "packages/homebrew/terraform-linter.rb" ]; then
            success "Homebrew formula created"
        else
            error "Homebrew formula not created"
        fi
        
        if [ -f "packages/snap/snapcraft.yaml" ]; then
            success "Snap package config created"
        else
            error "Snap package config not created"
        fi
        
        if [ -f "packages/chocolatey/terraform-linter.nuspec" ]; then
            success "Chocolatey package config created"
        else
            error "Chocolatey package config not created"
        fi
        
        # Cleanup
        rm -rf packages/ dist/
    else
        error "make packages failed"
    fi
}

# Run all tests
main() {
    echo "Starting installation method tests..."
    
    test_binary_build
    test_makefile
    test_docker
    
    echo -e "\n🎉 Installation testing complete!"
    echo "=================================================="
}

# Run main function
main 