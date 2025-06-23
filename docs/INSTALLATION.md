# 🏗️ Installation Guide

This guide covers all the ways to install and set up the Go Terraform Linter.

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Installation Methods](#installation-methods)
- [Binary Installation](#binary-installation)
- [Source Installation](#source-installation)
- [Docker Installation](#docker-installation)
- [Package Managers](#package-managers)
- [Verification](#verification)
- [Updating](#updating)
- [Uninstallation](#uninstallation)

## 🔧 Prerequisites

### System Requirements
- **Operating System**: Linux, macOS, Windows
- **Architecture**: amd64, arm64
- **Memory**: Minimum 256MB RAM
- **Disk Space**: 50MB for installation

### For Source Installation
- **Go**: Version 1.21 or higher
- **Git**: For cloning the repository
- **Make**: (Optional) For using Makefile commands

### Verify Go Installation
```bash
go version
# Should output: go version go1.21.x linux/amd64 (or your platform)
```

## 🚀 Installation Methods

### Method 1: Binary Installation (Recommended)

#### Download Latest Release
```bash
# Linux/macOS
curl -L https://github.com/heyimusa/go-terraform-linter/releases/latest/download/terraform-linter-linux-amd64 -o terraform-linter
chmod +x terraform-linter
sudo mv terraform-linter /usr/local/bin/

# Verify installation
terraform-linter --help
```

#### Windows
```powershell
# Download from GitHub releases
# https://github.com/heyimusa/go-terraform-linter/releases/latest

# Or use PowerShell
Invoke-WebRequest -Uri "https://github.com/heyimusa/go-terraform-linter/releases/latest/download/terraform-linter-windows-amd64.exe" -OutFile "terraform-linter.exe"

# Add to PATH or place in desired directory
```

### Method 2: Source Installation

#### Quick Install
```bash
# Clone and build in one command
git clone https://github.com/heyimusa/go-terraform-linter.git && \
cd go-terraform-linter && \
go build -o terraform-linter ./cmd/linter && \
sudo mv terraform-linter /usr/local/bin/
```

#### Detailed Install
```bash
# 1. Clone the repository
git clone https://github.com/heyimusa/go-terraform-linter.git
cd go-terraform-linter

# 2. Download dependencies
go mod download

# 3. Run tests (optional but recommended)
go test ./...

# 4. Build the binary
go build -o terraform-linter ./cmd/linter

# 5. Install system-wide (optional)
sudo mv terraform-linter /usr/local/bin/

# 6. Verify installation
terraform-linter --version
```

#### Development Installation
```bash
# For development with hot reload
git clone https://github.com/heyimusa/go-terraform-linter.git
cd go-terraform-linter

# Install development dependencies
go mod download

# Run in development mode
go run ./cmd/linter --help

# Or build with debug symbols
go build -gcflags="all=-N -l" -o terraform-linter-debug ./cmd/linter
```

### Method 3: Go Install

```bash
# Install latest version
go install github.com/heyimusa/go-terraform-linter/cmd/linter@latest

# Install specific version
go install github.com/heyimusa/go-terraform-linter/cmd/linter@v1.0.0

# The binary will be installed to $GOPATH/bin or $HOME/go/bin
```

### Method 4: Docker Installation

#### Pull and Run
```bash
# Pull the latest image
docker pull ghcr.io/heyimusa/go-terraform-linter:latest

# Run on current directory
docker run --rm -v $(pwd):/workspace ghcr.io/heyimusa/go-terraform-linter:latest /workspace

# Run with specific output format
docker run --rm -v $(pwd):/workspace -v $(pwd)/output:/output \
  ghcr.io/heyimusa/go-terraform-linter:latest \
  /workspace --format json --output /output/report.json

# Create an alias for easy use
echo 'alias terraform-linter="docker run --rm -v \$(pwd):/workspace ghcr.io/heyimusa/go-terraform-linter:latest"' >> ~/.bashrc
source ~/.bashrc

# Test the alias
terraform-linter /workspace --help
```

#### Build Your Own Image
```bash
# Clone the repository
git clone https://github.com/heyimusa/go-terraform-linter.git
cd go-terraform-linter

# Build the production image
docker build -t terraform-linter .

# Or build the development image
docker build -f Dockerfile.dev -t terraform-linter:dev .

# Run the production image
docker run --rm -v $(pwd)/examples:/workspace terraform-linter /workspace

# Run with docker-compose (includes examples)
docker-compose up terraform-linter
```

#### Using Docker Compose
```bash
# Clone and run with docker-compose
git clone https://github.com/heyimusa/go-terraform-linter.git
cd go-terraform-linter

# Run linter on examples
docker-compose up terraform-linter

# Run in development mode
docker-compose up terraform-linter-dev

# Run tests
docker-compose up test-runner
```

#### Using Makefile (Recommended for Development)
```bash
# Build Docker image
make docker

# Run Docker image on current directory
make docker-run

# Push to registry (maintainers only)
make docker-push

# Run with docker-compose
make docker-compose-up
```

### Method 5: Package Managers

#### Homebrew (macOS/Linux)
```bash
# Method 1: Using Homebrew tap (recommended)
brew tap heyimusa/terraform-linter
brew install terraform-linter

# Method 2: Install directly from URL
brew install heyimusa/terraform-linter/terraform-linter

# Method 3: Install from local formula (for development)
# Download the formula from releases and install
curl -L https://github.com/heyimusa/go-terraform-linter/releases/latest/download/terraform-linter.rb -o terraform-linter.rb
brew install --formula terraform-linter.rb

# Verify installation
terraform-linter --version
brew test terraform-linter
```

#### Snap (Linux)
```bash
# Method 1: Install from Snap Store
sudo snap install terraform-linter

# Method 2: Install from GitHub releases
# Download the .snap file from releases page
curl -L https://github.com/heyimusa/go-terraform-linter/releases/latest/download/terraform-linter_linux_amd64.snap -o terraform-linter.snap
sudo snap install --dangerous terraform-linter.snap

# Method 3: Build and install locally
git clone https://github.com/heyimusa/go-terraform-linter.git
cd go-terraform-linter
make snap
sudo snap install --dangerous packages/snap/terraform-linter_*.snap

# Verify installation
terraform-linter --version
snap info terraform-linter
```

#### Chocolatey (Windows)
```powershell
# Method 1: Install from Chocolatey community repository
choco install terraform-linter

# Method 2: Install from GitHub releases
# Download the .nupkg file from releases page
$url = "https://github.com/heyimusa/go-terraform-linter/releases/latest/download/terraform-linter.nupkg"
Invoke-WebRequest -Uri $url -OutFile "terraform-linter.nupkg"
choco install terraform-linter.nupkg

# Method 3: Build and install locally
git clone https://github.com/heyimusa/go-terraform-linter.git
cd go-terraform-linter
# Requires chocolatey pack tools
make chocolatey
choco install packages/chocolatey/terraform-linter.nupkg

# Verify installation
terraform-linter --version
choco list terraform-linter
```

#### Package Creation (For Maintainers)
```bash
# Build all packages using Makefile
make packages

# Or build individually
make homebrew  # Creates Homebrew formula
make snap      # Creates Snap package config  
make chocolatey # Creates Chocolatey package

# Complete release process
make release   # Builds binaries, packages, and checksums

# Setup publishing to official repositories
./scripts/setup-package-publishing.sh
```

**📝 For Package Publishing**: See the [Package Publishing Guide](PUBLISHING_PACKAGES.md) for detailed instructions on how to publish to official Homebrew, Snap, and Chocolatey repositories.

## ✅ Verification

### Check Installation
```bash
# Verify the binary is installed
which terraform-linter
# Output: /usr/local/bin/terraform-linter

# Check version
terraform-linter --version
# Output: terraform-linter version 1.0.0

# Test basic functionality
terraform-linter --help
```

### Test with Sample File
```bash
# Create a test Terraform file
cat > test.tf << EOF
resource "aws_s3_bucket" "test" {
  bucket = "my-test-bucket"
  acl    = "public-read"
}
EOF

# Run the linter
terraform-linter .

# Should detect security issues
```

## 🔄 Updating

### Binary Installation
```bash
# Download and replace the binary
curl -L https://github.com/heyimusa/go-terraform-linter/releases/latest/download/terraform-linter-linux-amd64 -o /tmp/terraform-linter-new
chmod +x /tmp/terraform-linter-new
sudo mv /tmp/terraform-linter-new /usr/local/bin/terraform-linter
```

### Source Installation
```bash
cd go-terraform-linter
git pull origin main
go build -o terraform-linter ./cmd/linter
sudo mv terraform-linter /usr/local/bin/
```

### Go Install
```bash
go install github.com/heyimusa/go-terraform-linter/cmd/linter@latest
```

### Docker
```bash
docker pull ghcr.io/heyimusa/go-terraform-linter:latest
```

## 🗑️ Uninstallation

### Remove Binary
```bash
sudo rm /usr/local/bin/terraform-linter
```

### Remove Source Installation
```bash
rm -rf go-terraform-linter/
```

### Remove Go Install
```bash
rm $GOPATH/bin/linter
# or
rm $HOME/go/bin/linter
```

### Remove Docker
```bash
docker rmi ghcr.io/heyimusa/go-terraform-linter:latest
```

## 🔧 Advanced Installation

### Custom Installation Directory
```bash
# Install to custom directory
go build -o ~/bin/terraform-linter ./cmd/linter

# Add to PATH
echo 'export PATH=$PATH:~/bin' >> ~/.bashrc
source ~/.bashrc
```

### Multiple Versions
```bash
# Install multiple versions
go build -o terraform-linter-v1.0.0 ./cmd/linter
go build -o terraform-linter-latest ./cmd/linter

# Use specific version
./terraform-linter-v1.0.0 --version
```

### Cross-Platform Build
```bash
# Build for different platforms
GOOS=linux GOARCH=amd64 go build -o terraform-linter-linux ./cmd/linter
GOOS=darwin GOARCH=amd64 go build -o terraform-linter-darwin ./cmd/linter
GOOS=windows GOARCH=amd64 go build -o terraform-linter-windows.exe ./cmd/linter
```

## 🐛 Troubleshooting

### Common Issues

#### Permission Denied
```bash
# Fix: Make the binary executable
chmod +x terraform-linter
```

#### Command Not Found
```bash
# Fix: Add to PATH or use full path
export PATH=$PATH:/usr/local/bin
# or
/usr/local/bin/terraform-linter --help
```

#### Go Version Issues
```bash
# Check Go version
go version

# Update Go if needed
# Follow: https://golang.org/doc/install
```

#### Build Failures
```bash
# Clean module cache
go clean -modcache

# Re-download dependencies
go mod download

# Try building again
go build ./cmd/linter
```

### Getting Help

If you encounter issues:

1. Check the [Troubleshooting Guide](TROUBLESHOOTING.md)
2. Search [existing issues](https://github.com/heyimusa/go-terraform-linter/issues)
3. Create a [new issue](https://github.com/heyimusa/go-terraform-linter/issues/new)

---

**Next Steps**: Check out the [Usage Guide](USAGE.md) to learn how to use the linter effectively. 