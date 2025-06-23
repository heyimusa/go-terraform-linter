# 🐋 Docker & Package Manager Setup Guide

This guide covers the implementation of Docker and package manager installations for the Go Terraform Linter.

## 📦 What's Been Implemented

### Docker Support ✅

#### Files Created:
- **`Dockerfile`** - Production-ready multi-stage build
- **`Dockerfile.dev`** - Development image with tools
- **`docker-compose.yml`** - Multi-service setup for development
- **`.dockerignore`** - Optimized build context

#### Features:
- Multi-stage build for minimal image size
- Support for both `amd64` and `arm64` architectures
- Automatic publishing to GitHub Container Registry
- Development environment with live reload
- Test runner service

### Package Managers ✅

#### Homebrew
- Auto-generated formula with platform detection
- SHA256 checksums for security
- Proper test integration

#### Snap
- Linux package with proper confinement
- Multi-architecture support
- Home directory access for Terraform files

#### Chocolatey
- Windows package with PowerShell installer
- Checksum verification
- Binary file management

## 🚀 Quick Start

### Using Docker

```bash
# Pull and run latest version
docker pull ghcr.io/heyimusa/go-terraform-linter:latest
docker run --rm -v $(pwd):/workspace ghcr.io/heyimusa/go-terraform-linter:latest /workspace

# Using docker-compose for development
git clone https://github.com/heyimusa/go-terraform-linter.git
cd go-terraform-linter
docker-compose up terraform-linter
```

### Using Package Managers

```bash
# Homebrew (macOS/Linux)
brew tap heyimusa/terraform-linter
brew install terraform-linter

# Snap (Linux)
sudo snap install terraform-linter

# Chocolatey (Windows)
choco install terraform-linter
```

## 🛠️ Development Workflow

### Building Packages Locally

```bash
# Build all packages
make packages

# Build specific packages
make homebrew
make snap
make chocolatey

# Complete release workflow
make release
```

### Testing Installation Methods

```bash
# Run the comprehensive test suite
./scripts/test-installation.sh

# Test specific components
make docker
make docker-run
make docker-compose-up
```

## 📋 Release Process

### Automated Release (Recommended)

1. **Create a Git Tag:**
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

2. **GitHub Actions Workflow:**
   - Builds binaries for all platforms
   - Creates Docker images for `amd64` and `arm64`
   - Generates package manager configs
   - Publishes to GitHub Container Registry
   - Creates GitHub release with assets

### Manual Release

1. **Build Everything:**
   ```bash
   make release
   ```

2. **Docker Build and Push:**
   ```bash
   make docker-push
   ```

3. **Verify Packages:**
   ```bash
   ./scripts/test-installation.sh
   ```

## 🔧 Configuration

### Docker Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `TF_LINTER_VERBOSE` | Enable verbose output | `false` |
| `TF_LINTER_CONFIG` | Config file path | `""` |

### Makefile Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VERSION` | Release version | Git tag or `dev` |
| `DOCKER_REGISTRY` | Container registry | `ghcr.io` |
| `DOCKER_REPO` | Repository name | `heyimusa/go-terraform-linter` |

## 📊 Build Matrix

### Supported Platforms

| OS | Architecture | Binary | Docker | Package Manager |
|----|-------------|--------|--------|----------------|
| Linux | amd64 | ✅ | ✅ | Snap |
| Linux | arm64 | ✅ | ✅ | Snap |
| macOS | amd64 | ✅ | ❌ | Homebrew |
| macOS | arm64 | ✅ | ❌ | Homebrew |
| Windows | amd64 | ✅ | ❌ | Chocolatey |

## 🐛 Troubleshooting

### Docker Issues

**Image won't build:**
```bash
# Clean Docker cache
docker system prune -a

# Build with no cache
docker build --no-cache -t terraform-linter .
```

**Permission denied in container:**
```bash
# Run with current user
docker run --rm -u $(id -u):$(id -g) -v $(pwd):/workspace terraform-linter /workspace
```

### Package Manager Issues

**Homebrew formula errors:**
```bash
# Update checksums
make homebrew
brew install --build-from-source packages/homebrew/terraform-linter.rb
```

**Snap installation fails:**
```bash
# Install in devmode for testing
sudo snap install --devmode packages/snap/terraform-linter_*.snap
```

**Chocolatey checksum mismatch:**
```bash
# Rebuild with correct checksums
make chocolatey
choco install packages/chocolatey/terraform-linter.nupkg --force
```

## 📝 Implementation Details

### CI/CD Pipeline

The `.github/workflows/release.yml` workflow handles:

1. **Build Stage**: Cross-compilation for all platforms
2. **Docker Stage**: Multi-arch image building and publishing
3. **Package Stage**: Generation of package manager configs
4. **Release Stage**: GitHub release creation with all assets

### Docker Multi-Stage Build

```dockerfile
# Stage 1: Build binary
FROM golang:1.21-alpine AS builder
# ... build process ...

# Stage 2: Create minimal runtime image
FROM scratch
COPY --from=builder /app/terraform-linter /usr/local/bin/
# ... runtime setup ...
```

### Package Generation

Each package manager has a dedicated Makefile target that:

1. Builds the binary for the target platform
2. Generates the package configuration
3. Calculates and embeds checksums
4. Creates the package structure

## 🎯 Next Steps

### Immediate Improvements

- [ ] Add ARM64 Windows support when Go supports it
- [ ] Implement automatic Homebrew tap updates
- [ ] Add Snap Store publishing automation
- [ ] Create Chocolatey community package

### Future Enhancements

- [ ] Add APT/DEB package support
- [ ] Implement RPM package support
- [ ] Create Kubernetes Helm chart
- [ ] Add support for more container registries

## 🤝 Contributing

To improve the Docker and package setup:

1. Test installations on your platform
2. Run the test suite: `./scripts/test-installation.sh`
3. Report issues or suggest improvements
4. Submit pull requests with fixes or enhancements

---

**Need help?** Check the main [Installation Guide](INSTALLATION.md) or create an issue on GitHub. 