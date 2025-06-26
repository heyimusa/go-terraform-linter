.PHONY: build test clean docker docker-dev docker-push homebrew snap chocolatey packages release help

# Variables
BINARY_NAME=go-terraform-linter
VERSION ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo "0.0.1")
COMMIT_HASH=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(shell date +%Y-%m-%dT%H:%M:%S%z)
LDFLAGS=-ldflags="-s -w -X main.version=$(VERSION) -X main.commitHash=$(COMMIT_HASH) -X main.buildTime=$(BUILD_TIME)"

# Docker settings
DOCKER_REGISTRY ?= ghcr.io
DOCKER_REPO ?= heyimusa/go-terraform-linter
DOCKER_TAG ?= $(VERSION)

# Build targets
build: ## Build the binary
	go build $(LDFLAGS) -o $(BINARY_NAME) ./cmd/linter

build-all: ## Build binaries for all platforms
	@mkdir -p dist
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-amd64 ./cmd/linter
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-arm64 ./cmd/linter
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-amd64 ./cmd/linter
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-arm64 ./cmd/linter
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-windows-amd64.exe ./cmd/linter

# Test targets
test: ## Run tests
	go test ./...

test-verbose: ## Run tests with verbose output
	go test -v ./...

test-coverage: ## Run tests with coverage
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Docker targets
docker: ## Build Docker image
	docker build -t $(DOCKER_REPO):$(DOCKER_TAG) .
	docker tag $(DOCKER_REPO):$(DOCKER_TAG) $(DOCKER_REPO):latest

docker-dev: ## Build development Docker image
	docker build -f Dockerfile.dev -t $(DOCKER_REPO):dev .

docker-push: docker ## Build and push Docker image
	docker push $(DOCKER_REGISTRY)/$(DOCKER_REPO):$(DOCKER_TAG)
	docker push $(DOCKER_REGISTRY)/$(DOCKER_REPO):latest

docker-run: ## Run Docker container on current directory
	docker run --rm -v $(PWD):/workspace $(DOCKER_REPO):latest /workspace

docker-compose-up: ## Start services with docker-compose
	docker-compose up --build

docker-compose-test: ## Run tests in docker-compose
	docker-compose run --rm test-runner

# Package managers
homebrew: build-all ## Create Homebrew formula
	@mkdir -p packages/homebrew
	@echo "Creating Homebrew formula..."
	@echo 'class GoTerraformLinter < Formula' > packages/homebrew/go-terraform-linter.rb
	@echo '  desc "A security-focused Terraform linter"' >> packages/homebrew/go-terraform-linter.rb
	@echo '  homepage "https://github.com/heyimusa/go-terraform-linter"' >> packages/homebrew/go-terraform-linter.rb
	@echo '  version "$(VERSION)"' >> packages/homebrew/go-terraform-linter.rb
	@echo '  url "https://github.com/heyimusa/go-terraform-linter/releases/download/$(VERSION)/go-terraform-linter-$$(uname -s | tr A-Z a-z)-$$(uname -m).tar.gz"' >> packages/homebrew/go-terraform-linter.rb
	@echo '  def install' >> packages/homebrew/go-terraform-linter.rb
	@echo '    bin.install "go-terraform-linter"' >> packages/homebrew/go-terraform-linter.rb
	@echo '  end' >> packages/homebrew/go-terraform-linter.rb
	@echo '  test do' >> packages/homebrew/go-terraform-linter.rb
	@echo '    assert_match version.to_s, shell_output("#{bin}/go-terraform-linter --version")' >> packages/homebrew/go-terraform-linter.rb
	@echo '  end' >> packages/homebrew/go-terraform-linter.rb
	@echo 'end' >> packages/homebrew/go-terraform-linter.rb
	@echo "Homebrew formula created at packages/homebrew/go-terraform-linter.rb"

snap: build-all ## Create Snap package
	@mkdir -p packages/snap
	@echo "Creating Snap package..."
	@echo 'name: go-terraform-linter' > packages/snap/snapcraft.yaml
	@echo 'version: "$(VERSION:v%=%)"' >> packages/snap/snapcraft.yaml
	@echo 'summary: A security-focused Terraform linter' >> packages/snap/snapcraft.yaml
	@echo 'description: |' >> packages/snap/snapcraft.yaml
	@echo '  A fast and comprehensive Terraform linter that focuses on security best practices,' >> packages/snap/snapcraft.yaml
	@echo '  resource misconfigurations, and infrastructure vulnerabilities.' >> packages/snap/snapcraft.yaml
	@echo '' >> packages/snap/snapcraft.yaml
	@echo 'grade: stable' >> packages/snap/snapcraft.yaml
	@echo 'confinement: strict' >> packages/snap/snapcraft.yaml
	@echo 'base: core22' >> packages/snap/snapcraft.yaml
	@echo '' >> packages/snap/snapcraft.yaml
	@echo 'apps:' >> packages/snap/snapcraft.yaml
	@echo '  go-terraform-linter:' >> packages/snap/snapcraft.yaml
	@echo '    command: bin/go-terraform-linter' >> packages/snap/snapcraft.yaml
	@echo '    plugs: [home, removable-media]' >> packages/snap/snapcraft.yaml
	@echo '' >> packages/snap/snapcraft.yaml
	@echo 'parts:' >> packages/snap/snapcraft.yaml
	@echo '  go-terraform-linter:' >> packages/snap/snapcraft.yaml
	@echo '    plugin: dump' >> packages/snap/snapcraft.yaml
	@echo '    source: dist/' >> packages/snap/snapcraft.yaml
	@echo '    organize:' >> packages/snap/snapcraft.yaml
	@echo '      go-terraform-linter-linux-amd64: bin/go-terraform-linter' >> packages/snap/snapcraft.yaml
	@echo "Snap package config created at packages/snap/snapcraft.yaml"

chocolatey: build-all ## Create Chocolatey package
	@mkdir -p packages/chocolatey/tools
	@echo "Creating Chocolatey package..."
	@echo "Generating checksum for Windows binary..."
	@cd dist && sha256sum go-terraform-linter-windows-amd64.exe | cut -d' ' -f1 > ../chocolatey-checksum.txt
	@echo '<?xml version="1.0" encoding="utf-8"?>' > packages/chocolatey/go-terraform-linter.nuspec
	@echo '<package xmlns="http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd">' >> packages/chocolatey/go-terraform-linter.nuspec
	@echo '  <metadata>' >> packages/chocolatey/go-terraform-linter.nuspec
	@echo '    <id>go-terraform-linter</id>' >> packages/chocolatey/go-terraform-linter.nuspec
	@echo '    <version>$(VERSION:v%=%)</version>' >> packages/chocolatey/go-terraform-linter.nuspec
	@echo '    <packageSourceUrl>https://github.com/heyimusa/go-terraform-linter</packageSourceUrl>' >> packages/chocolatey/go-terraform-linter.nuspec
	@echo '    <owners>heyimusa</owners>' >> packages/chocolatey/go-terraform-linter.nuspec
	@echo '    <title>Go Terraform Linter</title>' >> packages/chocolatey/go-terraform-linter.nuspec
	@echo '    <authors>heyimusa</authors>' >> packages/chocolatey/go-terraform-linter.nuspec
	@echo '    <projectUrl>https://github.com/heyimusa/go-terraform-linter</projectUrl>' >> packages/chocolatey/go-terraform-linter.nuspec
	@echo '    <iconUrl>https://raw.githubusercontent.com/heyimusa/go-terraform-linter/master/docs/logo.svg</iconUrl>' >> packages/chocolatey/go-terraform-linter.nuspec
	@echo '    <licenseUrl>https://github.com/heyimusa/go-terraform-linter/blob/master/LICENSE</licenseUrl>' >> packages/chocolatey/go-terraform-linter.nuspec
	@echo '    <requireLicenseAcceptance>false</requireLicenseAcceptance>' >> packages/chocolatey/go-terraform-linter.nuspec
	@echo '    <projectSourceUrl>https://github.com/heyimusa/go-terraform-linter</projectSourceUrl>' >> packages/chocolatey/go-terraform-linter.nuspec
	@echo '    <docsUrl>https://github.com/heyimusa/go-terraform-linter/blob/master/docs/README.md</docsUrl>' >> packages/chocolatey/go-terraform-linter.nuspec
	@echo '    <bugTrackerUrl>https://github.com/heyimusa/go-terraform-linter/issues</bugTrackerUrl>' >> packages/chocolatey/go-terraform-linter.nuspec
	@echo '    <releaseNotes>https://github.com/heyimusa/go-terraform-linter/releases/tag/$(VERSION)</releaseNotes>' >> packages/chocolatey/go-terraform-linter.nuspec
	@echo '    <summary>A security-focused Terraform linter</summary>' >> packages/chocolatey/go-terraform-linter.nuspec
	@echo '    <description>A fast and comprehensive Terraform linter that focuses on security best practices, resource misconfigurations, and infrastructure vulnerabilities.</description>' >> packages/chocolatey/go-terraform-linter.nuspec
	@echo '    <tags>terraform security linter infrastructure devops go</tags>' >> packages/chocolatey/go-terraform-linter.nuspec
	@echo '  </metadata>' >> packages/chocolatey/go-terraform-linter.nuspec
	@echo '  <files>' >> packages/chocolatey/go-terraform-linter.nuspec
	@echo '    <file src="tools/**" target="tools" />' >> packages/chocolatey/go-terraform-linter.nuspec
	@echo '  </files>' >> packages/chocolatey/go-terraform-linter.nuspec
	@echo '</package>' >> packages/chocolatey/go-terraform-linter.nuspec
	@echo 'Creating PowerShell install script...'
	@echo '$$ErrorActionPreference = "Stop"' > packages/chocolatey/tools/chocolateyinstall.ps1
	@echo '$$packageName = "go-terraform-linter"' >> packages/chocolatey/tools/chocolateyinstall.ps1
	@echo '$$toolsDir = "$$(Split-Path -parent $$MyInvocation.MyCommand.Definition)"' >> packages/chocolatey/tools/chocolateyinstall.ps1
	@echo '$$url64 = "https://github.com/heyimusa/go-terraform-linter/releases/download/$(VERSION)/go-terraform-linter-windows-amd64.exe"' >> packages/chocolatey/tools/chocolateyinstall.ps1
	@echo '' >> packages/chocolatey/tools/chocolateyinstall.ps1
	@echo '$$packageArgs = @{' >> packages/chocolatey/tools/chocolateyinstall.ps1
	@echo '  packageName   = $$packageName' >> packages/chocolatey/tools/chocolateyinstall.ps1
	@echo '  unzipLocation = $$toolsDir' >> packages/chocolatey/tools/chocolateyinstall.ps1
	@echo '  url64bit      = $$url64' >> packages/chocolatey/tools/chocolateyinstall.ps1
	@echo '  softwareName  = "go-terraform-linter*"' >> packages/chocolatey/tools/chocolateyinstall.ps1
	@CHECKSUM=$$(cat chocolatey-checksum.txt); echo "  checksum64    = \"$$CHECKSUM\"" >> packages/chocolatey/tools/chocolateyinstall.ps1
	@echo '  checksumType64= "sha256"' >> packages/chocolatey/tools/chocolateyinstall.ps1
	@echo '}' >> packages/chocolatey/tools/chocolateyinstall.ps1
	@echo '' >> packages/chocolatey/tools/chocolateyinstall.ps1
	@echo 'Get-ChocolateyWebFile @packageArgs' >> packages/chocolatey/tools/chocolateyinstall.ps1
	@echo 'Install-ChocolateyPath "$$toolsDir" "Machine"' >> packages/chocolatey/tools/chocolateyinstall.ps1
	@cp dist/go-terraform-linter-windows-amd64.exe packages/chocolatey/tools/go-terraform-linter.exe
	@echo 'Creating LICENSE.txt...'
	@echo 'MIT License' > packages/chocolatey/tools/LICENSE.txt
	@echo '' >> packages/chocolatey/tools/LICENSE.txt
	@echo 'Copyright (c) 2024 heyimusa' >> packages/chocolatey/tools/LICENSE.txt
	@echo '' >> packages/chocolatey/tools/LICENSE.txt
	@echo 'Permission is hereby granted, free of charge, to any person obtaining a copy' >> packages/chocolatey/tools/LICENSE.txt
	@echo 'of this software and associated documentation files (the "Software"), to deal' >> packages/chocolatey/tools/LICENSE.txt
	@echo 'in the Software without restriction, including without limitation the rights' >> packages/chocolatey/tools/LICENSE.txt
	@echo 'to use, copy, modify, merge, publish, distribute, sublicense, and/or sell' >> packages/chocolatey/tools/LICENSE.txt
	@echo 'copies of the Software, and to permit persons to whom the Software is' >> packages/chocolatey/tools/LICENSE.txt
	@echo 'furnished to do so, subject to the following conditions:' >> packages/chocolatey/tools/LICENSE.txt
	@echo '' >> packages/chocolatey/tools/LICENSE.txt
	@echo 'The above copyright notice and this permission notice shall be included in all' >> packages/chocolatey/tools/LICENSE.txt
	@echo 'copies or substantial portions of the Software.' >> packages/chocolatey/tools/LICENSE.txt
	@echo '' >> packages/chocolatey/tools/LICENSE.txt
	@echo 'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR' >> packages/chocolatey/tools/LICENSE.txt
	@echo 'IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,' >> packages/chocolatey/tools/LICENSE.txt
	@echo 'FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE' >> packages/chocolatey/tools/LICENSE.txt
	@echo 'AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER' >> packages/chocolatey/tools/LICENSE.txt
	@echo 'LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,' >> packages/chocolatey/tools/LICENSE.txt
	@echo 'OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE' >> packages/chocolatey/tools/LICENSE.txt
	@echo 'SOFTWARE.' >> packages/chocolatey/tools/LICENSE.txt
	@echo 'Creating VERIFICATION.txt...'
	@echo 'VERIFICATION' > packages/chocolatey/tools/VERIFICATION.txt
	@echo 'Verification is intended to assist the Chocolatey moderators and community' >> packages/chocolatey/tools/VERIFICATION.txt
	@echo 'in verifying that this package'\''s contents are trustworthy.' >> packages/chocolatey/tools/VERIFICATION.txt
	@echo '' >> packages/chocolatey/tools/VERIFICATION.txt
	@echo 'Package can be verified like this:' >> packages/chocolatey/tools/VERIFICATION.txt
	@echo '' >> packages/chocolatey/tools/VERIFICATION.txt
	@echo '1. Download:' >> packages/chocolatey/tools/VERIFICATION.txt
	@echo '' >> packages/chocolatey/tools/VERIFICATION.txt
	@echo '   x64: https://github.com/heyimusa/go-terraform-linter/releases/download/$(VERSION)/go-terraform-linter-windows-amd64.exe' >> packages/chocolatey/tools/VERIFICATION.txt
	@echo '' >> packages/chocolatey/tools/VERIFICATION.txt
	@echo '2. You can use one of the following methods to obtain the SHA256 checksum:' >> packages/chocolatey/tools/VERIFICATION.txt
	@echo '   - Use powershell function '\''Get-FileHash'\''' >> packages/chocolatey/tools/VERIFICATION.txt
	@echo '   - Use Chocolatey utility '\''checksum.exe'\''' >> packages/chocolatey/tools/VERIFICATION.txt
	@echo '' >> packages/chocolatey/tools/VERIFICATION.txt
	@echo '   checksum64: ' >> packages/chocolatey/tools/VERIFICATION.txt
	@cat chocolatey-checksum.txt >> packages/chocolatey/tools/VERIFICATION.txt
	@echo '' >> packages/chocolatey/tools/VERIFICATION.txt
	@echo 'File '\''go-terraform-linter.exe'\'' is obtained from:' >> packages/chocolatey/tools/VERIFICATION.txt
	@echo '   https://github.com/heyimusa/go-terraform-linter/releases/download/$(VERSION)/go-terraform-linter-windows-amd64.exe' >> packages/chocolatey/tools/VERIFICATION.txt
	@rm -f chocolatey-checksum.txt
	@echo "Chocolatey package created at packages/chocolatey/"

packages: homebrew snap chocolatey ## Create all package manager configs

# Release targets
checksums: build-all ## Generate checksums for all binaries
	@cd dist && sha256sum * > ../checksums.txt
	@echo "Checksums generated in checksums.txt"

release: clean build-all packages checksums ## Prepare a complete release
	@echo "Release $(VERSION) prepared!"
	@echo "Binaries in dist/"
	@echo "Package configs in packages/"
	@echo "Checksums in checksums.txt"

# Utility targets
install: build ## Install binary to /usr/local/bin
	sudo cp $(BINARY_NAME) /usr/local/bin/

uninstall: ## Remove binary from /usr/local/bin
	sudo rm -f /usr/local/bin/$(BINARY_NAME)

clean: ## Clean build artifacts
	rm -f $(BINARY_NAME)
	rm -rf dist/
	rm -rf packages/
	rm -f checksums.txt coverage.out coverage.html

fmt: ## Format code
	go fmt ./...

lint: ## Run linters
	golangci-lint run

deps: ## Download dependencies
	go mod download
	go mod tidy

dev-setup: ## Set up development environment
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/cosmtrek/air@latest

help: ## Show this help message
	@echo 'Usage:'
	@echo '  make <target>'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST) 