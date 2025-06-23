# 📦 Publishing Packages to Official Repositories

This guide explains how to publish your Go Terraform Linter to official package manager repositories.

## 🍺 Homebrew Publication

### Option 1: Create Your Own Tap (Recommended)

A "tap" is a third-party Homebrew repository. This is the easiest way to distribute your package.

#### Step 1: Create a Homebrew Tap Repository

```bash
# Create a new GitHub repository named "homebrew-terraform-linter"
# The name MUST start with "homebrew-" for Homebrew to recognize it

# Clone your new tap repository
git clone https://github.com/heyimusa/homebrew-terraform-linter.git
cd homebrew-terraform-linter

# Create the Formula directory
mkdir -p Formula

# Copy your generated formula
cp ../go-terraform-linter/packages/homebrew/terraform-linter.rb Formula/

# Commit and push
git add .
git commit -m "Add terraform-linter formula"
git push origin main
```

#### Step 2: Update Your Release Workflow

Add this to your `.github/workflows/release.yml`:

```yaml
- name: Update Homebrew Tap
  if: startsWith(github.ref, 'refs/tags/')
  uses: mislav/bump-homebrew-formula-action@v3
  with:
    formula-name: terraform-linter
    formula-path: Formula/terraform-linter.rb
    homebrew-tap: heyimusa/homebrew-terraform-linter
    base-branch: main
    download-url: https://github.com/heyimusa/go-terraform-linter/releases/download/${{ github.ref_name }}/terraform-linter-darwin-amd64
    commit-message: |
      {{formulaName}} {{version}}

      Created by https://github.com/mislav/bump-homebrew-formula-action
  env:
    COMMITTER_TOKEN: ${{ secrets.COMMITTER_TOKEN }}
```

#### Step 3: Users Install Via Your Tap

```bash
brew tap heyimusa/terraform-linter
brew install terraform-linter
```

### Option 2: Submit to Homebrew Core (For Popular Packages)

This is for packages that meet Homebrew's acceptance criteria:

1. **Requirements**:
   - Package must be notable/popular
   - Stable, versioned releases
   - No duplicates of existing packages
   - Open source license

2. **Process**:
   ```bash
   # Fork https://github.com/Homebrew/homebrew-core
   # Add your formula to Formula/terraform-linter.rb
   # Submit a Pull Request
   ```

## 📦 Snap Store Publication

### Step 1: Register as a Snap Developer

```bash
# Install snapcraft
sudo snap install snapcraft --classic

# Login to your Ubuntu One account
snapcraft login

# Register your snap name (one-time only)
snapcraft register terraform-linter
```

### Step 2: Build and Publish Your Snap

```bash
# Build the snap package
cd go-terraform-linter
snapcraft

# Upload to store (will create a snap file)
snapcraft upload terraform-linter_*.snap

# Release to specific channels
snapcraft release terraform-linter <revision> stable
```

### Step 3: Automate with GitHub Actions

Add this to your release workflow:

```yaml
- name: Build and Publish Snap
  uses: snapcore/action-build@v1
  with:
    snapcraft-channel: stable

- name: Upload to Snap Store
  uses: snapcore/action-publish@v1
  env:
    SNAPCRAFT_STORE_CREDENTIALS: ${{ secrets.SNAPCRAFT_TOKEN }}
  with:
    snap: terraform-linter_*.snap
    release: stable
```

### Step 4: Get Your Snap Store Token

```bash
# Export login credentials for CI/CD
snapcraft export-login --snaps terraform-linter --channels stable -

# Add the output as SNAPCRAFT_TOKEN secret in GitHub
```

## 🍫 Chocolatey Community Repository

### Step 1: Create a Chocolatey Account

1. Go to [chocolatey.org](https://chocolatey.org/)
2. Create an account
3. Get your API key from your profile

### Step 2: Prepare Your Package

```bash
# Generate the package
make chocolatey

# Install Chocolatey CLI tools (Windows)
# OR use Docker for cross-platform development
docker run --rm -v $(pwd):/workspace chocolatey/choco:latest
```

### Step 3: Test Your Package Locally

```bash
# Test installation locally
choco install packages/chocolatey/terraform-linter.nupkg --source .

# Test uninstallation
choco uninstall terraform-linter
```

### Step 4: Submit to Community Repository

#### Manual Submission:
```bash
# Push package to community repository
choco push packages/chocolatey/terraform-linter.nupkg --source https://push.chocolatey.org/ --api-key YOUR_API_KEY
```

#### Automated with GitHub Actions:
```yaml
- name: Publish to Chocolatey
  if: startsWith(github.ref, 'refs/tags/')
  run: |
    choco apikey --key ${{ secrets.CHOCOLATEY_API_KEY }} --source https://push.chocolatey.org/
    choco push packages/chocolatey/terraform-linter.nupkg --source https://push.chocolatey.org/
```

### Step 5: Package Review Process

- Chocolatey packages undergo a review process
- Initial packages may take several days to approve
- Subsequent updates are usually faster

## 🔄 Automated Publishing Workflow

### Complete GitHub Actions Workflow

```yaml
name: Publish Packages

on:
  release:
    types: [published]

jobs:
  publish-homebrew:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Update Homebrew Tap
        uses: mislav/bump-homebrew-formula-action@v3
        with:
          formula-name: terraform-linter
          homebrew-tap: heyimusa/homebrew-terraform-linter
          download-url: ${{ github.event.release.assets[0].browser_download_url }}
        env:
          COMMITTER_TOKEN: ${{ secrets.HOMEBREW_TAP_TOKEN }}

  publish-snap:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: snapcore/action-build@v1
      - uses: snapcore/action-publish@v1
        env:
          SNAPCRAFT_STORE_CREDENTIALS: ${{ secrets.SNAPCRAFT_TOKEN }}
        with:
          snap: terraform-linter_*.snap
          release: stable

  publish-chocolatey:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Chocolatey
        run: |
          Set-ExecutionPolicy Bypass -Scope Process -Force
          iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
      - name: Build Package
        run: make chocolatey
      - name: Publish Package
        run: |
          choco apikey --key ${{ secrets.CHOCOLATEY_API_KEY }} --source https://push.chocolatey.org/
          choco push packages/chocolatey/terraform-linter.nupkg --source https://push.chocolatey.org/
```

## 🔑 Required Secrets

Add these secrets to your GitHub repository settings:

### Homebrew
- `HOMEBREW_TAP_TOKEN` - Personal Access Token with repo permissions

### Snap Store  
- `SNAPCRAFT_TOKEN` - Export from `snapcraft export-login`

### Chocolatey
- `CHOCOLATEY_API_KEY` - From your Chocolatey profile

## 📋 Pre-Publication Checklist

### General
- [ ] Stable version number (no dev/beta in package managers)
- [ ] Proper LICENSE file
- [ ] README with clear usage instructions
- [ ] Tested on target platforms

### Homebrew
- [ ] Formula passes `brew audit --strict terraform-linter`
- [ ] Package builds successfully on macOS
- [ ] No conflicting package names

### Snap
- [ ] Snap builds without errors
- [ ] Confinement is appropriate (strict recommended)
- [ ] App has proper interface plugs

### Chocolatey
- [ ] Package installs/uninstalls cleanly
- [ ] PowerShell scripts are signed (recommended)
- [ ] No malware/false positives in scanners

## 🚀 Getting Started

1. **Start with Homebrew Tap** - Easiest to set up and maintain
2. **Add Snap Store** - Good Linux coverage, automated publishing
3. **Submit to Chocolatey** - Windows users, requires review process

## 📞 Support

If you encounter issues:
- **Homebrew**: Check [Homebrew docs](https://docs.brew.sh/Formula-Cookbook)
- **Snap**: Visit [Snapcraft.io docs](https://snapcraft.io/docs)
- **Chocolatey**: See [Chocolatey docs](https://docs.chocolatey.org/en-us/create/create-packages)

---

Remember: Package publication is a one-time setup. Once configured, your CI/CD pipeline will automatically update packages when you create new releases! 