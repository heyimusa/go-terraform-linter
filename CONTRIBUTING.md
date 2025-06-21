# Contributing to Go Terraform Linter

Thank you for your interest in contributing! 🎉

## Getting Started

1. **Fork the repository** and clone your fork.
2. **Install Go** (version 1.18 or higher recommended).
3. **Install dependencies:**
   ```bash
   go mod download
   ```
4. **Build the project:**
   ```bash
   go build -o tflint cmd/linter/main.go
   ```
5. **Run the linter:**
   ```bash
   ./tflint -c examples/ -v
   ```
6. **Run tests:**
   ```bash
   go test ./...
   ```

## Code Style
- Use `gofmt` and `golint` before submitting code.
- Write clear, descriptive commit messages.
- Keep functions small and focused.
- Add comments for exported functions and complex logic.

## Submitting Issues
- Search [existing issues](https://github.com/heyimusa/go-terraform-linter/issues) before opening a new one.
- Include steps to reproduce, expected behavior, and environment details.

## Pull Requests
- Create a feature or bugfix branch from `main`.
- Open a pull request with a clear description of your changes.
- Reference related issues (e.g., `Fixes #123`).
- Add or update tests as needed.
- Ensure CI checks pass before requesting review.

## Review Process
- At least one approval is required before merging.
- Address all review comments and suggestions.
- Be responsive and respectful in discussions.

## Communication
- Use [GitHub Discussions](https://github.com/heyimusa/go-terraform-linter/discussions) for questions and ideas.
- For sensitive issues, email the maintainers listed in `SECURITY.md`.

## Thank you for helping make this project better! 🙏 