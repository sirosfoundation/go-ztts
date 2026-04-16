# Contributing to go-ztts

Thank you for your interest in contributing to go-ztts! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

This project follows standard open source community guidelines. Please be respectful and professional in all interactions.

## Getting Started

### Prerequisites

- Go 1.26 or later
- Make
- Git

### Initial Setup

1. **Fork the repository** on GitHub

2. **Clone your fork**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/go-ztts.git
   cd go-ztts
   ```

3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/sirosfoundation/go-ztts.git
   ```

4. **Run the setup script**:
   ```bash
   make setup
   ```

## Development Workflow

### 1. Create a Feature Branch

```bash
git checkout main
git pull upstream main
git checkout -b feature/my-new-feature
```

Branch naming conventions:
- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation updates
- `test/` - Test additions or improvements
- `refactor/` - Code refactoring

### 2. Make Your Changes

- Write clean, idiomatic Go code
- Add tests for new functionality
- Update documentation as needed

### 3. Test Your Changes

```bash
# Run all checks (format, vet, test)
make check

# Run tests with race detection
make test

# Check coverage
make coverage-cli

# Run linters
golangci-lint run ./...
```

### 4. Commit Your Changes

Write clear, descriptive commit messages following [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: Add CRL hot-reload support
fix: Correct scope validation edge case
docs: Update configuration reference
test: Add edge case tests for renewal gate
```

### 5. Push and Create Pull Request

```bash
git push origin feature/my-new-feature
```

Then create a Pull Request on GitHub.

## Coding Standards

- Follow [Effective Go](https://golang.org/doc/effective_go.html)
- Use `gofmt` for formatting
- Pass `go vet` and `golangci-lint` without warnings
- Always check and handle errors
- Wrap errors with context using `fmt.Errorf` with `%w`
- Use table-driven tests for multiple scenarios

## Testing

- All new features must include tests
- Bug fixes should include regression tests
- Aim for >80% code coverage overall
- Use `-race` flag for race detection

## Pull Request Guidelines

1. Ensure all CI checks pass
2. Code coverage should not decrease
3. Write a clear PR description explaining what and why
4. Keep PRs focused and reasonably sized

## License

By contributing, you agree that your contributions will be licensed under the BSD 2-Clause License.
