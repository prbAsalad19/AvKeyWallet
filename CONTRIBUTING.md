# Contributing to Secure Vault Manager 🚀

First off, thank you for considering contributing to avKeyWallet! It's contributions like yours that make the open-source community an amazing place to learn, inspire, and create.

All types of contributions are welcome: bug fixes, feature requests, documentation improvements, and code refactoring.

---

## How Can I Contribute?

### 1. Reporting Bugs
Before opening a new issue, please search the existing issues to see if the bug has already been reported. 

When creating a bug report, please include:
- Your Operating System (Linux distribution, Windows version, macOS).
- Compiler version (`g++ --version`, `clang --version`, or MSVC version).
- Steps to reproduce the issue.
- Expected vs. actual behavior.

### 2. Suggesting Features
Enhancements and feature requests are very welcome! Please open an issue describing:
- The problem your feature solves.
- How you envision the feature working in the CLI.

### 3. Submitting Pull Requests (PRs)
1. **Fork** the repository and create your branch from `main`:
   ```bash
   git checkout -b feature/amazing-feature

Build and test your changes locally to ensure there are no build errors or broken features.
Make sure your code adheres to modern C++17 standards.
Commit your changes with clear, descriptive commit messages:
   ```bash
   git commit -m "feat: add clipboard support for password copying"
```
Push to your fork and submit a Pull Request.


### Coding Guidelines & Conventions

- C++ Standard: C++17.
- Security First: Never bypass sodium_malloc or sodium_memzero when handling sensitive buffers (passwords, master keys, plaintext data).
- Code Style: Keep code clean, readable, and self-documenting. Use const correctness and RAII where applicable.
- Cross-Platform: Ensure any system call or platform-specific logic is properly guarded using #if defined(_WIN32) / #else blocks.

### License
By contributing to this project, you agree that your contributions will be licensed under the project's **MIT License**.

---
