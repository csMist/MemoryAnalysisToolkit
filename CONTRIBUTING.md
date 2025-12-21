# Contributing to memscan-util

Thank you for your interest in contributing to memscan-util! 🎉

This document provides guidelines and information for contributors.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Pull Request Process](#pull-request-process)
- [Style Guidelines](#style-guidelines)
- [Testing](#testing)

## 🤝 Code of Conduct

This project follows a code of conduct to ensure a welcoming environment for all contributors. By participating, you agree to:

- Be respectful and inclusive
- Focus on constructive feedback
- Accept responsibility for mistakes
- Show empathy towards other contributors
- Help create a positive community

## 🚀 Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/yourusername/memscan-util.git
   cd memscan-util
   ```
3. **Create** a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## 🛠️ Development Setup

### Prerequisites

- **C++17 compatible compiler** (GCC 7+, Clang 5+, MSVC 2017+)
- **CMake 3.16+**
- **Git**
- **Platform development tools**

### Building from Source

```bash
# Configure the project
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DMEMSCAN_BUILD_TESTS=ON

# Build the library
cmake --build . --config Debug

# Run tests
ctest --output-on-failure
```

### Development with IDEs

#### Visual Studio Code
- Install C++ extension
- Use CMake Tools extension
- Configure with `CMake: Configure`

#### CLion
- Import as CMake project
- Build targets are automatically detected

#### Visual Studio
- Open the folder containing CMakeLists.txt
- Let Visual Studio detect and configure CMake

## 💡 How to Contribute

### Types of Contributions

- 🐛 **Bug fixes**: Fix existing issues
- ✨ **Features**: Add new functionality
- 📚 **Documentation**: Improve docs, examples, or comments
- 🧪 **Tests**: Add or improve test coverage
- 🔧 **Build/CI**: Improve build system or CI pipelines
- 🎨 **Code style**: Refactor code for better readability

### Finding Issues to Work On

- Check the [Issues](https://github.com/yourusername/memscan-util/issues) tab
- Look for issues labeled `good first issue` or `help wanted`
- Comment on issues you'd like to work on to avoid duplicate work

## 📝 Pull Request Process

1. **Update documentation** for any changed functionality
2. **Add tests** for new features or bug fixes
3. **Ensure all tests pass** locally and in CI
4. **Update CHANGELOG.md** if applicable
5. **Write clear commit messages**

### PR Template

When creating a pull request, please include:

- **Description**: What does this PR do?
- **Type of change**: Bug fix, feature, documentation, etc.
- **Testing**: How was this tested?
- **Breaking changes**: Does this break existing functionality?

## 🎨 Style Guidelines

### C++ Code Style

- **Language**: C++17 standard
- **Naming**: snake_case for variables/functions, PascalCase for types
- **Formatting**: Use consistent indentation (4 spaces)
- **Comments**: Doxygen-style documentation for public APIs
- **Error handling**: Use exceptions appropriately, no silent failures

### Example

```cpp
/**
 * @brief Brief description of the function
 *
 * @param param1 Description of parameter
 * @return Description of return value
 */
ReturnType functionName(ParamType param1) {
    // Implementation
    if (error_condition) {
        throw std::runtime_error("Error message");
    }

    return result;
}
```

### Commit Messages

Follow conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New features
- `fix`: Bug fixes
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test additions/changes
- `chore`: Maintenance tasks

Examples:
```
feat: add SIMD scanning support for SSE2

fix: resolve memory leak in Process::readMemory

docs: update API reference for PatternScanner
```

## 🧪 Testing

### Running Tests

```bash
# Build with tests enabled
cmake .. -DMEMSCAN_BUILD_TESTS=ON
cmake --build .

# Run all tests
ctest --output-on-failure

# Run specific test
ctest -R TestPatternScanner
```

### Writing Tests

- Use Google Test framework
- Place tests in `tests/` directory
- Follow naming convention: `Test<ClassName>.cpp`
- Cover both success and failure cases
- Test edge cases and error conditions

### Performance Testing

```bash
# Build with benchmarks
cmake .. -DMEMSCAN_BUILD_BENCHMARKS=ON
cmake --build .

# Run benchmarks
./benchmarks/memscan-benchmarks
```

## 🔍 Code Review Process

All submissions require review. Reviewers will check for:

- ✅ **Functionality**: Does the code work as intended?
- ✅ **Style**: Follows project conventions?
- ✅ **Tests**: Adequate test coverage?
- ✅ **Documentation**: Clear and complete?
- ✅ **Performance**: No regressions?
- ✅ **Security**: Safe memory handling?

## 📞 Getting Help

- 📖 **Documentation**: Check the [README](README.md) and inline docs
- 💬 **Discussions**: Use GitHub Discussions for questions
- 🐛 **Issues**: Report bugs or request features
- 📧 **Maintainer**: Contact the maintainer for sensitive issues

## 🙏 Recognition

Contributors are recognized in:
- CHANGELOG.md for significant changes
- GitHub's contributor insights
- Release notes

Thank you for contributing to memscan-util! 🚀
