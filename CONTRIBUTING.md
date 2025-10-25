# Contributing to DiscourseMap

Thank you for your interest in contributing to DiscourseMap! This document provides guidelines and information for contributors.

## 🤝 How to Contribute

### Reporting Issues
- Use the [GitHub Issues](https://github.com/ibrahmsql/discoursemap/issues) page
- Search existing issues before creating a new one
- Provide detailed information including:
  - Python version
  - Operating system
  - Steps to reproduce
  - Expected vs actual behavior
  - Error messages and stack traces

### Suggesting Features
- Open a [GitHub Discussion](https://github.com/ibrahmsql/discoursemap/discussions) for feature requests
- Describe the use case and expected behavior
- Consider the modular architecture when proposing new features

### Code Contributions

#### Development Setup
```bash
# Clone the repository
git clone https://github.com/ibrahmsql/discoursemap.git
cd discoursemap

# Set up development environment
make dev-setup

# Install development dependencies
pip install -e .[dev,advanced,reporting,integrations]
```

#### Development Workflow
1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/amazing-feature`
3. **Make** your changes following our coding standards
4. **Test** your changes: `make test`
5. **Lint** your code: `make lint`
6. **Format** your code: `make format`
7. **Commit** your changes: `git commit -m 'Add amazing feature'`
8. **Push** to your branch: `git push origin feature/amazing-feature`
9. **Open** a Pull Request

## 📋 Coding Standards

### Python Style Guide
- Follow [PEP 8](https://pep8.org/) style guide
- Use [Black](https://black.readthedocs.io/) for code formatting
- Use [Flake8](https://flake8.pycqa.org/) for linting
- Maximum line length: 127 characters

### Code Quality Checks
```bash
# Format code
make format

# Run linting
make lint

# Run security checks
make security-check

# Run all checks
make check-all
```

### Type Hints
- Use type hints for all function parameters and return values
- Import types from `typing` module when needed

```python
from typing import Dict, List, Optional, Any

def process_results(data: Dict[str, Any]) -> List[str]:
    """Process scan results and return formatted output."""
    return []
```

### Documentation
- Write clear docstrings for all classes and functions
- Use Google-style docstrings
- Include parameter types and descriptions
- Include return value descriptions

```python
def scan_endpoint(self, endpoint: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Scan a specific endpoint for vulnerabilities.
    
    Args:
        endpoint: The endpoint URL to scan
        timeout: Request timeout in seconds
        
    Returns:
        Dictionary containing scan results with keys:
        - 'vulnerabilities': List of found vulnerabilities
        - 'status': Scan status ('completed', 'failed', 'timeout')
        - 'response_time': Time taken for the scan
        
    Raises:
        ValueError: If endpoint URL is invalid
        ConnectionError: If unable to connect to endpoint
    """
```

## 🏗️ Modular Architecture Guidelines

### Creating New Modules

#### Module Structure
```python
#!/usr/bin/env python3
"""
Module Name

Brief description of what this module does.
"""

from typing import Dict, List, Optional, Any
from colorama import Fore, Style


class ModuleName:
    """Brief description of the module."""
    
    def __init__(self, target_url: str, session: Optional[Any] = None,
                 verbose: bool = False):
        """
        Initialize the module.
        
        Args:
            target_url: Target Discourse forum URL
            session: Optional requests session
            verbose: Enable verbose output
        """
        self.target_url = target_url.rstrip('/')
        self.session = session
        self.verbose = verbose
    
    def scan(self) -> Dict[str, Any]:
        """
        Main scanning method.
        
        Returns:
            Dictionary with scan results
        """
        if self.verbose:
            print(f"{Fore.CYAN}[*] Starting module scan...{Style.RESET_ALL}")
        
        results = {
            'vulnerabilities': [],
            'recommendations': [],
            'metadata': {
                'module': self.__class__.__name__,
                'target': self.target_url
            }
        }
        
        # Implementation here
        
        return results
```

#### Module Categories
Place new modules in appropriate categories:

- **`discourse_specific/`** - Discourse-specific functionality
- **`security/testing/`** - General security testing
- **`performance/`** - Performance and load testing
- **`monitoring/`** - Health and uptime monitoring
- **`utilities/`** - Utility functions
- **`integrations/`** - External system integrations

#### Module Registration
1. Add your module to the appropriate `__init__.py` file
2. Update the module manager if needed
3. Add configuration options if required
4. Write unit tests for your module

### Testing Guidelines

#### Unit Tests
- Write tests for all new modules and functions
- Use pytest framework
- Aim for >80% code coverage
- Test both success and failure scenarios

```python
import unittest
from discoursemap.your_module import YourModule

class TestYourModule(unittest.TestCase):
    def setUp(self):
        self.module = YourModule('https://example.com')
    
    def test_scan_returns_dict(self):
        result = self.module.scan()
        self.assertIsInstance(result, dict)
        self.assertIn('vulnerabilities', result)
    
    def test_invalid_url_raises_error(self):
        with self.assertRaises(ValueError):
            YourModule('invalid-url')
```

#### Integration Tests
- Test module interactions
- Test with real (safe) endpoints when possible
- Use mocking for external dependencies

#### Running Tests
```bash
# Run all tests
make test

# Run specific test file
python -m pytest tests/test_your_module.py -v

# Run with coverage
python -m pytest tests/ --cov=discoursemap --cov-report=html
```

## 🔒 Security Guidelines

### Ethical Testing
- Only test systems you own or have explicit permission to test
- Respect rate limits and terms of service
- Implement safe defaults and warnings
- Provide clear documentation about ethical usage

### Security Best Practices
- Validate all inputs
- Use secure defaults
- Implement proper error handling
- Avoid logging sensitive information
- Use parameterized queries for database operations

### Vulnerability Reporting
If you discover security vulnerabilities:
1. **DO NOT** open a public issue
2. Email ibrahimsql@proton.me with details
3. Allow time for assessment and patching
4. Follow responsible disclosure practices

## 📚 Documentation

### Code Documentation
- Write clear, concise docstrings
- Include usage examples
- Document configuration options
- Update README.md for new features

### Architecture Documentation
- Update MODULAR_ARCHITECTURE.md for structural changes
- Document new module categories
- Include integration examples
- Maintain API documentation

## 🎯 Pull Request Guidelines

### Before Submitting
- [ ] Code follows style guidelines
- [ ] Tests pass locally
- [ ] New tests added for new functionality
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] No merge conflicts

### PR Description Template
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests pass
```

### Review Process
1. Automated checks must pass
2. Code review by maintainers
3. Testing in different environments
4. Documentation review
5. Final approval and merge

## 🏷️ Release Process

### Version Numbering
We follow [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist
- [ ] Update version in `__init__.py`
- [ ] Update CHANGELOG.md
- [ ] Create release notes
- [ ] Tag release
- [ ] Build and test packages
- [ ] Deploy to PyPI
- [ ] Update Docker images

## 🤔 Questions?

- **General Questions**: [GitHub Discussions](https://github.com/ibrahmsql/discoursemap/discussions)
- **Bug Reports**: [GitHub Issues](https://github.com/ibrahmsql/discoursemap/issues)
- **Security Issues**: ibrahimsql@proton.me
- **Direct Contact**: ibrahimsql@proton.me

## 📄 License

By contributing to DiscourseMap, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to DiscourseMap! 🙏