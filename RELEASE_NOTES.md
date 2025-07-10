# DiscourseMap v1.1.0 Release Notes

## 🚀 What's New in v1.1.0

DiscourseMap'in en stabil sürümü artık burada! Bu sürümde kritik hata düzeltmeleri ve paket yapısı iyileştirmeleri bulunuyor.

## 🔧 Major Bug Fixes

### ModuleNotFoundError Completely Resolved
- ✅ Fixed `ModuleNotFoundError: No module named 'modules'` error
- ✅ Corrected import paths from `modules.*` to `discoursemap.modules.*`
- ✅ Improved entry point configuration in setup.py
- ✅ Restructured package hierarchy for better compatibility

### Package Structure Improvements
- 📁 Moved all modules under `discoursemap/` directory
- 📦 Added proper `__init__.py` files for package recognition
- 🔧 Optimized `setup.py` configuration
- 📋 Added `MANIFEST.in` for better package content control

## 🛠️ Technical Enhancements

- **Python Compatibility**: Supports Python 3.6+
- **Dependencies**: Updated colorama, requests, pyyaml requirements
- **Cross-Platform**: Full compatibility across Windows, macOS, and Linux
- **CLI Integration**: Global installation support with `discoursemap` command

## 📦 Installation

### From PyPI (Recommended)
```bash
pip install discoursemap
```

### From Source
```bash
git clone https://github.com/ibrahmsql/discoursemap.git
cd discoursemap
pip install .
```

### From Wheel
```bash
pip install discoursemap-1.1.0-py3-none-any.whl
```

## 🎯 Usage Examples

### Basic Scan
```bash
discoursemap -u https://forum.example.com
```

### Advanced Scan with Options
```bash
discoursemap -u https://forum.example.com --threads 10 --timeout 30
```

### Help and Documentation
```bash
discoursemap --help
```

## 🔍 Features

- **Comprehensive Security Scanning**: Full Discourse forum security assessment
- **Plugin Detection**: Identifies installed plugins and their versions
- **Vulnerability Assessment**: Checks for known CVEs and security issues
- **User Enumeration**: Discovers forum users and their information
- **API Endpoint Discovery**: Maps available API endpoints
- **Configuration Analysis**: Reviews security configurations
- **Detailed Reporting**: Generates comprehensive security reports

## 📋 Release Assets

- `discoursemap-1.1.0.tar.gz` - Source distribution
- `discoursemap-1.1.0-py3-none-any.whl` - Universal wheel package

## 🐛 Bug Reports

If you encounter any issues, please report them on our [GitHub Issues](https://github.com/ibrahmsql/discoursemap/issues) page.

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines for more information.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Full Changelog**: https://github.com/ibrahmsql/discoursemap/compare/v1.0.6...v1.1.0

**Download**: [Latest Release](https://github.com/ibrahmsql/discoursemap/releases/tag/v1.1.0)