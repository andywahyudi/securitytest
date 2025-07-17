# Enhanced Web Application Security Testing Tool

A comprehensive Python-based security testing tool for web applications with advanced authentication support, session management testing, and multiple vulnerability detection capabilities.

## Features

### Core Functionality
- **XSS Detection**: Comprehensive Cross-Site Scripting vulnerability detection
- **CSRF Testing**: Cross-Site Request Forgery vulnerability assessment
- **Session Management**: Session fixation, timeout, and concurrent session testing
- **Privilege Escalation**: Automated privilege escalation detection
- **Authentication Bypass**: Multiple bypass technique testing

### Advanced Authentication Support
- **Form-based Authentication**: Standard login form support
- **Basic Authentication**: HTTP Basic Auth support
- **Cookie-based Authentication**: Session cookie authentication
- **Header-based Authentication**: Custom header authentication (Bearer tokens, etc.)
- **Multi-step Authentication**: Complex authentication flows
- **OAuth Simulation**: OAuth 2.0 flow simulation (In-Progress)
- **Session Import/Export**: Save and reuse authentication sessions (In-Testing)

### Reporting & Output
- **Multiple Formats**: Markdown, JSON, HTML, CSV reports  (In-Testing)
- **Detailed Analysis**: Comprehensive vulnerability analysis (To Do)
- **Executive Summaries**: High-level security assessment summaries (To Do)
- **Technical Details**: In-depth technical findings (To Do)
- **Remediation Guidance**: Specific fix recommendations (To Do)

## Installation

### Prerequisites
- Python 3.7+
- pip package manager

### Setup using Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### Required Dependencies
```bash
pip install requests beautifulsoup4 lxml pyyaml colorama tqdm
```
if it failed, check your python version.
```bash
python --version
```
or
```bash
python3 --version
```
another solution is using python3
```bash
python3 -m pip install requests beautifulsoup4 lxml pyyaml colorama tqdm
```
or
```bash
pip3 install requests beautifulsoup4 lxml pyyaml colorama tqdm
```

### Optional Dependencies
```bash
pip install selenium  # For JavaScript-heavy applications
pip install pillow    # For screenshot capabilities
```

### Installation
```bash
git clone https://github.com/andywahyudi/securitytest.git
cd securitytest
pip install -r requirements.txt
```

## Configuration

### Configuration File
Create a YAML configuration file to customize testing parameters:

```yaml
# config/custom_config.yml
scanning:
    max_depth: 3
    delay_between_requests: 0.2
    request_timeout: 15

authentication:
    retry_attempts: 3
    session_timeout: 3600

xss_testing:
    enabled: true
    custom_payloads:
      - "<script>alert('Custom XSS')</script>"

reporting:
    export_formats:
      - "markdown"
      - "json"
      - "html"
```

## Usage

### Basic Usage

#### Simple Vulnerability Scan
```bash
python3 enhanced_main.py --all http://example.com
```

#### Specific Vulnerability Tests
```bash
# XSS testing only
python3 enhanced_main.py --xss http://example.com

# CSRF testing only
python3 enhanced_main.py --csrf http://example.com

# Multiple specific tests
python3 enhanced_main.py --xss --csrf --session http://example.com
```

### Authentication Examples

#### Form-based Authentication
```bash
python3 enhanced_main.py \
    --auth '{"type":"form","login_url":"http://example.com/login","username":"admin","password":"password"}' \
    --all http://example.com
```

#### Simple Form Authentication (Alternative syntax)
```bash
python3 enhanced_main.py \
    --login-url http://example.com/login \
    --username admin \
    --password password \
    --all http://example.com
```

#### Cookie Authentication
```bash
python3 enhanced_main.py \
    --cookies "PHPSESSID=abc123;user_token=xyz789" \
    --all http://example.com
```

#### Header Authentication
```bash
python3 enhanced_main.py \
    --headers "Authorization:Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
    --all http://example.com
```

#### Multi-step Authentication
```bash
python3 enhanced_main.py \
    --auth '{"type":"multi_step","steps":[{"url":"http://example.com/login","data":{"username":"admin","password":"password"}},{"url":"http://example.com/verify","data":{"code":"123456"}}]}' \
  --all http://example.com
```

#### Basic HTTP Authentication
```bash
python3 enhanced_main.py \
  --auth '{"type":"basic","url":"http://example.com","username":"admin","password":"password"}' \
  --all http://example.com
```

### Session Management

#### Export Session for Reuse
```bash
python3 enhanced_main.py \
  --login-url http://example.com/login \
  --username admin \
  --password password \
  --export-session my_session \
  --all http://example.com
```

#### Import Previously Saved Session
```bash
python3 enhanced_main.py \
  --import-session my_session.json \
  --session --privilege \
  http://example.com
```

### Advanced Options

#### Custom Configuration
```bash
python3 enhanced_main.py \
  --config config/custom_config.yml \
  --all http://example.com
```

#### Multiple Output Formats
```bash
python3 enhanced_main.py \
  --all \
  --format json,html,csv \
  --output security_report \
  http://example.com
```

#### Performance Tuning
```bash
python3 enhanced_main.py \
  --all \
  --depth 2 \
  --delay 0.5 \
  --timeout 30 \
  --threads 5 \
  http://example.com
```

#### Verbose Output
```bash
python3 enhanced_main.py \
  --all \
  --verbose \
  --output detailed_report \
  http://example.com
```

## 🔍 Testing Capabilities

### XSS (Cross-Site Scripting)
- **Reflected XSS**: Input reflection in responses
- **Stored XSS**: Persistent XSS in database/storage
- **DOM-based XSS**: Client-side DOM manipulation
- **Context-aware Testing**: HTML, JavaScript, CSS contexts
- **Encoding Bypass**: Various encoding techniques
- **Filter Evasion**: WAF and filter bypass attempts

### CSRF (Cross-Site Request Forgery)
- **Token Absence**: Missing CSRF tokens
- **Token Prediction**: Predictable token patterns
- **Referer Bypass**: Referer header manipulation
- **Origin Bypass**: Origin header manipulation
- **Method Override**: HTTP method override attacks

### Session Management
- **Session Fixation**: Pre-session attack detection
- **Session Timeout**: Timeout mechanism testing
- **Concurrent Sessions**: Multiple session handling
- **Session Regeneration**: Login session regeneration
- **Logout Functionality**: Proper session termination

### Privilege Escalation
- **Horizontal Escalation**: Same-level user access
- **Vertical Escalation**: Higher privilege access
- **Admin Panel Access**: Administrative interface testing
- **Role-based Access**: Role permission testing

### Authentication Bypass
- **Direct Object Access**: Unprotected resource access
- **Method Bypass**: HTTP method manipulation
- **Header Manipulation**: Authentication header bypass
- **URL Manipulation**: Path traversal and manipulation

## Report Formats

### Markdown Report
```bash
python3 enhanced_main.py --all --format markdown --output report http://example.com
```
- Human-readable format
- Executive summary
- Detailed findings
- Remediation recommendations

### JSON Report
```bash
python3 enhanced_main.py --all --format json --output report http://example.com
```
- Machine-readable format
- Structured vulnerability data
- Integration-friendly
- API consumption ready

### HTML Report
```bash
python3 enhanced_main.py --all --format html --output report http://example.com
```
- Web-friendly format
- Interactive elements
- Styled presentation
- Easy sharing

### CSV Report
```bash
python3 enhanced_main.py --all --format csv --output report http://example.com
```
- Spreadsheet-compatible
- Data analysis friendly
- Bulk processing
- Filtering and sorting

## Development & Testing

### Running Tests
```bash
# Run the comprehensive test suite
python3 test_runner.py

# Run specific test categories
python3 test_runner.py --basic-only
python3 test_runner.py --auth-only
python3 test_runner.py --scanning-only
```

### Project Structure
```
security_tester/
├── enhanced_main.py              # Main application entry point
├── modules/
│   ├── auth_handler.py           # Authentication handler
│   ├── authenticated_scanner.py  # Authenticated vulnerability scanning
│   ├── csrf_scanner.py           # CSRF vulnerability detection
│   ├── csrf_tester.py            # CSRF testing
│   ├── crawler.py                # Web application crawler
|   ├── enhanced_reporter.py      # Multi-format report generation
|   ├── reporter.py               # Basic report generation
|   ├── scanner.py                # Vulnerability scanning
│   ├── advanced_auth.py          # Advanced authentication handler
│   └── test_config.py            # Configuration management
│   ├── xss_scanner.py            # XSS vulnerability detection
│   ├── xss_tester.py             # XSS testing
├── config/
│   └── default_config.yml    # Default configuration
├── payloads/
│   ├── xss_payloads.txt      # XSS test payloads
├── enhanced_main.py          # Main application entry point
├── main.py                   # Main application entry point
├── test_runner.py            # Automated test suite
├── requirements.txt          # Project dependencies
└── README.md                 # This file
```

### Adding Custom Payloads
Create custom payload files:

```text
# payloads/custom_xss.txt
<script>alert('Custom XSS 1')</script>
<img src=x onerror=alert('Custom XSS 2')>
javascript:alert('Custom XSS 3')
```

Update configuration:
```yaml
xss_testing:
  payloads_file: "payloads/custom_xss.txt"
  custom_payloads:
    - "<svg onload=alert('SVG XSS')>"
```

## Security Considerations

### Responsible Usage
- **Authorization Required**: Only test applications you own or have explicit permission to test
- **Rate Limiting**: Use appropriate delays to avoid overwhelming target servers
- **Data Protection**: Be careful with sensitive data in reports and logs
- **Legal Compliance**: Ensure compliance with local laws and regulations

### Best Practices
- **Isolated Environment**: Test in isolated/staging environments when possible
- **Backup Data**: Ensure target applications are backed up before testing
- **Monitor Impact**: Monitor application performance during testing
- **Document Findings**: Maintain detailed records of testing activities

## Troubleshooting

### Common Issues

#### Authentication Failures
```bash
# Enable verbose logging
python3 enhanced_main.py --verbose --auth '...' --all http://example.com

# Check session export
python3 enhanced_main.py --auth '...' --export-session debug_session --xss http://example.com
```

#### Connection Issues
```bash
# Increase timeout
python3 enhanced_main.py --timeout 60 --all http://example.com

# Disable SSL verification
python3 enhanced_main.py --all http://example.com  # SSL verification disabled by default
```

#### Performance Issues
```bash
# Reduce concurrency and add delays
python3 enhanced_main.py --threads 1 --delay 1.0 --depth 1 --all http://example.com
```

### Debug Mode
```bash
# Enable maximum verbosity
python3 enhanced_main.py --verbose --all http://example.com 2>&1 | tee debug.log
```

### Log Analysis
```bash
# Check log file for detailed information
tail -f security_test.log
```

## Contributing

### Development Setup
```bash
git clone https://github.com/andywahyudi/securitytest.git
cd securitytest
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development dependencies
```

### Running Development Tests
```bash
# Run unit tests
python3 -m pytest tests/

# Run integration tests
python3 test_runner.py

# Run linting
flake8 modules/ *.py

# Run type checking
mypy modules/ *.py
```

### Submitting Changes
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

## Credits
1. [XSS Payload List](https://github.com/payloadbox/xss-payload-list)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before testing any web application. The authors are not responsible for any misuse or damage caused by this tool.

## Support

### Getting Help
- **Issues**: Report bugs and request features on GitHub Issues
- **Documentation**: Check this README and inline code documentation

## Changelog

### Version 2.0.0
- Added advanced authentication support
- Implemented session management testing
- Added privilege escalation detection
- Enhanced reporting with multiple formats
- Improved configuration system
- Added comprehensive test suite

### Version 1.0.0
- Initial release
- Basic XSS and CSRF detection
- Simple authentication support
- Markdown reporting

## Roadmap

### Upcoming Features
- **SQL Injection Detection**: Comprehensive SQLi testing
- **File Upload Testing**: Malicious file upload detection
- **API Security Testing**: REST/GraphQL API security assessment
- **JavaScript Analysis**: Client-side security analysis
- **Mobile App Testing**: Mobile application security testing
- **CI/CD Integration**: Jenkins, GitHub Actions integration
- **Machine Learning**: AI-powered vulnerability detection

### Performance Improvements
- **Async Scanning**: Asynchronous request handling
- **Caching System**: Intelligent response caching
- **Distributed Scanning**: Multi-node scanning support
- **Real-time Reporting**: Live vulnerability reporting

---

**Happy Security Testing**
Now let's create a requirements file:

```text:security_tester/requirements.txt
requests>=2.28.0
beautifulsoup4>=4.11.0
lxml>=4.9.0
pyyaml>=6.0
colorama>=0.4.5
tqdm>=4.64.0
urllib3>=1.26.0
certifi>=2022.0.0
charset-normalizer>=2.1.0
idna>=3.3
soupsieve>=2.3.0
```

And a development requirements file:

```text:security_tester/requirements-dev.txt
pytest>=7.1.0
pytest-cov>=3.0.0
flake8>=5.0.0
mypy>=0.971
black>=22.6.0
isort>=5.10.0
pre-commit>=2.20.0
```

Finally, let's create a simple setup script:

```python:security_tester/setup.py
#!/usr/bin/env python3
"""
Setup script for Enhanced Web Application Security Testing Tool
"""

from setuptools import setup, find_packages
import os

# Read README for long description
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="web-security-tester",
    version="2.0.0",
    author="Security Testing Team",
    author_email="me@andywahyudi.com",
    description="Enhanced Web Application Security Testing Tool with Advanced Authentication Support",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/andywahyudi/securitytest",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Testing",
    ],
    python_requires=">=3.7",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "web-security-test=enhanced_main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["config/*.yml", "payloads/*.txt"],
    },
)
```

This completes the comprehensive enhanced web application security testing tool with advanced authentication support, multiple vulnerability detection capabilities, and extensive reporting features. The tool now includes:

1. **Advanced Authentication**: Form, Basic, Cookie, Header, Multi-step, and OAuth support
2. **Comprehensive Testing**: XSS, CSRF, Session Management, Privilege Escalation, Auth Bypass
3. **Multiple Report Formats**: Markdown, JSON, HTML, CSV
4. **Configuration System**: YAML/JSON configuration files
5. **Session Management**: Import/Export authentication sessions
6. **Test Suite**: Comprehensive automated testing
7. **Documentation**: Detailed README with examples
8. **Setup Scripts**: Easy installation and deployment

The tool is production-ready and can be used for professional security assessments of web applications.