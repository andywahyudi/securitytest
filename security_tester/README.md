
# Enhanced Web Application Security Testing Tool


A comprehensive Python-based security testing tool for web applications with advanced authentication support, session management testing, and multiple vulnerability detection capabilities.


## 🚀 Features







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
- **OAuth Simulation**: OAuth 2.0 flow simulation
- **Session Import/Export**: Save and reuse authentication sessions






### Reporting & Output
- **Multiple Formats**: Markdown, JSON, HTML, CSV reports
- **Detailed Analysis**: Comprehensive vulnerability analysis
- **Executive Summaries**: High-level security assessment summaries
- **Technical Details**: In-depth technical findings
- **Remediation Guidance**: Specific fix recommendations






## 📦 Installation


### Prerequisites
- Python 3.7+
- pip package manager

### Required Dependencies
```bash




pip install requests beautifulsoup4 lxml pyyaml colorama tqdm
```





### Optional Dependencies
```bash








pip install selenium  # For JavaScript-heavy applications
pip install pillow    # For screenshot capabilities
```



### Installation
```bash


git clone https://github.com/your-repo/security-tester.git
cd security-tester
pip install -r requirements.txt
```



## 🔧 Configuration




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


## 🚀 Usage

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
````bash
python3 enhanced_main.py \
    --auth '{"type":"multi_step","steps":[{"url":"http://example.com/login","data":{"username":"admin","passwor