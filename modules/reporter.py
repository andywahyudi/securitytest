import json
from datetime import datetime
import html

class Reporter:
    def __init__(self):
        self.report_template = """
# Web Application Security Test Report

**Target:** {target}
**Date:** {date}
**Total Vulnerabilities Found:** {total_vulns}

## Executive Summary

{executive_summary}

## Detailed Findings

{detailed_findings}

## Recommendations

{recommendations}

## Technical Details

{technical_details}
"""
    
    def generate_report(self, results, target_url):
        """Generate comprehensive security report"""
        total_vulns = 0
        high_vulns = 0
        medium_vulns = 0
        low_vulns = 0
        
        # Count vulnerabilities by severity
        for test_type, vulns in results.items():
            if isinstance(vulns, list):
                total_vulns += len(vulns)
                for vuln in vulns:
                    severity = vuln.get('severity', 'Low')
                    if severity == 'High':
                        high_vulns += 1
                    elif severity == 'Medium':
                        medium_vulns += 1
                    else:
                        low_vulns += 1
        
        # Generate sections - ensure they return strings, not None
        executive_summary = self.generate_executive_summary(high_vulns, medium_vulns, low_vulns) or ""
        detailed_findings = self.generate_detailed_findings(results) or ""
        recommendations = self.generate_recommendations(results) or ""
        technical_details = self.generate_technical_details(results) or ""
        
        # Fill template
        report = self.report_template.format(
            target=target_url,
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_vulns=total_vulns,
            executive_summary=executive_summary,
            detailed_findings=detailed_findings,
            recommendations=recommendations,
            technical_details=technical_details
        )
        
        return report
    
    def generate_executive_summary(self, high, medium, low):
        """Generate executive summary section"""
        total = high + medium + low
        
        if total == 0:
            return """
No vulnerabilities were found during this security assessment.

**GOOD:** The application appears to have proper security controls in place for the tested vulnerability types.

**Note:** This assessment focused on XSS and CSRF vulnerabilities. A comprehensive security assessment should include additional vulnerability types.
"""
        
        summary = f"""
This security assessment identified {total} vulnerabilities:
- **High Severity:** {high} vulnerabilities
- **Medium Severity:** {medium} vulnerabilities  
- **Low Severity:** {low} vulnerabilities

"""
        
        if high > 0:
            summary += "**CRITICAL:** High severity vulnerabilities require immediate attention and should be fixed as soon as possible.\n"
        elif medium > 0:
            summary += "**WARNING:** Medium severity vulnerabilities should be addressed promptly to prevent potential security breaches.\n"
        else:
            summary += "**INFO:** Only low severity issues found. These should be addressed during regular maintenance cycles.\n"
        
        # Add risk assessment
        if high > 0:
            summary += "\n**Risk Level:** HIGH - Immediate action required\n"
        elif medium > 0:
            summary += "\n**Risk Level:** MEDIUM - Address within next maintenance cycle\n"
        else:
            summary += "\n**Risk Level:** LOW - Monitor and address when convenient\n"
        
        return summary
    
    def generate_detailed_findings(self, results):
        """Generate detailed findings section"""
        if not any(results.values()):
            return "No vulnerabilities were found during the security assessment.\n"
        
        findings = ""
        
        for test_type, vulns in results.items():
            if not vulns:
                continue
                
            findings += f"\n### {test_type.upper()} Vulnerabilities\n\n"
            
            for i, vuln in enumerate(vulns, 1):
                findings += f"#### {test_type.upper()}-{i:03d}: {vuln.get('description', 'Vulnerability')}\n\n"
                findings += f"**Severity:** {vuln.get('severity', 'Unknown')}\n\n"
                findings += f"**Endpoint:** `{vuln.get('endpoint', 'Unknown')}`\n\n"
                findings += f"**Method:** {vuln.get('method', 'Unknown')}\n\n"
                
                if 'parameter' in vuln:
                    findings += f"**Parameter:** `{vuln['parameter']}`\n\n"
                
                if 'payload' in vuln:
                    findings += f"**Payload:** `{html.escape(str(vuln['payload']))}`\n\n"
                
                if 'payload_type' in vuln:
                    findings += f"**Payload Type:** {vuln['payload_type']}\n\n"
                
                if 'context' in vuln:
                    findings += f"**Context:** {vuln['context']}\n\n"
                
                if 'response_snippet' in vuln:
                    findings += f"**Response Snippet:**\n\n{html.escape(str(vuln['response_snippet']))}\n\n\n"
                
                if 'vulnerabilities' in vuln:
                    findings += f"**Issues Found:**\n"
                    for issue in vuln['vulnerabilities']:
                        findings += f"- {issue}\n"
                    findings += "\n"
                
                # Add CSRF-specific details
                if 'csrf_validation' in vuln:
                    csrf_val = vuln['csrf_validation']
                    findings += f"**CSRF Validation Status:** {csrf_val.get('status', 'Unknown')}\n"
                    findings += f"**CSRF Validation Details:** {csrf_val.get('message', 'No details')}\n\n"
                
                if 'referer_validation' in vuln:
                    ref_val = vuln['referer_validation']
                    findings += f"**Referer Validation Status:** {ref_val.get('status', 'Unknown')}\n"
                    findings += f"**Referer Validation Details:** {ref_val.get('message', 'No details')}\n\n"
                
                # Add impact assessment
                findings += f"**Impact Assessment:**\n"
                findings += self.generate_impact_assessment(vuln)
                findings += "\n"
                
                findings += "---\n\n"
        
        return findings
    
    def generate_impact_assessment(self, vuln):
        """Generate impact assessment for a vulnerability"""
        vuln_type = vuln.get('type', '').upper()
        severity = vuln.get('severity', 'Unknown')
        
        if vuln_type == 'XSS':
            if severity == 'High':
                return """- **Data Theft:** Attacker can steal user session cookies and sensitive data
- **Account Takeover:** Possible complete account compromise
- **Malware Distribution:** Can be used to distribute malware to users
- **Defacement:** Website content can be modified maliciously"""
            elif severity == 'Medium':
                return """- **Limited Data Access:** Some user data may be accessible
- **UI Manipulation:** Attacker can modify page appearance
- **Phishing:** Can be used for targeted phishing attacks"""
            else:
                return """- **Minor Content Injection:** Limited ability to inject content
- **User Confusion:** May cause confusion but limited security impact"""
        
        elif vuln_type == 'CSRF':
            if severity == 'High':
                return """- **Unauthorized Actions:** Attacker can perform actions on behalf of users
- **Data Modification:** User data can be modified without consent
- **Privilege Escalation:** Possible elevation of user privileges
- **Financial Impact:** Unauthorized transactions or changes"""
            elif severity == 'Medium':
                return """- **Limited Unauthorized Actions:** Some actions can be performed without consent
- **Data Integrity Issues:** Some user data may be modified"""
            else:
                return """- **Minor Security Bypass:** Limited ability to bypass security controls"""
        
        return "- **Unknown Impact:** Manual assessment required to determine full impact"
    
    def generate_recommendations(self, results):
        """Generate recommendations section"""
        recommendations = ""
        
        has_xss = 'xss' in results and results['xss']
        has_csrf = 'csrf' in results and results['csrf']
        
        if has_xss:
            recommendations += """

### XSS Prevention
1. **Input Validation:**
   - Implement strict input validation on all user inputs
   - Use whitelist validation where possible
   - Validate data type, length, format, and range
   - Reject inputs containing script tags or JavaScript

2. **Output Encoding:**
   - Encode all user data before displaying in HTML
   - Use context-appropriate encoding (HTML, JavaScript, CSS, URL)
   - Never insert user data directly into script tags

3. **Content Security Policy (CSP):**
   - Implement a strict CSP to prevent script execution
   - Use nonce or hash-based CSP for inline scripts
   - Regularly review and update CSP rules
   - PHP Specific Implementation:
   
    // Use htmlspecialchars() for HTML context
    echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');

    // Use json_encode() for JavaScript context
    echo json_encode($user_input, JSON_HEX_TAG | JSON_HEX_AMP);

    // Implement CSP headers
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'");

    // Input validation function
    function validateInput($input, $type = 'string') {
        $input = trim($input);
        switch($type) {
            case 'email':
                return filter_var($input, FILTER_VALIDATE_EMAIL);
            case 'int':
                return filter_var($input, FILTER_VALIDATE_INT);
            case 'url':
                return filter_var($input, FILTER_VALIDATE_URL);
            default:
                return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
        }
    }
    
    """
        if has_csrf:
            recommendations += """
CSRF Prevention
CSRF Tokens:

Implement CSRF tokens for all state-changing operations
Use cryptographically secure random tokens
Validate tokens on server-side for every request
Regenerate tokens after successful validation
SameSite Cookies:

Set SameSite attribute on session cookies
Use 'Strict' for maximum security or 'Lax' for better usability
Ensure cookies are marked as Secure and HttpOnly
Double Submit Cookie Pattern:

Send CSRF token both as cookie and form field
Validate that both values match on server-side
PHP Implementation:

// Start session with secure settings
session_set_cookie_params([
    'lifetime' => 3600,
    'path' => '/',
    'domain' => '',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict'
]);
session_start();

// Generate CSRF token
function generateCSRFToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

// Validate CSRF token
function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && 
           hash_equals($_SESSION['csrf_token'], $token);
}

// Form implementation
?>
<form method="POST" action="process.php">
    <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
    <!-- other form fields -->
    <button type="submit">Submit</button>
</form>

<?php
// Processing form
if ($_POST) {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        http_response_code(403);
        die('CSRF token validation failed');
    }
    // Process form data safely
}


Additional CSRF Protection:

Validate HTTP Referer header for sensitive operations
Use custom headers for AJAX requests
Implement request rate limiting
Log and monitor CSRF attempts
"""
        recommendations += """

General Security Recommendations
1. Security Headers:


// Implement comprehensive security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
header('Content-Security-Policy: default-src \\'self\\'; script-src \\'self\\'');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');



2. Input Validation Framework:


class InputValidator {
    public static function sanitize($input, $type = 'string') {
        $input = trim($input);
        
        switch($type) {
            case 'email':
                return filter_var($input, FILTER_SANITIZE_EMAIL);
            case 'int':
                return filter_var($input, FILTER_SANITIZE_NUMBER_INT);
            case 'url':
                return filter_var($input, FILTER_SANITIZE_URL);
            case 'string':
            default:
                return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
        }
    }
    
    public static function validate($input, $type = 'string') {
        switch($type) {
            case 'email':
                return filter_var($input, FILTER_VALIDATE_EMAIL) !== false;
            case 'int':
                return filter_var($input, FILTER_VALIDATE_INT) !== false;
            case 'url':
                return filter_var($input, FILTER_VALIDATE_URL) !== false;
            default:
                return !empty($input);
        }
    }
}



3. **Regular Security Practices:**
   - Implement automated security testing in CI/CD pipeline
   - Conduct regular penetration testing and code reviews
   - Keep all dependencies and frameworks updated
   - Monitor security advisories for used components
   - Implement proper logging and monitoring
   - Use HTTPS everywhere with proper certificate management

4. **Developer Training:**
   - Train developers on secure coding practices
   - Implement mandatory security code reviews
   - Use static analysis security testing (SAST) tools
   - Establish secure development lifecycle (SDLC)

5. **Database Security:**

   
   // Use prepared statements to prevent SQL injection
   $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ? AND status = ?");
   $stmt->execute([$user_id, 'active']);
   
   // Input validation for database operations
   function validateDatabaseInput($input, $max_length = 255) {
       $input = trim($input);
       if (strlen($input) > $max_length) {
           throw new InvalidArgumentException("Input too long");
       }
       return $input;
   }


6. **Session Security:**


// Secure session configuration
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.use_strict_mode', 1);
ini_set('session.cookie_samesite', 'Strict');

// Session regeneration
function regenerateSession() {
    session_regenerate_id(true);
}

// Session timeout
function checkSessionTimeout($timeout = 1800) {
    if (isset($_SESSION['last_activity']) && 
        (time() - $_SESSION['last_activity'] > $timeout)) {
        session_unset();
        session_destroy();
        return false;
    }
    $_SESSION['last_activity'] = time();
    return true;
}

"""

    def generate_technical_details(self, results, auth_info=None):
        """Generate technical details section"""
        details = f"""
### Scan Information

- **Scan Date:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- **Scanner Version:** Enhanced Security Scanner v2.0
- **Total Vulnerabilities:** {sum(len(v) if isinstance(v, list) else 0 for v in results.values())}
"""
        return details

def save_report(self, report_content, filename=None):
    """Save report to file"""
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{timestamp}.md"
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(report_content)
        return filename
    except Exception as e:
        raise Exception(f"Failed to save report: {str(e)}")

def generate_json_report(self, results, target_url):
    """Generate JSON format report for programmatic use"""
    report_data = {
        "target": target_url,
        "date": datetime.now().isoformat(),
        "summary": {
            "total_vulnerabilities": sum(len(vulns) for vulns in results.values()),
            "high_severity": 0,
            "medium_severity": 0,
            "low_severity": 0
        },
        "vulnerabilities": {}
    }
    
    # Count vulnerabilities by severity
    for test_type, vulns in results.items():
        report_data["vulnerabilities"][test_type] = []
        
        for vuln in vulns:
            severity = vuln.get('severity', 'Low')
            if severity == 'High':
                report_data["summary"]["high_severity"] += 1
            elif severity == 'Medium':
                report_data["summary"]["medium_severity"] += 1
            else:
                report_data["summary"]["low_severity"] += 1
            
            # Clean vulnerability data for JSON
            clean_vuln = {}
            for key, value in vuln.items():
                if isinstance(value, (str, int, float, bool, list, dict, type(None))):
                    clean_vuln[key] = value
                else:
                    clean_vuln[key] = str(value)
            
            report_data["vulnerabilities"][test_type].append(clean_vuln)
    
    return json.dumps(report_data, indent=2, ensure_ascii=False)

def generate_csv_report(self, results, target_url):
    """Generate CSV format report for spreadsheet analysis"""
    import csv
    import io
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        'Target', 'Date', 'Vulnerability Type', 'Severity', 'Endpoint', 
        'Method', 'Parameter', 'Description', 'Payload'
    ])
    
    # Write vulnerability data
    for test_type, vulns in results.items():
        for vuln in vulns:
            writer.writerow([
                target_url,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                test_type.upper(),
                vuln.get('severity', 'Unknown'),
                vuln.get('endpoint', 'Unknown'),
                vuln.get('method', 'Unknown'),
                vuln.get('parameter', 'N/A'),
                vuln.get('description', 'No description'),
                str(vuln.get('payload', 'N/A'))
            ])
    
    return output.getvalue()

def generate_html_report(self, results, target_url):
    """Generate HTML format report for web viewing"""
    # Count vulnerabilities
    total_vulns = sum(len(vulns) for vulns in results.values())
    high_vulns = sum(1 for vulns in results.values() for vuln in vulns if vuln.get('severity') == 'High')
    medium_vulns = sum(1 for vulns in results.values() for vuln in vulns if vuln.get('severity') == 'Medium')
    low_vulns = sum(1 for vulns in results.values() for vuln in vulns if vuln.get('severity') == 'Low')
    
    html_template = f"""
<div class="summary">
    <h2>Executive Summary</h2>
    <p>This security assessment identified {total_vulns} vulnerabilities:</p>
    <ul>
        <li><span class="severity-high">High Severity:</span> {high_vulns} vulnerabilities</li>
        <li><span class="severity-medium">Medium Severity:</span> {medium_vulns} vulnerabilities</li>
        <li><span class="severity-low">Low Severity:</span> {low_vulns} vulnerabilities</li>
    </ul>
</div>

<h2>Detailed Findings</h2>
"""
    # Add vulnerability details
    if not any(results.values()):
        html_template += "<p>No vulnerabilities were found during the security assessment.</p>"
    else:
        for test_type, vulns in results.items():
            if not vulns:
                continue
            
            html_template += f"<h3>{test_type.upper()} Vulnerabilities</h3>"
            
            for i, vuln in enumerate(vulns, 1):
                severity = vuln.get('severity', 'Low').lower()
                html_template += f"""
                <div class="vulnerability {severity}">
                    <h4>{test_type.upper()}-{i:03d}: {html.escape(vuln.get('description', 'Vulnerability'))}</h4>
                    <p><strong>Severity:</strong> <span class="severity-{severity}">{vuln.get('severity', 'Unknown')}</span></p>
                    <p><strong>Endpoint:</strong> <code>{html.escape(vuln.get('endpoint', 'Unknown'))}</code></p>
                    <p><strong>Method:</strong> {vuln.get('method', 'Unknown')}</p>
"""
                if 'parameter' in vuln:
                    html_template += f"<p><strong>Parameter:</strong> <code>{html.escape(vuln['parameter'])}</code></p>"
                
                if 'payload' in vuln:
                    html_template += f"<p><strong>Payload:</strong></p><div class='payload'>{html.escape(str(vuln['payload']))}</div>"
                
                if 'response_snippet' in vuln:
                    html_template += f"<p><strong>Response Snippet:</strong></p><div class='code'>{html.escape(str(vuln['response_snippet']))}</div>"
                
                html_template += "</div>"
    
    html_template += """
<h2>Recommendations</h2>
<p>Please refer to the detailed markdown report for comprehensive remediation guidance.</p>

<footer style="margin-top: 50px; padding-top: 20px; border-top: 1px solid #ddd; color: #666;">
    <p>Generated by Web Application Security Testing Tool v1.0.0</p>
    <p><strong>Note:</strong> This tool should only be used on applications you own or have explicit permission to test.</p>
</footer>
"""
    return html_template

