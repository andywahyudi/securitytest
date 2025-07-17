import json
import csv
import html
from datetime import datetime
from .reporter import Reporter

class EnhancedReporter(Reporter):
    def __init__(self):
        super().__init__()
        self.auth_report_template = """
# Web Application Security Test Report (Authenticated)

**Target:** {target}
**Date:** {date}
**Authentication:** {auth_status}
**Total Vulnerabilities Found:** {total_vulns}

## Authentication Summary

{auth_summary}

## Executive Summary

{executive_summary}

## Authentication-Specific Findings

{auth_findings}

## Standard Vulnerability Findings

{detailed_findings}

## Session Management Analysis

{session_analysis}

## Recommendations

{recommendations}

## Technical Details

{technical_details}
"""
    
    def generate_authenticated_report(self, results, target_url, auth_info=None):
        """Generate comprehensive security report including authentication details"""
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
        
        # Generate sections
        auth_status = "Authenticated" if auth_info and auth_info.get('logged_in') else "Unauthenticated"
        auth_summary = self.generate_auth_summary(auth_info)
        executive_summary = self.generate_executive_summary(high_vulns, medium_vulns, low_vulns)
        auth_findings = self.generate_auth_findings(results)
        detailed_findings = self.generate_detailed_findings(results)
        session_analysis = self.generate_session_analysis(results)
        recommendations = self.generate_enhanced_recommendations(results, auth_info)
        technical_details = self.generate_technical_details(results)
        
        # Fill template
        report = self.auth_report_template.format(
            target=target_url,
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            auth_status=auth_status,
            total_vulns=total_vulns,
            auth_summary=auth_summary,
            executive_summary=executive_summary,
            auth_findings=auth_findings,
            detailed_findings=detailed_findings,
            session_analysis=session_analysis,
            recommendations=recommendations,
            technical_details=technical_details
        )
        
        return report
    
    def generate_auth_summary(self, auth_info):
        """Generate authentication summary section"""
        if not auth_info:
            return "No authentication was used during this scan."
        
        summary = f"""
**Authentication Status:** {'✅ Successful' if auth_info.get('logged_in') else '❌ Failed'}
**Login URL:** {auth_info.get('login_url', 'N/A')}
**Session Cookies:** {len(auth_info.get('cookies', []))} cookies found
**Authentication Headers:** {len(auth_info.get('headers', []))} headers set
**CSRF Tokens:** {len(auth_info.get('csrf_tokens', []))} tokens detected

### Session Information
"""
        
        if auth_info.get('cookies'):
            summary += "**Active Cookies:**\n"
            for cookie in auth_info['cookies']:
                summary += f"- `{cookie}`\n"
            summary += "\n"
        
        if auth_info.get('headers'):
            summary += "**Authentication Headers:**\n"
            for header in auth_info['headers']:
                summary += f"- `{header}`\n"
            summary += "\n"
        
        return summary
    
    def generate_auth_findings(self, results):
        """Generate authentication-specific findings"""
        findings = ""
        
        # Session management findings
        if 'session' in results and results['session']:
            findings += "### Session Management Vulnerabilities\n\n"
            for vuln in results['session']:
                findings += f"#### {vuln.get('type', 'Unknown').upper()}: {vuln.get('description', 'Session vulnerability')}\n\n"
                findings += f"**Severity:** {vuln.get('severity', 'Unknown')}\n\n"
                findings += f"**Details:** {vuln.get('details', 'No details available')}\n\n"
                findings += "---\n\n"
        
        # Privilege escalation findings
        if 'privilege_escalation' in results and results['privilege_escalation']:
            findings += "### Privilege Escalation Vulnerabilities\n\n"
            for vuln in results['privilege_escalation']:
                findings += f"#### PRIVESC: {vuln.get('description', 'Privilege escalation')}\n\n"
                findings += f"**Severity:** {vuln.get('severity', 'Unknown')}\n\n"
                findings += f"**Endpoint:** `{vuln.get('endpoint', 'Unknown')}`\n\n"
                findings += f"**Details:** {vuln.get('details', 'No details available')}\n\n"
                findings += "---\n\n"
        
        # Authentication bypass findings
        if 'auth_bypass' in results and results['auth_bypass']:
            findings += "### Authentication Bypass Vulnerabilities\n\n"
            for vuln in results['auth_bypass']:
                findings += f"#### BYPASS: {vuln.get('description', 'Authentication bypass')}\n\n"
                findings += f"**Method:** {vuln.get('method', 'Unknown')}\n\n"
                findings += f"**Success:** {'Yes' if vuln.get('success') else 'No'}\n\n"
                if vuln.get('headers'):
                    findings += f"**Bypass Headers:** `{vuln['headers']}`\n\n"
                if vuln.get('url'):
                    findings += f"**Bypass URL:** `{vuln['url']}`\n\n"
                findings += "---\n\n"
        
        return findings if findings else "No authentication-specific vulnerabilities found.\n\n"
    
    def generate_session_analysis(self, results):
        """Generate session management analysis"""
        analysis = ""
        
        if 'session' not in results or not results['session']:
            return "No session management issues detected.\n\n"
        
        session_issues = results['session']
        
        # Categorize session issues
        fixation_issues = [v for v in session_issues if v.get('type') == 'session_fixation']
        timeout_issues = [v for v in session_issues if v.get('type') == 'session_timeout']
        concurrent_issues = [v for v in session_issues if v.get('type') == 'concurrent_sessions']
        
        if fixation_issues:
            analysis += "### Session Fixation Analysis\n\n"
            analysis += "The application is vulnerable to session fixation attacks. "
            analysis += "Session IDs are not regenerated after successful authentication, "
            analysis += "allowing attackers to potentially hijack user sessions.\n\n"
        
        if timeout_issues:
            analysis += "### Session Timeout Analysis\n\n"
            analysis += "The application does not implement proper session timeout mechanisms. "
            analysis += "This could allow sessions to remain active indefinitely, "
            analysis += "increasing the risk of session hijacking.\n\n"
        
        if concurrent_issues:
            analysis += "### Concurrent Session Analysis\n\n"
            analysis += "The application allows multiple concurrent sessions for the same user. "
            analysis += "While this may be intended behavior, it can increase security risks "
            analysis += "if user accounts are compromised.\n\n"
        
        return analysis
    
    def generate_enhanced_recommendations(self, results, auth_info):
        """Generate enhanced recommendations including authentication-specific advice"""
        recommendations = super().generate_recommendations(results)
        
        # Add authentication-specific recommendations
        if auth_info and auth_info.get('logged_in'):
            recommendations += "\n### Authentication Security Recommendations\n\n"
            
            # Session management recommendations
            if 'session' in results and results['session']:
                recommendations += """
#### Session Management

1. **Session ID Regeneration:**
   - Regenerate session IDs after successful authentication
   - Regenerate session IDs after privilege level changes
   - Use cryptographically secure random session ID generation

2. **Session Timeout:**
   - Implement appropriate session timeout values
   - Provide session timeout warnings to users
   - Clear session data on timeout

3. **Session Security:**
   
   // PHP session security settings
   ini_set('session.cookie_httponly', 1);
   ini_set('session.cookie_secure', 1);
   ini_set('session.use_strict_mode', 1);
   session_regenerate_id(true);
   
   """
           # Privilege escalation recommendations
        if 'privilege_escalation' in results and results['privilege_escalation']:
            recommendations += """
Access Control
Implement Proper Authorization:

Check user permissions on every request
Use role-based access control (RBAC)
Implement principle of least privilege
Secure Admin Areas:

Separate admin interfaces from user interfaces
Implement additional authentication for admin functions
Log all administrative actions
Authorization Example:

function checkAdminAccess() {
    if (!isset($_SESSION['user_role']) || $_SESSION['user_role'] !== 'admin') {
        http_response_code(403);
        die('Access denied');
    }
}

"""
        # Authentication bypass recommendations
        if 'auth_bypass' in results and results['auth_bypass']:
            recommendations += """

Authentication Bypass Prevention
Consistent Authentication Checks:

Implement authentication checks on all protected endpoints
Validate authentication on all HTTP methods
Dont rely solely on client-side restrictions
Header Security:

Validate and sanitize all HTTP headers
Dont trust forwarded headers without validation
Implement proper reverse proxy configuration
URL Security:

Normalize URLs before processing
Implement proper URL validation
Use whitelist-based URL routing
"""
        return recommendations

def generate_json_report(self, results, target_url, auth_info=None):
    """Generate JSON format report"""
    report_data = {
        'target': target_url,
        'scan_date': datetime.now().isoformat(),
        'authentication': auth_info or {},
        'summary': {
            'total_vulnerabilities': sum(len(vulns) if isinstance(vulns, list) else 0 for vulns in results.values()),
            'high_severity': sum(1 for vulns in results.values() if isinstance(vulns, list) for vuln in vulns if vuln.get('severity') == 'High'),
            'medium_severity': sum(1 for vulns in results.values() if isinstance(vulns, list) for vuln in vulns if vuln.get('severity') == 'Medium'),
            'low_severity': sum(1 for vulns in results.values() if isinstance(vulns, list) for vuln in vulns if vuln.get('severity') == 'Low')
        },
        'vulnerabilities': results
    }
    
    return json.dumps(report_data, indent=2)

def generate_html_report(self, results, target_url, auth_info=None):
    """Generate HTML format report"""
    html_template = """
{auth_section}

<div class="summary">
    <div class="summary-card">
        <h3>{total_vulns}</h3>
        <p>Total Vulnerabilities</p>
    </div>
    <div class="summary-card">
        <h3 style="color: #dc3545;">{high_vulns}</h3>
        <p>High Severity</p>
    </div>
    <div class="summary-card">
        <h3 style="color: #fd7e14;">{medium_vulns}</h3>
        <p>Medium Severity</p>
    </div>
    <div class="summary-card">
        <h3 style="color: #28a745;">{low_vulns}</h3>
        <p>Low Severity</p>
    </div>
</div>
    
    <h2>Vulnerability Details</h2>
    {vulnerability_details}
    
    <h2>Recommendations</h2>
    <div style="background: #e7f3ff; padding: 20px; border-radius: 5px;">
        {recommendations}
    </div>
    
</body>
</html>
"""
        
    # Calculate vulnerability counts
    total_vulns = sum(len(vulns) if isinstance(vulns, list) else 0 for vulns in results.values())
    high_vulns = sum(1 for vulns in results.values() if isinstance(vulns, list) for vuln in vulns if vuln.get('severity') == 'High')
    medium_vulns = sum(1 for vulns in results.values() if isinstance(vulns, list) for vuln in vulns if vuln.get('severity') == 'Medium')
    low_vulns = sum(1 for vulns in results.values() if isinstance(vulns, list) for vuln in vulns if vuln.get('severity') == 'Low')
    
    # Generate authentication section
    auth_section = ""
    if auth_info and auth_info.get('logged_in'):
        auth_section = f"""
<div class="auth-info">
        <h3>Authentication Information</h3>
        <p><strong>Login URL:</strong> {auth_info.get('login_url', 'N/A')}</p>
        <p><strong>Session Cookies:</strong> {len(auth_info.get('cookies', []))}</p>
        <p><strong>Auth Headers:</strong> {len(auth_info.get('headers', []))}</p>
    </div>
"""
        
        # Generate vulnerability details
        vulnerability_details = ""
        for test_type, vulns in results.items():
            if isinstance(vulns, list) and vulns:
                vulnerability_details += f"<h3>{test_type.upper()} Vulnerabilities</h3>"
                for vuln in vulns:
                    severity = vuln.get('severity', 'Low').lower()
                    severity_class = f"{severity}-severity"
                    
                    vulnerability_details += f"""
    <div class="vulnerability {severity_class}">
        <h4>{html.escape(vuln.get('description', 'Vulnerability'))}</h4>
        <p><strong>Severity:</strong> {vuln.get('severity', 'Unknown')}</p>
        <p><strong>Endpoint:</strong> <code>{html.escape(vuln.get('endpoint', 'Unknown'))}</code></p>
        {f"<p><strong>Method:</strong> {vuln.get('method', 'Unknown')}</p>" if vuln.get('method') else ""}
        {f"<p><strong>Parameter:</strong> <code>{html.escape(vuln.get('parameter', ''))}</code></p>" if vuln.get('parameter') else ""}
        {f"<p><strong>Payload:</strong> <div class='code'>{html.escape(vuln.get('payload', ''))}</div></p>" if vuln.get('payload') else ""}
        {f"<p><strong>Details:</strong> {html.escape(vuln.get('details', ''))}</p>" if vuln.get('details') else ""}
    </div>
"""
        
        # Generate recommendations
        recommendations_html = self.generate_enhanced_recommendations(results, auth_info).replace('\n', '<br>')
        recommendations_html = recommendations_html.replace('', '<div class="code">').replace('', '</div>')
        
        return html_template.format(
            target=html.escape(target_url),
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            auth_status="Authenticated" if auth_info and auth_info.get('logged_in') else "Unauthenticated",
            auth_section=auth_section,
            total_vulns=total_vulns,
            high_vulns=high_vulns,
            medium_vulns=medium_vulns,
            low_vulns=low_vulns,
            vulnerability_details=vulnerability_details,
            recommendations=recommendations_html
        )
    
    def generate_csv_report(self, results, target_url, auth_info=None):
        """Generate CSV format report"""
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Target', 'Scan Date', 'Authenticated', 'Vulnerability Type', 
            'Severity', 'Description', 'Endpoint', 'Method', 'Parameter', 
            'Payload', 'Details'
        ])
        
        # Write vulnerability data
        scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        authenticated = "Yes" if auth_info and auth_info.get('logged_in') else "No"
        
        for test_type, vulns in results.items():
            if isinstance(vulns, list):
                for vuln in vulns:
                    writer.writerow([
                        target_url,
                        scan_date,
                        authenticated,
                        test_type.upper(),
                        vuln.get('severity', 'Unknown'),
                        vuln.get('description', ''),
                        vuln.get('endpoint', ''),
                        vuln.get('method', ''),
                        vuln.get('parameter', ''),
                        vuln.get('payload', ''),
                        vuln.get('details', '')
                    ])
        
        return output.getvalue()
    
    def save_report(self, report_content, filename, format_type='markdown'):
        """Save report to file with appropriate extension"""
        import os
        
        # Determine file extension based on format
        extensions = {
            'markdown': '.md',
            'json': '.json',
            'html': '.html',
            'csv': '.csv'
        }
        
        # Add extension if not present
        if not any(filename.endswith(ext) for ext in extensions.values()):
            filename += extensions.get(format_type, '.txt')
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report_content)
            return filename
        except Exception as e:
            raise Exception(f"Failed to save report: {e}")
