import json
from typing import Dict, Any, List
import os
import sys
import dotenv
import uuid

# Load environment variables from a .env file (if present)
dotenv.load_dotenv()

# Add the project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Assuming local_llm.py is in the same directory or accessible via PYTHONPATH
from local_llm import generate_response, load_model # Import generate_response and load_model directly
# Also import config for default max tokens for summarization
from chatbot_modules import config 


class Llama:
    """
    Dummy Llama class for type hinting if llama_cpp is not installed during development.
    In a real scenario, you would import Llama directly from llama_cpp.
    """
    def __init__(self, *args, **kwargs):
        pass
    def create_chat_completion(self, *args, **kwargs):
        pass

def _format_nmap_summary_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Crafts a detailed prompt for the LLM based on Nmap parsed data.
    Focuses on high-level findings, open ports, OS detection, and potential risks.
    """
    prompt = (
        "As a cybersecurity analyst, analyze the following Nmap scan report and provide:\n"
        "1. A concise summary of the scan, including the target, scan type, and overall host status.\n"
        "2. A list of key findings, focusing on open ports, identified services/versions, and OS detection.\n"
        "3. Potential security implications for any significant findings.\n"
        "4. Actionable remediation steps for the identified issues (e.g., patching, configuration changes, firewall rules).\n"
        "The report data is in JSON format. Prioritize critical and high-risk information. "
        "Do not invent information not present in the report.\n\n"
        "--- Nmap Report Data ---\n"
    )

    # Add scan metadata
    metadata = parsed_data.get("scan_metadata", {})
    prompt += f"Scan Initiated By: {metadata.get('scan_initiated_by', 'N/A')}\n"
    prompt += f"Timestamp: {metadata.get('timestamp', 'N/A')}\n"
    prompt += f"Target: {metadata.get('target', 'N/A')}\n"
    prompt += f"Nmap Version: {metadata.get('nmap_version', 'N/A')}\n"
    prompt += f"Scan Type: {metadata.get('scan_type', 'N/A')}\n"
    prompt += f"Scan Duration: {metadata.get('scan_duration', 'N/A')}\n\n"

    # Iterate through hosts
    hosts = parsed_data.get("hosts", [])
    if not hosts:
        prompt += "No hosts found in the Nmap report.\n"
    else:
        for i, host in enumerate(hosts):
            prompt += f"--- Host {i+1}: {host.get('hostname', 'N/A')} ({host.get('ip_address', 'N/A')}) ---\n"
            prompt += f"  Status: {host.get('status', 'N/A')} (Latency: {host.get('latency', 'N/A')})\n"

            # OS Detection
            os_detection = host.get("os_detection", {})
            if os_detection.get("os_guesses"):
                prompt += f"  OS Guesses: {', '.join(os_detection['os_guesses'])}\n"
            if os_detection.get("device_type"):
                prompt += f"  Device Type: {', '.join(os_detection['device_type'])}\n"
            
            # Ports
            ports = host.get("ports", [])
            if ports:
                prompt += "  Open/Filtered Ports:\n"
                for port in ports:
                    prompt += (
                        f"    - Port: {port.get('port_id')}/{port.get('protocol')} "
                        f"State: {port.get('state')} Service: {port.get('service')} "
                        f"Version: {port.get('version', 'N/A')}\n"
                    )
                    if port.get('script_outputs'):
                        prompt += "      Script Outputs:\n"
                        for script_name, script_output in port['script_outputs'].items():
                            prompt += f"        {script_name}: {script_output.splitlines()[0][:100]}...\n" # Limit script output to first line/100 chars
            else:
                prompt += "  No open or filtered ports identified.\n"
            
            prompt += "\n" # Separate hosts

    prompt += "\n--- End Nmap Report Data ---\n"
    prompt += "Please provide the summary, key findings, implications, and remediation steps based on the above. "
    prompt += "Format your response with clear headings: 'Summary', 'Key Findings', 'Implications', 'Remediation Steps'."
    
    return prompt

def _format_zap_summary_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Crafts a detailed prompt for the LLM based on ZAP parsed data.
    Focuses on vulnerabilities, risk levels, and provides details for high/medium risks.
    """
    prompt = (
        "As a cybersecurity analyst, analyze the following ZAP scan report and provide:\n"
        "1. A concise summary of the scan, including the target site and overall risk distribution.\n"
        "2. A detailed explanation of key findings, focusing on High and Medium risk vulnerabilities.\n"
        "3. Actionable remediation steps for each significant vulnerability identified.\n"
        "The report data is in JSON format. Prioritize critical and high-risk information. "
        "Do not invent information not present in the report.\n\n"
        "--- ZAP Report Data ---\n"
    )

    # Add scan metadata
    metadata = parsed_data.get("scan_metadata", {})
    prompt += f"Tool: {metadata.get('tool', 'N/A')}\n"
    prompt += f"Report ID: {metadata.get('report_id', 'N/A')}\n"
    prompt += f"Generated At: {metadata.get('generated_at', 'N/A')}\n"
    prompt += f"Site: {metadata.get('site', 'N/A')}\n"
    prompt += f"ZAP Version: {metadata.get('zap_version', 'N/A')}\n\n"

    # Add summary risk counts
    summary = parsed_data.get("summary", {})
    risk_counts = summary.get("risk_counts", {})
    prompt += "Summary of Alerts by Risk Level:\n"
    for risk_level, count in risk_counts.items():
        prompt += f"  {risk_level}: {count} alerts\n"
    prompt += f"Total Alerts: {summary.get('total_alerts', 0)}\n\n"

    # Focus on High and Medium vulnerabilities for detailed explanation
    vulnerabilities = parsed_data.get("vulnerabilities", [])
    high_medium_vulnerabilities = [
        v for v in vulnerabilities if v.get("risk") in ["High", "Medium"]
    ]

    if not high_medium_vulnerabilities:
        prompt += "No High or Medium risk vulnerabilities identified in the ZAP report.\n"
    else:
        prompt += "--- Detailed High and Medium Risk Vulnerabilities ---\n"
        for i, vuln in enumerate(high_medium_vulnerabilities):
            prompt += f"Vulnerability {i+1}: {vuln.get('name', 'N/A')}\n"
            prompt += f"  Risk Level: {vuln.get('risk', 'N/A')}\n"
            prompt += f"  Description: {vuln.get('description', 'N/A')[:500]}...\n" # Limit description
            prompt += f"  Instances: {vuln.get('instances_count', 0)}\n"
            
            if vuln.get('urls'):
                prompt += "  Affected URLs (first 2 instances):\n"
                for j, instance in enumerate(vuln['urls'][:2]): # Limit to first 2 instances
                    prompt += f"    - URL: {instance.get('url', 'N/A')}\n"
                    prompt += f"      Method: {instance.get('method', 'N/A')}\n"
                    prompt += f"      Parameter: {instance.get('parameter', 'N/A')}\n"
                    prompt += f"      Attack: {instance.get('attack', 'N/A')[:100]}...\n"
            prompt += "\n" # Separate vulnerabilities

    prompt += "\n--- End ZAP Report Data ---\n"
    prompt += "Please provide the summary, detailed explanation of key findings (High/Medium risk), and remediation steps. "
    prompt += "Format your response with clear headings: 'Summary', 'Key Findings', 'Remediation Steps'."
    
    return prompt

def _format_sslscan_summary_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Crafts a detailed prompt for the LLM based on SSLScan parsed data.
    Focuses on protocols, ciphers, key exchange, certificate details, and security features.
    """
    prompt = (
        "As a cybersecurity analyst, analyze the following SSL/TLS Vulnerability Scan Report "
        "and provide:\n"
        "1. A concise summary of the scan results, including the target host and overall security posture.\n"
        "2. Key findings regarding enabled/disabled protocols, supported ciphers, and certificate details.\n"
        "3. Potential security implications for any identified weaknesses (e.g., outdated protocols, weak ciphers, certificate issues).\n"
        "4. Actionable remediation steps to improve the SSL/TLS configuration.\n"
        "The report data is in JSON format. Do not invent information not present in the report.\n\n"
        "--- SSLScan Report Data ---\n"
    )

    # Add scan metadata
    metadata = parsed_data.get("scan_metadata", {})
    prompt += f"Tool: {metadata.get('tool', 'N/A')}\n"
    prompt += f"Target Host: {metadata.get('target_host', 'N/A')}\n"
    prompt += f"Connected IP: {metadata.get('connected_ip', 'N/A')}\n"
    prompt += f"Timestamp: {metadata.get('timestamp', 'N/A')}\n"
    prompt += f"Tool Version: {metadata.get('tool_version', 'N/A')}\n"
    prompt += f"OpenSSL Version: {metadata.get('openssl_version', 'N/A')}\n"
    prompt += f"Tested Server: {metadata.get('tested_server', 'N/A')}:{metadata.get('tested_port', 'N/A')} (SNI: {metadata.get('sni_name', 'N/A')})\n\n"

    # Protocols
    protocols = parsed_data.get("protocols", [])
    if protocols:
        prompt += "SSL/TLS Protocols:\n"
        for proto in protocols:
            prompt += f"  - {proto.get('name', 'N/A')}: {proto.get('status', 'N/A')}\n"
    
    # Security Features
    security_features = parsed_data.get("security_features", {})
    if security_features:
        prompt += "\nTLS Security Features:\n"
        for feature, status in security_features.items():
            if isinstance(status, list): # For Heartbleed which can be a list
                prompt += f"  - {feature.replace('_', ' ').title()}: {', '.join(status)}\n"
            else:
                prompt += f"  - {feature.replace('_', ' ').title()}: {status}\n"

    # Supported Ciphers
    ciphers = parsed_data.get("supported_ciphers", [])
    if ciphers:
        prompt += "\nSupported Server Ciphers (Preferred/Accepted):\n"
        for cipher in ciphers:
            cipher_info = f"  - {cipher.get('status', 'N/A')} {cipher.get('name', 'N/A')} ({cipher.get('bits', 'N/A')} bits)"
            if cipher.get('tls_version'):
                cipher_info += f" on {cipher['tls_version']}"
            if cipher.get('curve'):
                cipher_info += f" Curve: {cipher['curve']}"
            if cipher.get('dhe_bits'):
                cipher_info += f" DHE: {cipher['dhe_bits']} bits"
            prompt += f"{cipher_info}\n"

    # Key Exchange Groups
    key_exchange_groups = parsed_data.get("key_exchange_groups", [])
    if key_exchange_groups:
        prompt += "\nServer Key Exchange Groups:\n"
        for group in key_exchange_groups:
            group_info = f"  - {group.get('name', 'N/A')} ({group.get('details', 'N/A')})"
            if group.get('tls_version'):
                group_info += f" on {group['tls_version']}"
            if group.get('bits'):
                group_info += f" ({group['bits']} bits)"
            prompt += f"{group_info}\n"

    # SSL Certificate
    certificate = parsed_data.get("ssl_certificate", {})
    if certificate:
        prompt += "\nSSL Certificate Details:\n"
        prompt += f"  - Subject: {certificate.get('subject', 'N/A')}\n"
        prompt += f"  - Issuer: {certificate.get('issuer', 'N/A')}\n"
        prompt += f"  - Signature Algorithm: {certificate.get('signature_algorithm', 'N/A')}\n"
        prompt += f"  - RSA Key Strength: {certificate.get('rsa_key_strength', 'N/A')} bits\n"
        prompt += f"  - Altnames: {', '.join(certificate.get('altnames', ['N/A']))}\n"
        prompt += f"  - Valid From: {certificate.get('not_valid_before', 'N/A')}\n"
        prompt += f"  - Valid Until: {certificate.get('not_valid_after', 'N/A')}\n"

    prompt += "\n--- End SSLScan Report Data ---\n"
    prompt += "Please provide the summary, key findings, implications, and remediation steps based on the above. "
    prompt += "Format your response with clear headings: 'Summary', 'Key Findings', 'Implications', 'Remediation Steps'."
    
    return prompt

def _format_mobsf_android_summary_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Crafts a detailed prompt for the LLM based on MobSF parsed data.
    Focuses on app information, security score, findings, and permissions.
    """
    prompt = (
        "As a cybersecurity analyst, analyze the following Mobile Security Framework (MobSF) report "
        "and provide:\n"
        "1. A concise summary of the application analysis, including app name, package, version, and overall security score.\n"
        "2. Key findings, focusing on high and medium severity issues, and abused permissions.\n"
        "3. Potential security implications for any identified weaknesses.\n"
        "4. Actionable remediation steps for the identified issues.\n"
        "The report data is in JSON format. Prioritize critical and high-risk information. "
        "Do not invent information not present in the report.\n\n"
        "--- MobSF Report Data ---\n"
    )

    # Add scan metadata
    metadata = parsed_data.get("scan_metadata", {})
    prompt += f"Tool: {metadata.get('tool', 'N/A')}\n"
    prompt += f"Report ID: {metadata.get('report_id', 'N/A')}\n"
    prompt += f"Scan Date: {metadata.get('scan_date', 'N/A')}\n"
    prompt += f"MobSF Version: {metadata.get('mobsf_version', 'N/A')}\n"
    prompt += f"App Security Score: {metadata.get('app_security_score', 'N/A')}\n"
    prompt += f"Grade: {metadata.get('grade', 'N/A')}\n\n"

    # App Information
    app_info = parsed_data.get("app_information", {})
    file_info = parsed_data.get("file_information", {})
    prompt += "App Information:\n"
    prompt += f"  App Name: {app_info.get('App Name', 'N/A')}\n"
    prompt += f"  Package Name: {app_info.get('Package Name', 'N/A')}\n"
    prompt += f"  Android Version Name: {app_info.get('Android Version Name', 'N/A')}\n"
    prompt += f"  MD5: {file_info.get('MD5', 'N/A')}\n"
    prompt += f"  SHA1: {file_info.get('SHA1', 'N/A')}\n"
    prompt += f"  SHA256: {file_info.get('SHA256', 'N/A')}\n\n"

    # Summary of Findings
    summary = parsed_data.get("summary", {})
    findings_severity = summary.get("findings_severity", {})
    prompt += "Summary of Findings:\n"
    prompt += f"  Total Issues: {summary.get('total_issues', 0)}\n"
    prompt += f"  High Severity: {findings_severity.get('High', 0)}\n"
    prompt += f"  Medium Severity: {findings_severity.get('Medium', 0)}\n"
    prompt += f"  Info Severity: {findings_severity.get('Info', 0)}\n"
    prompt += f"  Secure Findings: {findings_severity.get('Secure', 0)}\n"
    prompt += f"  Hotspot Findings: {findings_severity.get('Hotspot', 0)}\n\n"

    # Detailed Findings (High & Medium)
    all_findings = []
    all_findings.extend(parsed_data.get("certificate_analysis_findings", []))
    all_findings.extend(parsed_data.get("manifest_analysis_findings", []))
    all_findings.extend(parsed_data.get("code_analysis_findings", []))

    high_medium_findings = [f for f in all_findings if f.get('severity') in ['high', 'warning']] # Using 'high' and 'warning' based on provided JSON
    
    if high_medium_findings:
        prompt += "Detailed High and Medium Severity Findings:\n"
        for i, finding in enumerate(high_medium_findings):
            prompt += f"  Finding {i+1}:\n"
            prompt += f"    Title/Issue: {finding.get('title', finding.get('issue', 'N/A'))}\n"
            prompt += f"    Description: {finding.get('description', 'N/A')}\n"
            prompt += f"    Severity: {finding.get('severity', 'N/A')}\n"
            if 'standards' in finding: # Specifically for code_analysis_findings
                prompt += f"    Standards/CWE: {finding.get('standards', 'N/A')}\n"
            if 'files' in finding: # Specifically for code_analysis_findings
                prompt += f"    Files: {finding.get('files', 'N/A')}\n"
            prompt += "\n"
    else:
        prompt += "No High or Medium severity findings reported.\n\n"

    # Abused Permissions
    abused_permissions = parsed_data.get("abused_permissions_summary", {})
    malware_permissions_section = abused_permissions.get("Malware Permissions", {})
    
    # Check if 'matches' is a string like "2/25" and extract the first number
    matches_str = malware_permissions_section.get('matches', '0/0')
    total_abused_permissions_count = 0
    if isinstance(matches_str, str) and '/' in matches_str:
        try:
            total_abused_permissions_count = int(matches_str.split('/')[0])
        except ValueError:
            total_abused_permissions_count = 0

    if total_abused_permissions_count > 0:
        prompt += "Abused Permissions:\n"
        prompt += f"  Matches: {matches_str}\n"
        prompt += f"  Permissions: {', '.join(malware_permissions_section.get('permissions', []))}\n"
        prompt += f"  Description: {malware_permissions_section.get('description', 'N/A')}\n\n"
    else:
        prompt += "No abused permissions detected as malware.\n\n"


    prompt += "\n--- End MobSF Report Data ---\n"
    prompt += "Please provide the summary, key findings, implications, and remediation steps based on the above. "
    prompt += "Format your response with clear headings: 'Summary', 'Key Findings', 'Implications', 'Remediation Steps'."
    
    return prompt

def _format_mobsf_ios_summary_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Crafts a detailed prompt for the LLM based on MobSF iOS parsed data.
    Focuses on app information, security score, and various security findings.
    """
    prompt = (
        "As a cybersecurity analyst, analyze the following Mobile Security Framework (MobSF) iOS report "
        "and provide:\n"
        "1. A concise summary of the application analysis, including app name, identifier, version, and overall security score.\n"
        "2. Key findings, focusing on high and medium (warning) severity issues from binary code analysis and binary protection analysis.\n"
        "3. Potential security implications for any identified weaknesses.\n"
        "4. Actionable remediation steps for the identified issues.\n"
        "The report data is in JSON format. Prioritize critical and high-risk information. "
        "Do not invent information not present in the report.\n\n"
        "--- MobSF iOS Report Data ---\n"
    )

    # Add scan metadata
    metadata = parsed_data.get("scan_metadata", {})
    prompt += f"Tool: {metadata.get('tool', 'N/A')}\n"
    prompt += f"Report ID: {metadata.get('report_id', 'N/A')}\n"
    prompt += f"Scan Date: {metadata.get('scan_date', 'N/A')}\n"
    prompt += f"MobSF Version: {metadata.get('mobsf_version', 'N/A')}\n"
    prompt += f"App Security Score: {metadata.get('app_security_score', 'N/A')}\n"
    prompt += f"Grade: {metadata.get('grade', 'N/A')}\n\n"

    # App Information
    app_info = parsed_data.get("app_information", {})
    file_info = parsed_data.get("file_information", {})
    prompt += "App Information:\n"
    prompt += f"  App Name: {app_info.get('App Name', 'N/A')}\n"
    prompt += f"  Identifier: {app_info.get('Identifier', 'N/A')}\n"
    prompt += f"  App Type: {app_info.get('App Type', 'N/A')}\n"
    prompt += f"  SDK Name: {app_info.get('SDK Name', 'N/A')}\n"
    prompt += f"  Version: {app_info.get('Version', 'N/A')}\n"
    prompt += f"  Build: {app_info.get('Build', 'N/A')}\n"
    prompt += f"  Platform Version: {app_info.get('Platform Version', 'N/A')}\n"
    prompt += f"  Min OS Version: {app_info.get('Min OS Version', 'N/A')}\n"
    prompt += f"  Supported Platforms: {', '.join(app_info.get('Supported Platforms', ['N/A']))}\n\n"

    # File Information
    prompt += "File Information:\n"
    prompt += f"  File Name: {file_info.get('File Name', 'N/A')}\n"
    prompt += f"  Size: {file_info.get('Size', 'N/A')}\n"
    prompt += f"  MD5: {file_info.get('MD5', 'N/A')}\n"
    prompt += f"  SHA1: {file_info.get('SHA1', 'N/A')}\n"
    prompt += f"  SHA256: {file_info.get('SHA256', 'N/A')}\n\n"

    # Summary of Findings
    summary = parsed_data.get("summary", {})
    findings_severity = summary.get("findings_severity", {})
    prompt += "Summary of Findings:\n"
    prompt += f"  Total Issues: {summary.get('total_issues', 0)}\n"
    prompt += f"  High Severity: {findings_severity.get('High', 0)}\n"
    prompt += f"  Medium Severity: {findings_severity.get('Medium', 0)}\n"
    prompt += f"  Info Severity: {findings_severity.get('Info', 0)}\n"
    prompt += f"  Secure Findings: {findings_severity.get('Secure', 0)}\n"
    prompt += f"  Hotspot Findings: {findings_severity.get('Hotspot', 0)}\n\n"

    # IPA Binary Code Analysis Findings (High & Warning)
    ipa_code_analysis = parsed_data.get("ipa_binary_code_analysis_findings", [])
    high_warning_ipa_code_findings = [f for f in ipa_code_analysis if f.get('severity') in ['high', 'warning']]

    if high_warning_ipa_code_findings:
        prompt += "Detailed IPA Binary Code Analysis Findings (High and Warning Severity):\n"
        for i, finding in enumerate(high_warning_ipa_code_findings):
            prompt += f"  Finding {i+1}:\n"
            prompt += f"    Issue: {finding.get('issue', 'N/A')}\n"
            prompt += f"    Description: {finding.get('description', 'N/A')}\n"
            prompt += f"    Severity: {finding.get('severity', 'N/A')}\n"
            if 'standards' in finding:
                standards = finding['standards']
                prompt += f"    Standards:\n"
                prompt += f"      CWE: {standards.get('CWE', 'N/A')}\n"
                prompt += f"      OWASP Top 10: {standards.get('OWASP Top 10', 'N/A')}\n"
                prompt += f"      OWASP MASVS: {standards.get('OWASP MASVS', 'N/A')}\n"
            prompt += "\n"
    else:
        prompt += "No High or Warning severity IPA Binary Code Analysis findings reported.\n\n"

    # IPA Binary Analysis Findings (Protections)
    ipa_binary_analysis = parsed_data.get("ipa_binary_analysis_findings", [])
    if ipa_binary_analysis:
        prompt += "IPA Binary Analysis (Protections):\n"
        for i, finding in enumerate(ipa_binary_analysis):
            prompt += f"  Protection {i+1}:\n"
            prompt += f"    Protection: {finding.get('protection', 'N/A')}\n"
            prompt += f"    Status: {finding.get('status', 'N/A')}\n"
            prompt += f"    Severity: {finding.get('severity', 'N/A')}\n"
            prompt += f"    Description: {finding.get('description', 'N/A')}\n"
            prompt += "\n"
    else:
        prompt += "No IPA Binary Analysis findings reported.\n\n"
        
    # App Transport Security Findings
    ats_findings = parsed_data.get("app_transport_security_findings", [])
    if ats_findings:
        prompt += "App Transport Security (ATS) Findings:\n"
        for i, finding in enumerate(ats_findings):
            prompt += f"  ATS Finding {i+1}:\n"
            prompt += f"    Issue: {finding.get('issue', 'N/A')}\n"
            prompt += f"    Severity: {finding.get('severity', 'N/A')}\n"
            prompt += f"    Description: {finding.get('description', 'N/A')}\n"
            prompt += "\n"
    else:
        prompt += "No App Transport Security (ATS) findings reported.\n\n"

    # OFAC Sanctioned Countries
    ofac_countries = parsed_data.get("ofac_sanctioned_countries", [])
    if ofac_countries:
        prompt += "OFAC Sanctioned Countries:\n"
        for i, country_data in enumerate(ofac_countries):
            prompt += f"  Country {i+1}:\n"
            prompt += f"    Domain: {country_data.get('domain', 'N/A')}\n"
            prompt += f"    Country/Region: {country_data.get('country_region', 'N/A')}\n"
            prompt += "\n"
    else:
        prompt += "No OFAC Sanctioned Countries detected.\n\n"

    # Domain Malware Check
    domain_malware_check = parsed_data.get("domain_malware_check", [])
    if domain_malware_check:
        prompt += "Domain Malware Check:\n"
        for i, domain_data in enumerate(domain_malware_check):
            prompt += f"  Domain {i+1}:\n"
            prompt += f"    Domain: {domain_data.get('domain', 'N/A')}\n"
            prompt += f"    Status: {domain_data.get('status', 'N/A')}\n"
            if domain_data.get('geolocation'):
                geo = domain_data['geolocation']
                prompt += f"    Geolocation:\n"
                prompt += f"      IP: {geo.get('IP', 'N/A')}\n"
                prompt += f"      Country: {geo.get('Country', 'N/A')}\n"
                prompt += f"      Region: {geo.get('Region', 'N/A')}\n"
                prompt += f"      City: {geo.get('City', 'N/A')}\n"
                prompt += f"      Latitude: {geo.get('Latitude', 'N/A')}\n"
                prompt += f"      Longitude: {geo.get('Longitude', 'N/A')}\n"
            prompt += "\n"
    else:
        prompt += "No Domain Malware Check findings reported.\n\n"

    # Scan Logs (optional, depending on verbosity desired for LLM)
    scan_logs = parsed_data.get("scan_logs", [])
    if scan_logs:
        prompt += "Scan Logs (Recent Entries):\n"
        for i, log_entry in enumerate(scan_logs[-5:]): # Last 5 entries
            prompt += f"  Log {i+1}: Timestamp={log_entry.get('timestamp', 'N/A')}, Event={log_entry.get('event', 'N/A')}, Error={log_entry.get('error', 'N/A')}\n"
        prompt += "\n"


    prompt += "\n--- End MobSF iOS Report Data ---\n"
    prompt += "Please provide the summary, key findings, implications, and remediation steps based on the above. "
    prompt += "Format your response with clear headings: 'Summary', 'Key Findings', 'Implications', 'Remediation Steps'."
    
    return prompt

def _format_nikto_summary_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Crafts a detailed prompt for the LLM based on Nikto parsed data.
    Focuses on host details, scan summary, and identified findings.
    """
    prompt = (
        "As a cybersecurity analyst, analyze the following Nikto Web Server Scan Report "
        "and provide:\n"
        "1. A concise summary of the scan results, including the target host, port, HTTP server, and overall security posture based on findings.\n"
        "2. Key findings regarding missing security headers (e.g., X-Frame-Options, Strict-Transport-Security, X-Content-Type-Options) and identified uncommon headers.\n"
        "3. Potential security implications for any identified weaknesses (e.g., missing security headers allowing clickjacking, MIME-sniffing, or insecure transport).\n"
        "4. Actionable remediation steps to improve the web server's security configuration.\n"
        "5. Provide Statistics, the test links, references, and any other relevant information from the report.\n"
        "6.If nothing found then just provide the information extracted form the report.\n"
        "7.Say Preper zap scan over nikto as no relevent information is found.\n"
        "The report data is in JSON format. Do not invent information not present in the report.\n\n"
        "--- Nikto Report Data ---\n"
    )

    # Add scan metadata
    metadata = parsed_data.get("scan_metadata", {})
    prompt += f"Tool: {metadata.get('tool', 'N/A')}\n"
    prompt += f"Host Summary Start Time: {metadata.get('start_time_host_summary', 'N/A')}\n"
    prompt += f"Host Summary End Time: {metadata.get('end_time_host_summary', 'N/A')}\n"
    prompt += f"Host Summary Elapsed Time: {metadata.get('elapsed_time_host_summary', 'N/A')}\n\n"

    # Add Host Details
    host_details = parsed_data.get("host_details", {})
    prompt += "Host Details:\n"
    prompt += f" - Hostname: {host_details.get('hostname', 'N/A')}\n"
    prompt += f" - IP: {host_details.get('ip', 'N/A')}\n"
    prompt += f" - Port: {host_details.get('port', 'N/A')}\n"
    prompt += f" - HTTP Server: {host_details.get('http_server', 'N/A')}\n"
    prompt += f" - Site Link (Name): {host_details.get('site_link_name', 'N/A')}\n"
    prompt += f" - Site Link (IP): {host_details.get('site_link_ip', 'N/A')}\n"
    
    statistics = host_details.get("statistics", {})
    if statistics:
        prompt += " - Statistics:\n"
        prompt += f"   - Requests: {statistics.get('requests', 'N/A')}\n"
        prompt += f"   - Errors: {statistics.get('errors', 'N/A')}\n"
        prompt += f"   - Findings: {statistics.get('findings', 'N/A')}\n"
    prompt += "\n"

    # Add Findings
    findings = parsed_data.get("findings", [])
    if findings:
        prompt += "Identified Findings:\n"
        for i, finding in enumerate(findings):
            prompt += f"Finding {i + 1}:\n"
            prompt += f" - URI: {finding.get('uri', 'N/A')}\n"
            prompt += f" - HTTP Method: {finding.get('http_method', 'N/A')}\n"
            prompt += f" - Description: {finding.get('description', 'N/A')}\n"
            if finding.get('test_links'):
                prompt += " - Test Links:\n"
                for link in finding['test_links']:
                    prompt += f"   - {link}\n"
            if finding.get('references'):
                prompt += " - References:\n"
                for ref in finding['references']:
                    prompt += f"   - {ref}\n"
            prompt += "\n"

    # Add Scan Summary
    scan_summary = parsed_data.get("scan_summary", {})
    if scan_summary:
        prompt += "Scan Summary:\n"
        prompt += f" - Software: {scan_summary.get('software', 'N/A')}\n"
        prompt += f" - CLI Options: {scan_summary.get('cli_options', 'N/A')}\n"
        prompt += f" - Hosts Tested: {scan_summary.get('hosts_tested', 'N/A')}\n"
        prompt += f" - Scan Start Time: {scan_summary.get('start_time', 'N/A')}\n"
        prompt += f" - Scan End Time: {scan_summary.get('end_time', 'N/A')}\n"
        prompt += f" - Scan Elapsed Time: {scan_summary.get('elapsed_time', 'N/A')}\n"
    prompt += "\n"

    prompt += "--- End Nikto Report Data ---\n"
    prompt += "Please provide the summary, key findings, implications, and remediation steps based on the above. "
    prompt += "Format your response with clear headings: 'Summary', 'Key Findings', 'Implications', 'Remediation Steps'."
    
    return prompt



def summarize_report_with_llm(
    llm_instance: Llama, parsed_data: Dict[str, Any], report_type: str
) -> str:
    """
    Generates a natural language summary and remediation steps for a parsed security report
    using the local LLM.

    Args:
        llm_instance (Llama): The loaded Llama model instance.
        parsed_data (Dict[str, Any]): The structured dictionary parsed from the report.
        report_type (str): The type of the report ("nmap", "zap", or "sslscan").

    Returns:
        str: The generated explanation and remediation steps from the LLM.
    """
    if report_type.lower() == "nmap":
        prompt = _format_nmap_summary_prompt(parsed_data)
    elif report_type.lower() == "zap":
        prompt = _format_zap_summary_prompt(parsed_data)
    elif report_type.lower() == "sslscan": # New condition for SSLScan
        prompt = _format_sslscan_summary_prompt(parsed_data)
    elif report_type.lower() == "mobsf_android": # New condition for Mobsf Android
        prompt = _format_mobsf_android_summary_prompt(parsed_data)
    elif report_type.lower() == "mobsf_ios": # New condition for Mobsf iOS
        prompt = _format_mobsf_ios_summary_prompt(parsed_data)
    elif report_type.lower() == "nikto": # New condition for nikto
        prompt = _format_nikto_summary_prompt(parsed_data)
    else:
        return "Error: Unsupported report type for summarization. Please specify 'nmap', 'zap', or 'sslscan'."

    print(f"\n--- Sending formatted prompt to LLM for {report_type} report summary ---")

    try:
        llm_response = generate_response(llm_instance, prompt, max_tokens=config.DEFAULT_MAX_TOKENS)
        return llm_response
    except Exception as e:
        return f"Error generating LLM response: {e}"


def summarize_chat_history_segment(
    llm_instance: Any, history_segment: List[Dict[str, str]], max_tokens: int = config.DEFAULT_SUMMARIZE_MAX_TOKENS
) -> str:
    """
    Uses the LLM to summarize a segment of the chat history.

    Args:
        llm_instance (Any): The loaded Llama model instance.
        history_segment (List[Dict[str, str]]): A list of message dictionaries
                                                 (e.g., [{'role': 'user', 'content': '...'}, ...]).
        max_tokens (int): Maximum tokens for the summary.

    Returns:
        str: A concise summary of the conversation segment.
    """
    if not history_segment:
        return ""

    # Construct the prompt for summarization
    summarization_prompt = (
        "Please summarize the following conversation history concisely. "
        "Focus on the main topics discussed and any key questions or conclusions.\n\n"
        "--- Conversation History to Summarize ---\n"
    )
    
    # Concatenate the history segment into a string for the LLM
    for msg in history_segment:
        summarization_prompt += f"{msg['role'].capitalize()}: {msg['content']}\n"
    
    summarization_prompt += "--- End Conversation History ---\n\nSummary:"

    print(f"\n--- Sending chat history segment to LLM for summarization (length: {len(summarization_prompt)} chars) ---")

    try:
        # Call generate_response with the summarization prompt
        # We enforce a smaller max_tokens for summarization to keep it concise
        summary_response = generate_response(llm_instance, summarization_prompt, max_tokens=max_tokens)
        return summary_response.strip()
    except Exception as e:
        print(f"Error generating history summary: {e}")
        return "(Error summarizing previous conversation. Some context may be lost.)"


# Example usage (for testing summarizer.py directly if needed)
if __name__ == "__main__":
    print("--- Testing summarizer.py directly ---")
    # This requires a dummy local_llm and parsed data.
    # In a real run, main.py will handle loading and parsing.

    # Mock LLM instance for local testing without actual model download/load
    class MockLlama:
        def create_chat_completion(self, messages, max_tokens, temperature, stop):
            # For simplicity, mock the chat completion response
            full_prompt = messages[0]['content'] if messages else ""
            if "summarize the following conversation history" in full_prompt.lower():
                return {"choices": [{"message": {"content": "Mocked summary of the conversation history."}}]}
            elif "Nmap Report Data" in full_prompt:
                 return {"choices": [{"message": {"content": "Mocked Nmap report summary."}}]}
            elif "ZAP Report Data" in full_prompt:
                 return {"choices": [{"message": {"content": "Mocked ZAP report summary."}}]}
            elif "SSLScan Report Data" in full_prompt: # New mock response for SSLScan
                return {"choices": [{"message": {"content": "Mocked SSLScan report summary."}}]}
            elif "Mobsf Android Report Data" in full_prompt: # New mock response for SSLScan
                return {"choices": [{"message": {"content": "Mocked Mobsf Android report summary."}}]}
            else:
                return {"choices": [{"message": {"content": "Mocked LLM response."}}]}

    # Override generate_response for this test block
    _original_generate_response = generate_response
    def generate_response(llm_instance, prompt, max_tokens=256, temperature=0.7, stop=["</s>"]):
        return llm_instance.create_chat_completion(
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
            temperature=temperature,
            stop=stop
        )["choices"][0]["message"]["content"]

    dummy_llm_instance = MockLlama()
    print("Using Mock LLM for summarizer test.")


    # Dummy Nmap parsed data
    dummy_nmap_data = {
        "scan_metadata": {
            "scan_initiated_by": "User",
            "timestamp": "Fri Jun 18 10:00:00 2025 IST",
            "target": "example.com (192.168.1.1)",
            "nmap_version": "7.92",
            "scan_type": "Port Scan",
            "scan_duration": "10.5 seconds"
        },
        "hosts": [
            {
                "ip_address": "192.168.1.1",
                "hostname": "example.com",
                "status": "up",
                "latency": "0.002s",
                "os_detection": {
                    "os_guesses": ["Linux 3.10 - 4.11"],
                    "device_type": ["general purpose"]
                },
                "ports": [
                    {
                        "port_id": 22, "protocol": "tcp", "state": "open", "service": "ssh",
                        "version": "OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)",
                        "script_outputs": {"ssh-hostkey": "2048 SHA256:abcd... (RSA)"}
                    },
                    {
                        "port_id": 80, "protocol": "tcp", "state": "open", "service": "http",
                        "version": "Apache httpd 2.4.29 ((Ubuntu))",
                        "script_outputs": {"http-title": "Apache2 Ubuntu Default Page"}
                    }
                ]
            }
        ]
    }

    # Dummy ZAP parsed data
    dummy_zap_data = {
        "scan_metadata": {
            "tool": "Checkmarx ZAP Report",
            "report_id": "12345-abcde",
            "generated_at": "2025-06-18T10:05:00",
            "site": "http://testphp.vulnweb.com",
            "zap_version": "2.10.0"
        },
        "summary": {
            "risk_counts": {"High": 1, "Medium": 2, "Low": 3, "Informational": 5, "False Positives": 0},
            "total_alerts": 11
        },
        "vulnerabilities": [
            {
                "name": "SQL Injection", "risk": "High",
                "description": "SQL Injection vulnerability found in parameter 'id'.",
                "urls": [{"url": "http://testphp.vulnweb.com/listproducts.php?cat=1", "method": "GET", "parameter": "id", "attack": "id=1'%20OR%201=1--", "evidence": "Error message with SQL syntax"}],
                "solution": "Use parameterized queries or prepared statements.",
                "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
                "cwe_id": 89
            },
            {
                "name": "Cross Site Scripting (XSS)", "risk": "Medium",
                "description": "Reflected XSS vulnerability identified.",
                "urls": [{"url": "http://testphp.vulnweb.com/search.php?test=1", "method": "GET", "parameter": "test", "attack": "<script>alert(1)</script>", "evidence": "Reflected script in response"}],
                "solution": "Implement proper input validation and output encoding.",
                "references": ["https://owasp.org/www-community/attacks/xss/"],
                "cwe_id": 79
            }
        ]
    }

    # Dummy SSLScan parsed data
    dummy_sslscan_data = {
        "scan_metadata": {
            "tool": "SSLScan Report",
            "initiated_by": "Maaz",
            "timestamp": "2025-04-19 12:29:21",
            "target_host": "hackthissite.org",
            "tool_version": "2.1.5",
            "openssl_version": "3.4.0",
            "connected_ip": "137.74.187.102",
            "tested_server": "hackthissite.org",
            "tested_port": 443,
            "sni_name": "hackthissite.org"
        },
        "protocols": [
            {"name": "SSLv2", "status": "disabled"},
            {"name": "SSLv3", "status": "disabled"},
            {"name": "TLSv1.2", "status": "enabled"},
            {"name": "TLSv1.3", "status": "disabled"}
        ],
        "security_features": {
            "tls_fallback_scsv": "Server supports TLS Fallback SCSV",
            "tls_renegotiation": "Session renegotiation not supported",
            "tls_compression": "Compression disabled",
            "heartbleed": ["TLSv1.2 not vulnerable to heartbleed"]
        },
        "supported_ciphers": [
            {"status": "Preferred", "tls_version": "TLSv1.2", "bits": 256, "name": "ECDHE-RSA-AES256-GCM-SHA384", "curve": "P-256", "dhe_bits": 256}
        ],
        "key_exchange_groups": [
            {"tls_version": "TLSv1.2", "bits": 128, "name": "secp256r1", "details": "NIST P-256"}
        ],
        "ssl_certificate": {
            "signature_algorithm": "sha256WithRSAEncryption",
            "rsa_key_strength": 4096,
            "subject": "hackthisjogneh42n5o7gbzrewxee3vyu6ex37ukyvdw6jm66npakiyd.onion",
            "altnames": ["DNS: hackthissite.org", "DNS:www.hackthissite.org"],
            "issuer": "HARICA DV TLS RSA",
            "not_valid_before": "Mar 25 04:43:22 2025 GMT",
            "not_valid_after": "Mar 25 04:43:22 2026 GMT"
        }
    }


    if dummy_llm_instance:
        print("\n--- Testing with Nmap Report ---")
        nmap_summary = summarize_report_with_llm(dummy_llm_instance, dummy_nmap_data, "nmap")
        print("Generated Nmap Summary:")
        print(nmap_summary)

        print("\n--- Testing with ZAP Report ---")
        zap_summary = summarize_report_with_llm(dummy_llm_instance, dummy_zap_data, "zap")
        print("Generated ZAP Summary:")
        print(zap_summary)
        
        print("\n--- Testing with SSLScan Report ---") # New test call
        sslscan_summary = summarize_report_with_llm(dummy_llm_instance, dummy_sslscan_data, "sslscan")
        print("Generated SSLScan Summary:")
        print(sslscan_summary)

        # Test summarize_chat_history_segment
        print("\n--- Testing chat history summarization ---")
        test_history_segment = [
            {"role": "user", "content": "What is SQL injection?"},
            {"role": "assistant", "content": "SQL injection is a web security vulnerability that allows an attacker to alter the SQL queries made by an application."},
            {"role": "user", "content": "How do I prevent it?"},
            {"role": "assistant", "content": "You can prevent SQL injection by using parameterized queries, prepared statements, and input validation."}
        ]
        
        # Temporarily set a dummy config for this test if not importing real config
        class DummyConfig:
            DEFAULT_SUMMARIZE_MAX_TOKENS = 150
        
        # Use the actual config if available, otherwise use dummy
        current_config = config if 'config' in locals() else DummyConfig()
        
        history_summary = summarize_chat_history_segment(dummy_llm_instance, test_history_segment, max_tokens=current_config.DEFAULT_SUMMARIZE_MAX_TOKENS)
        print("Generated History Summary:")
        print(history_summary)

    else:
        print("Skipping summarizer tests as LLM instance could not be loaded.")
    
    # Restore original generate_response after testing
    generate_response = _original_generate_response

