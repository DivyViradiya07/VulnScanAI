import json
from typing import Dict, Any, List, Union
import os
import sys
import dotenv
import uuid
import re

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

def _format_mobsf_raw_text_summary_prompt(raw_text: str) -> str:
    """
    Crafts a detailed prompt for the LLM based on raw MobSF report text.
    Instructs the LLM to summarize key findings directly from the provided text,
    focusing on app security score, identified vulnerabilities, and platform-specific details.
    """
    # Determine if it's an Android or iOS report based on keywords in the raw text
    os_type = "Mobile" # Default
    if re.search(r'ANDROID STATIC ANALYSIS REPORT', raw_text, re.IGNORECASE):
        os_type = "Android"
    elif re.search(r'IOS STATIC ANALYSIS REPORT', raw_text, re.IGNORECASE):
        os_type = "iOS"

    platform_specific_details = ""
    if os_type == "Android":
        platform_specific_details = "- **Dangerous Permissions:** Highlight any dangerous permissions requested by the application.\n"
    elif os_type == "iOS":
        platform_specific_details = "- **Insecure API Calls (iOS):** Highlight any insecure API calls or configurations specific to iOS.\n"
    
    prompt = (
        f"As a cybersecurity analyst, analyze the following MobSF {os_type} Static Analysis Report.\n"
        "This report is provided as raw text because a structured parser is not available for it.\n"
        "Your task is to read through the raw text and extract the most critical information:\n"
        "- **Overall App Security Score and Grade.**\n"
        "- **Findings Severity Summary:** Breakdown of High, Medium, Info, and Secure findings.\n"
        "- **Key File and App Information:** Application name, package/identifier, file hashes.\n"
        "- **Identified Vulnerabilities/Issues:** Any specific security vulnerabilities, weaknesses, or misconfigurations mentioned.\n"
        f"{platform_specific_details}" # Dynamically added platform-specific line
        "- **Certificate Information:** Details about the signing certificate, if available.\n"
        "\n"
        "Based on these extracted points, provide a concise high-level summary of the report's security posture.\n"
        "Then, list significant findings or potential security implications.\n"
        "Finally, suggest general remediation steps based on the type of issues commonly found in mobile security reports.\n\n"
        "--- MobSF Raw Report Text ---\n"
        f"{raw_text}\n\n"
        "Consider the above MobSF raw report text. Generate a comprehensive summary, list key findings, and propose actionable remediation steps.\n"
        "Focus only on information present in the provided text and keep the response structured\n"
    )
    return prompt


def summarize_report_with_llm(llm_instance: Llama, parsed_data: Dict[str, Any], report_type: str) -> str:
    """
    Generates a summary of the provided structured security report using the LLM.
    This function handles Nmap, ZAP, and SSLScan reports which provide parsed dictionary data.

    Args:
        llm_instance (Llama): The loaded LLM model instance.
        parsed_data (Dict[str, Any]): The structured dictionary parsed from the report.
        report_type (str): The type of the report ('nmap', 'zap', 'sslscan').

    Returns:
        str: A summary of the report.
    """
    prompt_formatter = None
    if report_type == 'nmap':
        prompt_formatter = _format_nmap_summary_prompt
    elif report_type == 'zap':
        prompt_formatter = _format_zap_summary_prompt
    elif report_type == 'sslscan':
        prompt_formatter = _format_sslscan_summary_prompt
    else:
        return f"Error: Unsupported structured report type '{report_type}' for summarization."

    # Generate the specific prompt using the formatter
    summary_prompt = prompt_formatter(parsed_data)
    
    # Generate response using the LLM
    summary = generate_response(llm_instance, summary_prompt, max_tokens=config.DEFAULT_SUMMARIZE_MAX_TOKENS)
    return summary

def summarize_raw_text_report_with_llm(llm_instance: Llama, raw_text: str, report_type: str) -> str:
    """
    Generates a summary of a raw text security report (e.g., MobSF) using the LLM.

    Args:
        llm_instance (Llama): The loaded LLM model instance.
        raw_text (str): The raw text content of the report.
        report_type (str): The type of the report (e.g., 'mobsf').

    Returns:
        str: A summary of the report.
    """
    if report_type == 'mobsf':
        summary_prompt = _format_mobsf_raw_text_summary_prompt(raw_text)
    else:
        return f"Error: Unsupported raw text report type '{report_type}' for summarization."
    
    # Generate response using the LLM
    summary = generate_response(llm_instance, summary_prompt, max_tokens=config.DEFAULT_SUMMARIZE_MAX_TOKENS)
    return summary


def summarize_chat_history_segment(llm_instance: Llama, chat_segment: List[Dict[str, str]], max_tokens: int = config.DEFAULT_SUMMARIZE_MAX_TOKENS) -> str:
    """
    Summarizes a segment of the chat history to condense it for the LLM's context window.

    Args:
        llm_instance (Llama): The loaded LLM model instance.
        chat_segment (List[Dict[str, str]]): A list of chat messages (user/assistant) to summarize.
        max_tokens (int): The maximum number of tokens for the summary.

    Returns:
        str: A concise summary of the chat segment.
    """
    if not chat_segment:
        return "The previous conversation was brief."

    # Format the chat segment into a single string for the LLM
    formatted_segment = ""
    for msg in chat_segment:
        formatted_segment += f"{msg['role'].capitalize()}: {msg['content']}\n"

    prompt = (
        "Condense the following conversation segment into a concise summary, focusing on the main topics discussed and any conclusions reached.\n"
        "Ensure the summary captures key information from both user and assistant turns.\n\n"
        f"Conversation Segment:\n{formatted_segment}\n\n"
        "Concise Summary:"
    )

    try:
        summary = generate_response(llm_instance, prompt, max_tokens=max_tokens)
        return summary
    except Exception as e:
        print(f"Error summarizing chat history segment: {e}")
        return "Could not summarize previous conversation."


if __name__ == "__main__":
    # Dummy generate_response for testing purposes if LLM is not actually loaded
    _original_generate_response = generate_response
    
    def dummy_generate_response(llm_instance_dummy, prompt_text, max_tokens):
        print(f"\n--- Dummy LLM Call (Max Tokens: {max_tokens}) ---\nPrompt starts with: {prompt_text[:200]}...")
        if "nmap" in prompt_text.lower() and "report data" in prompt_text.lower():
            return "Dummy Nmap Summary: Scanned hosts, found some open ports and OS details."
        elif "zap" in prompt_text.lower() and "report data" in prompt_text.lower():
            return "Dummy ZAP Summary: Identified several web vulnerabilities, including a high-risk SQL Injection."
        elif "sslscan" in prompt_text.lower() and "report data" in prompt_text.lower():
            return "Dummy SSLScan Summary: Analyzed SSL/TLS configurations, found weak protocols and an expired certificate."
        elif "mobsf raw report text" in prompt_text.lower():
            return "Dummy MobSF Summary: Reviewed mobile application. Overall low risk, but noted some excessive permissions and an outdated SDK."
        elif "conversation segment" in prompt_text.lower():
            return "Dummy Chat History Summary: User asked about X, bot explained Y and Z."
        return "Dummy LLM Response."

    # Override generate_response for testing
    generate_response = dummy_generate_response

    # Dummy LLM instance for testing (not a real Llama instance)
    class DummyLLMInstance:
        def __init__(self):
            print("Dummy LLM instance created for testing summarizer.")
        def create_chat_completion(self, *args, **kwargs):
            return {"choices": [{"message": {"content": "Dummy response from chat completion."}}]}

    dummy_llm_instance = DummyLLMInstance()

    if dummy_llm_instance:
        print("\n--- Testing Report Summarization ---")

        # Test Nmap summary
        dummy_nmap_data = {
            "scan_metadata": {"target": "example.com", "scan_type": "SYN Scan", "scan_start": "2025-01-01", "nmap_version": "7.92"},
            "hosts": [
                {"ip_address": "192.168.1.1", "hostname": "host1.example.com",
                 "os_detection": {"os_match": [{"name": "Linux 2.6.32", "accuracy": 90}]},
                 "ports": [{"port_id": "80", "protocol": "tcp", "state": "open", "service": "http", "version": "nginx 1.18.0"}]}
            ]
        }
        nmap_summary = summarize_report_with_llm(dummy_llm_instance, dummy_nmap_data, "nmap")
        print("Generated Nmap Summary:")
        print(nmap_summary)

        # Test ZAP summary
        dummy_zap_data = {
            "scan_metadata": {"tool": "ZAP", "report_id": "123", "generated_at": "2025-01-01", "site": "https://example.com", "zap_version": "2.10.0"},
            "summary": {"risk_counts": {"High": 1, "Medium": 2, "Low": 5, "Informational": 3, "False Positives": 0}},
            "vulnerabilities": [
                {"name": "SQL Injection", "risk": "High", "description": "SQL injection vulnerability found.", "cwe_id": "89", "urls": [{"url": "https://example.com/login"}]},
                {"name": "Cross Site Scripting", "risk": "Medium", "description": "XSS vulnerability.", "cwe_id": "79", "urls": [{"url": "https://example.com/search"}]}
            ]
        }
        zap_summary = summarize_report_with_llm(dummy_llm_instance, dummy_zap_data, "zap")
        print("Generated ZAP Summary:")
        print(zap_summary)

        # Test SSLScan summary
        dummy_sslscan_data = {
            "scan_metadata": {"tool": "SSLScan", "target_host": "secure.example.com", "connected_ip": "1.2.3.4", "scan_time": "2025-01-01T10:00:00Z"},
            "protocols": [{"name": "TLSv1.0", "status": "enabled", "info": "weak"}],
            "supported_ciphers": [{"name": "TLS_RSA_WITH_RC4_128_SHA", "key_exchange": "RSA", "bits": "128", "status": "weak"}],
            "ssl_certificate": {"subject": "CN=secure.example.com", "issuer": "O=Example CA", "valid_from": "2024-01-01", "valid_to": "2025-01-01", "signature_algorithm": "SHA256WithRSA"}
        }
        sslscan_summary = summarize_report_with_llm(dummy_llm_instance, dummy_sslscan_data, "sslscan")
        print("Generated SSLScan Summary:")
        print(sslscan_summary)

        # Test MobSF raw text summary (NEW function call)
        dummy_mobsf_raw_data = """
--- PAGE 1 ---

MOBSF

ANDROID STATIC ANALYSIS REPORT

TESTDROID
CLOUD

BitbarSampleApp (1.0)

App Security Score:
Grade:

32/100 (HIGH RISK)
C

--- PAGE 3 ---

FINDINGS SEVERITY

HIGH

4

MEDIUM

3

INFO

2

SECURE

0

FILE INFORMATION
File Name: bitbar-sample-app.apk
Size: 0.11MB
MD5: 00cc5435151aa38a091781922c0390a4

APP INFORMATION
App Name: BitbarSampleApp
Package Name: com.bitbar.testdroid
Target SDK: 33
Min SDK: 21

CODE ANALYSIS
Issue: Insecure Communication
Severity: High
Files: ['com.bitbar.testdroid. SomeClass.java']

Issue: Hardcoded Secrets
Severity: Medium
Files: ['com.bitbar.testdroid. AnotherClass.java']

APPLICATION PERMISSIONS
PERMISSION,STATUS,INFO,DESCRIPTION
android.permission.INTERNET,dangerous,Signature|System,Allows applications to open network sockets.
android.permission.READ_EXTERNAL_STORAGE,dangerous,Signature,Allows an application to read from external storage.
"""
        mobsf_summary = summarize_raw_text_report_with_llm(dummy_llm_instance, dummy_mobsf_raw_data, "mobsf")
        print("Generated MobSF Summary (using new raw text function):")
        print(mobsf_summary)

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
