import json
from typing import Dict, Any

# Assuming local_llm.py is in the same directory or accessible via PYTHONPATH
# from local_llm import Llama, generate_response # You'll need Llama class for type hinting
from local_llm import generate_response, load_model # Import generate_response and load_model directly

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

def summarize_report_with_llm(
    llm_instance: Llama, parsed_data: Dict[str, Any], report_type: str
) -> str:
    """
    Generates a natural language summary and remediation steps for a parsed security report
    using the local LLM.

    Args:
        llm_instance (Llama): The loaded Llama model instance.
        parsed_data (Dict[str, Any]): The structured dictionary parsed from the report.
        report_type (str): The type of the report ("nmap" or "zap").

    Returns:
        str: The generated explanation and remediation steps from the LLM.
    """
    if report_type.lower() == "nmap":
        prompt = _format_nmap_summary_prompt(parsed_data)
    elif report_type.lower() == "zap":
        prompt = _format_zap_summary_prompt(parsed_data)
    else:
        return "Error: Unsupported report type for summarization. Please specify 'nmap' or 'zap'."

    print(f"\n--- Sending formatted prompt to LLM for {report_type} report ---")
    # print(prompt[:1000]) # Print first 1000 chars of prompt for debugging

    try:
        llm_response = generate_response(llm_instance, prompt)
        return llm_response
    except Exception as e:
        return f"Error generating LLM response: {e}"

# Example usage (for testing summarizer.py directly if needed)
if __name__ == "__main__":
    print("--- Testing summarizer.py directly ---")
    # This requires a dummy local_llm and parsed data.
    # In a real run, main.py will handle loading and parsing.

    # Dummy LLM instance (replace with actual load_model in main.py)
    # For standalone testing, you might need to mock or actually load the model here.
    # from local_llm import load_model, generate_response
    # MODEL_ID = "TheBloke/OpenHermes-2.5-Mistral-7B-GGUF"
    # MODEL_BASENAME = "openhermes-2.5-mistral-7b.Q4_K_M.gguf"
    # MODEL_DIR = "pretrained_language_model" # Or a suitable path
    # print("Loading dummy LLM (please ensure 'local_llm.py' is configured to load a real model)...")
    # try:
    #     dummy_llm_instance = load_model(MODEL_ID, MODEL_BASENAME, MODEL_DIR)
    #     print("Dummy LLM loaded.")
    # except Exception as e:
    #     print(f"Could not load LLM for direct summarizer test: {e}. Please ensure model path and settings are correct.")
    #     dummy_llm_instance = None # Set to None if loading fails

    # Mock LLM instance for local testing without actual model download/load
    class MockLlama:
        def create_chat_completion(self, messages, max_tokens, temperature, stop):
            print(f"Mock LLM received prompt: {messages[0]['content'][:200]}...")
            return {"choices": [{"message": {"content": "This is a mock LLM summary and remediation plan."}}]}

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

    if dummy_llm_instance:
        print("\n--- Testing with Nmap Report ---")
        nmap_summary = summarize_report_with_llm(dummy_llm_instance, dummy_nmap_data, "nmap")
        print("Generated Nmap Summary:")
        print(nmap_summary)

        print("\n--- Testing with ZAP Report ---")
        zap_summary = summarize_report_with_llm(dummy_llm_instance, dummy_zap_data, "zap")
        print("Generated ZAP Summary:")
        print(zap_summary)
    else:
        print("Skipping summarizer tests as LLM instance could not be loaded.")

