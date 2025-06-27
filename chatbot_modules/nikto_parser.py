import os
import re
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

# In a real scenario, if this were part of a larger system,
# you might have a generic text extractor or directly pass content.
# For this example, we'll assume the content is read into a string.


def parse_nikto_report(raw_nikto_text: str) -> Dict[str, Any]:
    """
    Parses raw Nikto report text into a structured dictionary.

    Args:
        raw_nikto_text (str): The raw text content of a Nikto report.

    Returns:
        dict: A structured dictionary containing Nikto report information.
    """
    # Standardize newlines for easier regex matching
    raw_nikto_text = re.sub(r'\r\n', '\n', raw_nikto_text)
    raw_nikto_text = re.sub(r'\r', '\n', raw_nikto_text)

    report_data: Dict[str, Any] = {
        "scan_metadata": {
            "tool": "Nikto Report"  # Identify the tool
        },
        "host_details": {},
        "findings": [],
        "scan_summary": {}
    }

    # --- Parse Host Details ---
    # Target Hostname
    match = re.search(r'Target hostname\s*([^\n]+)', raw_nikto_text)
    if match:
        report_data["host_details"]["hostname"] = match.group(1).strip()
    
    # Target IP
    match = re.search(r'Target IP\s*([\d\.]{7,15})', raw_nikto_text)
    if match:
        report_data["host_details"]["ip"] = match.group(1).strip()

    # Target Port
    match = re.search(r'Target Port\s*(\d+)', raw_nikto_text)
    if match:
        report_data["host_details"]["port"] = int(match.group(1))

    # HTTP Server
    match = re.search(r'HTTP Server\s*([^\n]+)', raw_nikto_text)
    if match:
        report_data["host_details"]["http_server"] = match.group(1).strip()
    
    # Site Link (Name)
    match = re.search(r'Site Link \(Name\)\s*(https?:\/\/[^\s]+)', raw_nikto_text)
    if match:
        report_data["host_details"]["site_link_name"] = match.group(1).strip()

    # Site Link (IP)
    match = re.search(r'Site Link \(IP\)\s*(https?:\/\/[^\s]+)', raw_nikto_text)
    if match:
        report_data["host_details"]["site_link_ip"] = match.group(1).strip()

    # --- Parse Findings ---
    # Each finding block starts with 'URI /' and ends before the next 'URI /' or 'Host Summary'
    findings_blocks = re.split(r'(?=URI /)', raw_nikto_text)
    
    for block in findings_blocks:
        if block.strip().startswith("URI /"):
            finding: Dict[str, Any] = {}
            
            # URI
            uri_match = re.search(r'URI\s*([^\n]+)', block)
            if uri_match:
                finding["uri"] = uri_match.group(1).strip()
            
            # HTTP Method
            method_match = re.search(r'HTTP Method\s*([^\n]+)', block)
            if method_match:
                finding["http_method"] = method_match.group(1).strip()
            
            # Description (can be multiline, so be careful with lookahead)
            description_match = re.search(r'Description\s*([^\n]+(?:\n\s*[^\n]+)*?)(?=\nTest Links|\nReferences|$)', block, re.DOTALL)
            if description_match:
                finding["description"] = description_match.group(1).strip()
            
            # Test Links
            test_links_match = re.search(r'Test Links\s*(https?:\/\/[^\n]+(?:\nhttps?:\/\/[^\n]+)*)', block)
            if test_links_match:
                finding["test_links"] = [link.strip() for link in test_links_match.group(1).splitlines() if link.strip()]

            # References (can be multiline)
            references_match = re.search(r'References\s*([^\n]*?(?:\n\s*[^\n]*)*?)(?=\nURI /|\nHost Summary|$)', block, re.DOTALL)
            if references_match and references_match.group(1).strip():
                # Split by newline and filter out empty strings, then strip each.
                # Handle cases where references might be empty or just whitespace after 'References'
                refs = [ref.strip() for ref in references_match.group(1).splitlines() if ref.strip()]
                if refs:
                    finding["references"] = refs
                else:
                    finding["references"] = [] # Explicitly empty if no meaningful references

            if finding: # Only add if we found at least some data for the finding
                report_data["findings"].append(finding)

    # --- Parse Host Summary ---
    host_summary_section_match = re.search(r'Host Summary\s*(.*?)(?=Scan Summary|$)', raw_nikto_text, re.DOTALL)
    if host_summary_section_match:
        host_summary_text = host_summary_section_match.group(1)
        
        # Start Time
        match = re.search(r'Start Time\s*([^\n]+)', host_summary_text)
        if match:
            report_data["scan_metadata"]["start_time_host_summary"] = match.group(1).strip()
        
        # End Time
        match = re.search(r'End Time\s*([^\n]+)', host_summary_text)
        if match:
            report_data["scan_metadata"]["end_time_host_summary"] = match.group(1).strip()
        
        # Elapsed Time
        match = re.search(r'Elapsed Time\s*([\d\.]+\s*seconds?)', host_summary_text)
        if match:
            report_data["scan_metadata"]["elapsed_time_host_summary"] = match.group(1).strip()
        
        # Statistics
        match = re.search(r'Statistics\s*(\d+)\s*requests,\s*(\d+)\s*errors,\s*(\d+)\s*findings', host_summary_text)
        if match:
            report_data["host_details"]["statistics"] = {
                "requests": int(match.group(1)),
                "errors": int(match.group(2)),
                "findings": int(match.group(3))
            }

    # --- Parse Scan Summary ---
    scan_summary_section_match = re.search(r'Scan Summary\s*(.*)', raw_nikto_text, re.DOTALL)
    if scan_summary_section_match:
        scan_summary_text = scan_summary_section_match.group(1)

        # Software Details
        match = re.search(r'Software\s*Details\s*([^\n]+)', scan_summary_text)
        if match:
            report_data["scan_summary"]["software"] = match.group(1).strip()

        # CLI Options
        match = re.search(r'CLI\s*Options\s*([^\n]+(?:\n\s*[^\n]+)*)', scan_summary_text)
        if match:
            report_data["scan_summary"]["cli_options"] = match.group(1).strip()
        
        # Hosts Tested
        match = re.search(r'Hosts\s*Tested\s*(\d+)', scan_summary_text)
        if match:
            report_data["scan_summary"]["hosts_tested"] = int(match.group(1))

        # Start Time (Scan Summary)
        match = re.search(r'Start\s*Time\s*([^\n]+)', scan_summary_text)
        if match:
            report_data["scan_summary"]["start_time"] = match.group(1).strip()

        # End Time (Scan Summary)
        match = re.search(r'End\s*Time\s*([^\n]+)', scan_summary_text)
        if match:
            report_data["scan_summary"]["end_time"] = match.group(1).strip()

        # Elapsed Time (Scan Summary)
        match = re.search(r'Elapsed\s*Time\s*([\d\.]+\s*seconds?)', scan_summary_text)
        if match:
            report_data["scan_summary"]["elapsed_time"] = match.group(1).strip()

    return report_data

def process_nikto_report_file(file_path: str) -> Dict[str, Any]:
    """
    Processes a Nikto report file (assumed to be plain text or extractable)
    and returns structured data.

    Args:
        file_path (str): Path to the Nikto report file.

    Returns:
        dict: Structured Nikto report data.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Nikto report not found: {file_path}")

    print(f"Processing Nikto report: {file_path}")

    try:
        # Try different encodings to read the file
        encodings = ['utf-8', 'latin-1', 'iso-8859-1', 'cp1252']
        raw_text = None
        
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    raw_text = f.read()
                break  # Successfully read the file
            except UnicodeDecodeError:
                continue
        
        if raw_text is None:
            # If all encodings fail, try reading as binary and decoding with 'replace' to handle errors
            with open(file_path, 'rb') as f:
                raw_text = f.read().decode('utf-8', errors='replace')

        if not raw_text.strip():
            raise ValueError("File is empty or contains only whitespace.")

        # Parse the Nikto report
        report_data = parse_nikto_report(raw_text)

        # Add file metadata
        report_data["file_metadata"] = {
            "filename": os.path.basename(file_path),
            "file_size": os.path.getsize(file_path),
            "last_modified": datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
        }

        return report_data

    except Exception as e:
        print(f"Error processing Nikto report {file_path}: {str(e)}")
        raise

if __name__ == "__main__":
    # Example usage with the provided text directly
    nikto_sample_report_text = """
saucedemo.com /
185.199.1 11.153 port 443
Target IP 185.199.111.153
Target hostname saucedemo.com
Target Port 443
HTTP Server GitHub.com
Site Link (Name) https://saucedemo.com:443/
Site Link (IP) https://185.199.111.153:443/
URI /
HTTP Method GET
Description /: Retrieved via header: 1.1 varnish.
Test Links https://saucedemo.com:443/
https://185.199.111.153:443/
References
URI /
HTTP Method GET
Description /: Retrieved x-served-by header: cache-bom4745-BOM.
Test Links https://saucedemo.com:443/
https://185.199.111.153:443/
References
URI /
HTTP Method GET
Description /: The anti-clickjacking X-Frame-Options header is not present.
Test Links https://saucedemo.com:443/
https://185.199.111.153:443/
References https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
URI /
HTTP Method GET
Description /: Fastly CDN was identified by the x-timer header.
Test Links https://saucedemo.com:443/
https://185.199.111.153:443/
References https://www.fastly.com/
URI /
HTTP Method GET
Description /: Uncommon header 'x-fastly-request-id' found, with contents:
5b8833ada78c6d4eccaa79ca0fb7663b9e89b660.
Test Links https://saucedemo.com:443/
https://185.199.111.153:443/
References
URI /
HTTP Method GET
Description /: Uncommon header 'x-served-by' found, with contents: cache-bom4745-BOM.
Test Links https://saucedemo.com:443/
https://185.199.111.153:443/
References
URI /
HTTP Method GET
Description /: Uncommon header 'x-github-request-id' found, with contents:
BFF7:102AF0:48C5:5330:68035047.
Test Links https://saucedemo.com:443/
https://185.199.111.153:443/19/04/2025, 12:57 Nikto Report
file:///home/isec/Desktop/VulnScanAI_Final_Iteration/app/reports/nikto/nikto_results/1_nikto_20250419_125703.html 1/2
References
URI /
HTTP Method GET
Description /: The site uses TLS and the Strict-Transport-Security HTTP header is not
defined.
Test Links https://saucedemo.com:443/
https://185.199.111.153:443/
References https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-
Security
URI /
HTTP Method GET
Description /: The X-Content-Type-Options header is not set. This could allow the user
agent to render the content of the site in a different fashion to the MIME type.
Test Links https://saucedemo.com:443/
https://185.199.111.153:443/
References https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-
content-type-header/
Host Summary
Start Time 2025-04-19 12:57:04
End Time 2025-04-19 12:57:30
Elapsed Time 26 seconds
Statistics 97 requests, 0 errors, 9 findings
Scan Summary
Software
DetailsNikto 2.5.0
CLI
Options-h https://saucedemo.com -output
/home/isec/Desktop/VulnScanAI_Final_Iteration/app/reports/nikto/nikto_results/1_nikto_20250419_125703.html
-Format html -timeout 10 -maxtime 25 -Tuning 123bde
Hosts
Tested1
Start
TimeSat Apr 19 12:57:03 2025
End
TimeSat Apr 19 12:57:30 2025
Elapsed
Time27 seconds
 2008 Chris Sullo19/04/2025, 12:57 Nikto Report
file:///home/isec/Desktop/VulnScanAI_Final_Iteration/app/reports/nikto/nikto_results/1_nikto_20250419_125703.html 2/2
"""

    try:
        print("Parsing Nikto sample report text directly...")
        parsed_data = parse_nikto_report(nikto_sample_report_text)
        
        if parsed_data:
            print("\nParsed Nikto Report Data:")
            print(json.dumps(parsed_data, indent=2))
            print("\nReport processed successfully!")
        else:
            print("Error: Failed to parse the Nikto report.")
            
    except Exception as e:
        print(f"Error processing text: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    # Example of how to use process_nikto_report_file if you save the above text to a file:
    # import sys
    # if len(sys.argv) != 2:
    #     print("Usage: python nikto_parser.py <path_to_nikto_report.txt>")
    #     sys.exit(1)
        
    # file_path = sys.argv[1]
    
    # if not os.path.exists(file_path):
    #     print(f"Error: File not found: {file_path}")
    #     sys.exit(1)
    
    # try:
    #     print(f"Processing Nikto report file: {file_path}")
    #     parsed_data = process_nikto_report_file(file_path)
        
    #     if parsed_data:
    #         print("\nParsed Nikto Report Data:")
    #         print(json.dumps(parsed_data, indent=2))
    #         print("\nReport processed successfully!")
    #     else:
    #         print("Error: Failed to parse the Nikto report.")
            
    # except Exception as e:
    #     print(f"Error processing file: {str(e)}")
    #     import traceback
    #     traceback.print_exc()
    #     sys.exit(1)
    