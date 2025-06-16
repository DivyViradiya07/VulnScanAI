import os
import re
import json
import uuid
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

# Import the PDF extractor for text extraction
try:
    from .pdf_extractor import extract_text_from_pdf
except ImportError:
    from pdf_extractor import extract_text_from_pdf
def parse_zap_report(raw_zap_text: str) -> Dict[str, Any]:
    """
    Parses raw ZAP report text into a structured dictionary based on the provided PDF format.

    Args:
        raw_zap_text: The raw text content of a ZAP report.

    Returns:
        dict: A structured dictionary containing ZAP report information.
    """
    # Standardize newlines for easier regex matching
    raw_zap_text = re.sub(r'\r\n', '\n', raw_zap_text)
    raw_zap_text = re.sub(r'\r', '\n', raw_zap_text)

    report = {
        "scan_metadata": {
            "tool": "Checkmarx ZAP Report",
            "report_id": str(uuid.uuid4()),
            "generated_at": None,
            "site": None,
            "zap_version": None
        },
        "summary": {
            "risk_counts": {"High": 0, "Medium": 0, "Low": 0, "Informational": 0, "False Positives": 0},
            "total_alerts": 0,
            "alerts_by_name": [],
            "scanned_urls": set()
        },
        "vulnerabilities": []
    }

    # --- Extract Scan Metadata ---
    site_match = re.search(r"Site: (https?://[^\s]+)", raw_zap_text)
    if site_match:
        report["scan_metadata"]["site"] = site_match.group(1).strip()
        report["summary"]["scanned_urls"].add(site_match.group(1).strip())

    generated_on_match = re.search(r"Generated on (.*)", raw_zap_text)
    if generated_on_match:
        try:
            generated_datetime_str = generated_on_match.group(1).strip()
            report["scan_metadata"]["generated_at"] = datetime.strptime(generated_datetime_str, "%a, %d %b %Y %H:%M:%S").isoformat()
        except ValueError:
            report["scan_metadata"]["generated_at"] = generated_datetime_str

    zap_version_match = re.search(r"ZAP Version: (\d+\.\d+\.\d+)", raw_zap_text)
    if zap_version_match:
        report["scan_metadata"]["zap_version"] = zap_version_match.group(1).strip()

    # --- Parse "Summary of Alerts" Table ---
    # Relaxed whitespace matching for robustness
    summary_alerts_table_match = re.search(
        r"Risk Level\s*\n\s*Number of Alerts\s*\n\s*High\s*\n\s*(\d+)\s*\n\s*Medium\s*\n\s*(\d+)\s*\n\s*Low\s*\n\s*(\d+)\s*\n\s*Informational\s*\n\s*(\d+)\s*\n\s*False Positives:\s*\n\s*(\d+)",
        raw_zap_text,
        re.DOTALL
    )

    if summary_alerts_table_match:
        report["summary"]["risk_counts"]["High"] = int(summary_alerts_table_match.group(1))
        report["summary"]["risk_counts"]["Medium"] = int(summary_alerts_table_match.group(2))
        report["summary"]["risk_counts"]["Low"] = int(summary_alerts_table_match.group(3))
        report["summary"]["risk_counts"]["Informational"] = int(summary_alerts_table_match.group(4))
        report["summary"]["risk_counts"]["False Positives"] = int(summary_alerts_table_match.group(5))
        report["summary"]["total_alerts"] = sum(report["summary"]["risk_counts"][key] for key in ["High", "Medium", "Low", "Informational"])

    # --- Parse "Alerts" Table (Summary of Names and Instances) ---
    alerts_table_content_match = re.search(
        r"Alerts\s*\n\s*Name\s*\n\s*Risk Level\s*\n\s*Number of\s*\n\s*Instances\s*\n(.*?)(?=Alert Detail)",
        raw_zap_text,
        re.DOTALL
    )

    if alerts_table_content_match:
        alerts_content = alerts_table_content_match.group(1).strip()
        
        # New regex to capture Name, Risk Level, and Instances across multiple lines
        alert_line_pattern = re.compile(
            r"(.+?)\s*\n\s*(High|Medium|Low|Informational)\s*\n\s*(\d+)",
            re.DOTALL
        )
        
        for match in alert_line_pattern.finditer(alerts_content):
            name = match.group(1).strip()
            risk = match.group(2).strip()
            instances = int(match.group(3))

            report["summary"]["alerts_by_name"].append({
                "name": name,
                "risk_level": risk,
                "instances_count": instances
            })

    # --- Parse "Alert Detail" Sections ---
    # Split the text into individual alert detail sections.
    # The split pattern looks for a risk level followed by a new line and then the alert name.
    # It attempts to split before each new alert detail section starts.
    alert_detail_sections = re.split(r"(?=\n(?:Medium|Low|Informational)\n)", raw_zap_text)

    for section in alert_detail_sections:
        if not section.strip():
            continue # Skip empty sections

        # Check for keywords that indicate this is a valid alert detail section
        if not any(keyword in section for keyword in ["Description", "URL", "Solution", "Reference"]):
            continue

        vuln = {
            "id": str(uuid.uuid4()),
            "name": None,
            "risk": None,
            "description": None,
            "urls": [], # To store URL, Method, Parameter, Attack, Evidence, Other Info
            "instances_count": 0,
            "solution": None,
            "references": [],
            "cwe_id": None,
            "wasc_id": None,
            "plugin_id": None
        }

        # Extract Risk Level and Name
        # This regex captures the risk level and the full name of the alert, being non-greedy
        # and stopping before "Description" or "URL" or other sections.
        risk_name_match = re.match(
            r"^\s*(High|Medium|Low|Informational)\s*\n\s*(.+?)(?=\n\s*Description|\n\s*URL|\n\s*Instances|\n\s*Solution|\n\s*Reference|\n\s*CWE Id|\n\s*WASC Id|\n\s*Plugin Id|\Z)",
            section,
            re.DOTALL
        )

        if risk_name_match:
            vuln["risk"] = risk_name_match.group(1).strip()
            vuln["name"] = risk_name_match.group(2).strip()
        else:
            # Fallback for alert names that might appear differently or if initial match fails
            # This is less ideal but can catch some cases.
            name_only_match = re.match(r"^\s*(Content Security Policy \(CSP\) Header Not Set|Missing Anti-clickjacking Header|Strict-Transport-Security Header Not Set|X-Content-Type-Options Header Missing|Re-examine Cache-control Directives)", section)
            if name_only_match:
                vuln["name"] = name_only_match.group(1).strip()
                # Try to infer risk if not explicitly captured by the first regex
                if "Medium" in section: vuln["risk"] = "Medium"
                elif "Low" in section: vuln["risk"] = "Low"
                elif "Informational" in section: vuln["risk"] = "Informational"

        if not vuln["name"]:
            continue # Skip if no valid name is found for the alert detail section


        # Description
        desc_match = re.search(r"Description\s*\n*(.*?)(?=URL|Method|Parameter|Attack|Evidence|Other\s*Info|Instances|Solution|Reference|CWE Id|WASC Id|Plugin Id|\Z)", section, re.DOTALL)
        if desc_match:
            cleaned_description = re.sub(r'\s+', ' ', desc_match.group(1)).strip()
            vuln["description"] = cleaned_description

        # URLs, Method, Parameter, Attack, Evidence, Other Info (can have multiple instances)
        # This pattern is refined to handle the 'Other Info' possibly ending a block or being followed by a URL
        url_block_pattern = re.compile(
            r"URL\s*\n\s*(https?://[^\n]+)\s*\n"
            r"Method\s*\n\s*([^\n]+)\s*\n"
            r"Parameter\s*\n\s*([^\n]*?)\s*\n"
            r"Attack\s*\n\s*([^\n]*?)\s*\n"
            r"Evidence\s*\n\s*([^\n]*?)\s*\n"
            r"Other\s*Info\s*\n\s*([^\n]*?)(?=\n\s*URL|\n\s*Instances|\n\s*Solution|\n\s*Reference|\n\s*CWE Id|\n\s*WASC Id|\n\s*Plugin Id|\Z)", re.DOTALL
        )
        url_blocks = url_block_pattern.findall(section)

        for block in url_blocks:
            instance_detail = {
                "url": block[0].strip(),
                "method": block[1].strip(),
                "parameter": block[2].strip(),
                "attack": block[3].strip(),
                "evidence": block[4].strip(),
                "other_info": block[5].strip()
            }
            vuln["urls"].append(instance_detail)
            report["summary"]["scanned_urls"].add(block[0].strip())

        # Instances Count
        instances_match = re.search(r"Instances\s*\n\s*(\d+)", section)
        if instances_match:
            vuln["instances_count"] = int(instances_match.group(1))

        # Solution
        solution_match = re.search(r"Solution\s*\n*(.*?)(?=Reference|CWE Id|WASC Id|Plugin Id|\Z)", section, re.DOTALL)
        if solution_match:
            # Clean up solution by removing extra newlines and leading/trailing spaces
            cleaned_solution = re.sub(r'\s+', ' ', solution_match.group(1)).strip()
            vuln["solution"] = cleaned_solution

        # References
        references_section_match = re.search(r"Reference\s*\n*(.*?)(?=CWE Id|WASC Id|Plugin Id|\Z)", section, re.DOTALL)
        if references_section_match:
            refs_text = references_section_match.group(1).strip()
            # Split by newlines and filter out empty strings, then clean
            raw_refs = [line.strip() for line in refs_text.split('\n') if line.strip()]
            # Filter out lines that might be part of the solution or other fields
            filtered_refs = [ref for ref in raw_refs if ref.startswith("http")] # Keep only lines that start with http
            vuln["references"] = filtered_refs

        # CWE Id, WASC Id, Plugin Id
        cwe_match = re.search(r"CWE Id\s*\n*\s*(\d+)", section)
        if cwe_match:
            vuln["cwe_id"] = int(cwe_match.group(1))

        wasc_match = re.search(r"WASC Id\s*\n*\s*(\d+)", section)
        if wasc_match:
            vuln["wasc_id"] = int(wasc_match.group(1))

        plugin_match = re.search(r"Plugin Id\s*\n*\s*(\d+)", section)
        if plugin_match:
            vuln["plugin_id"] = int(plugin_match.group(1))

        report["vulnerabilities"].append(vuln)

    # Convert sets to lists for JSON serialization
    report["summary"]["scanned_urls"] = list(report["summary"]["scanned_urls"])

    return report

def process_zap_report_file(pdf_path: str) -> Dict[str, Any]:
    """
    Processes a ZAP report PDF file and returns structured data.

    Args:
        pdf_path: Path to the ZAP report PDF file.

    Returns:
        dict: Structured ZAP report data.
    """
    if not os.path.exists(pdf_path):
        raise FileNotFoundError(f"ZAP report not found: {pdf_path}")

    print(f"Processing ZAP report: {pdf_path}")

    # Extract text from PDF
    try:
        raw_text = extract_text_from_pdf(pdf_path)
        if not raw_text.strip():
            raise ValueError("Extracted text is empty or contains only whitespace.")

        # Parse the ZAP report
        report_data = parse_zap_report(raw_text)

        # Add file metadata
        report_data["file_metadata"] = {
            "filename": os.path.basename(pdf_path),
            "file_size": os.path.getsize(pdf_path),
            "last_modified": datetime.fromtimestamp(os.path.getmtime(pdf_path)).isoformat()
        }

        return report_data

    except Exception as e:
        print(f"Error processing ZAP report {pdf_path}: {str(e)}")
        raise

if __name__ == "__main__":
    # Example usage
    import sys
    
    # This check needs to be adjusted for the environment it runs in.
    # In a typical script, you'd ensure pdf_extractor is available.
    # Here, we'll ensure a dummy is created if it's missing for standalone execution.
    if not os.path.exists("pdf_extractor.py"):
        with open("pdf_extractor.py", "w") as f:
            f.write("""
import PyPDF2
import os

def extract_text_from_pdf(pdf_path: str) -> str:
    if not os.path.exists(pdf_path):
        raise FileNotFoundError(f"The PDF file was not found: {pdf_path}")
    extracted_text = ""
    try:
        with open(pdf_path, 'rb') as file:
            reader = PyPDF2.PdfReader(file)
            for page_num in range(len(reader.pages)):
                page = reader.pages[page_num]
                text = page.extract_text()
                if text:
                    extracted_text += text + "\\n"
    except PyPDF2.errors.PdfReadError as e:
        raise PyPDF2.errors.PdfReadError(f"Error reading PDF file {pdf_path}: {e}. It might be corrupted or encrypted.")
    except Exception as e:
        raise Exception(f"Error extracting text from PDF {pdf_path}: {e}")
    return extracted_text

if __name__ == "__main__":
    # Dummy usage for pdf_extractor.py
    print("This is a dummy pdf_extractor.py. It requires an actual PDF file and 'pypdf' library to function fully.")
""")
        print("Created a dummy 'pdf_extractor.py'. Please ensure 'pypdf' is installed (`pip install pypdf`).")

    if len(sys.argv) > 1:
        report_path = sys.argv[1]
        try:
            report = process_zap_report_file(report_path)
            print(f"Successfully processed ZAP report: {report_path}")
            print(f"Found {len(report['vulnerabilities'])} vulnerabilities")
            print(f"Risk counts: {report['summary']['risk_counts']}")

            # Save structured output to a JSON file
            output_path = os.path.splitext(report_path)[0] + "_parsed.json"
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"Structured output saved to: {output_path}")

        except Exception as e:
            print(f"Error: {str(e)}")
            sys.exit(1)
    else:
        print("Usage: python zap_parser.py <path_to_zap_report.pdf>")
        print("\nNo file path provided. Please provide a path to a ZAP report PDF file.")