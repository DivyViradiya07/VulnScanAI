
import re
import json
import uuid
from typing import Dict, List, Any, Optional
from datetime import datetime


def parse_mobsf_report(raw_mobsf_text: str) -> Dict[str, Any]:
    """
    Parses raw MOBSF report text into a structured dictionary.

    Args:
        raw_mobsf_text: The raw text content of a MOBSF report.

    Returns:
        dict: A structured dictionary containing MOBSF report information.
    """
    # Standardize newlines for easier regex matching
    raw_mobsf_text = re.sub(r'\r\n', '\n', raw_mobsf_text)
    raw_mobsf_text = re.sub(r'\r', '\n', raw_mobsf_text)

    report = {
        "scan_metadata": {
            "tool": "Mobile Security Framework (MobSF)",
            "report_id": str(uuid.uuid4()),
            "generated_at": None,
            "app_name": None,
            "package_name": None,
            "file_name": None,
            "version_name": None,
            "version_code": None,
            "mobsf_version": None
        },
        "security_score": {
            "score": None,
            "grade": None,
            "risk_level": None
        },
        "findings": {
            "high": [],
            "medium": [],
            "info": [],
            "secure": [],
            "hotspot": []
        },
        "manifest_analysis": {
            "high": [],
            "warning": [],
            "info": []
        },
        "code_analysis": {
            "high": [],
            "warning": [],
            "info": []
        },
        "certificate_analysis": {
            "high": [],
            "warning": [],
            "info": []
        },
        "permissions": {
            "dangerous": [],
            "normal": []
        },
        "file_information": {},
        "app_information": {},
        "app_components": {}
    }

    # Extract App Basic Information
    app_name_match = re.search(r'App Name:\s*\n\s*([^\n]+)', raw_mobsf_text)
    if app_name_match:
        report["scan_metadata"]["app_name"] = app_name_match.group(1).strip()

    package_name_match = re.search(r'Package Name:\s*\n\s*([^\n]+)', raw_mobsf_text)
    if package_name_match:
        report["scan_metadata"]["package_name"] = package_name_match.group(1).strip()

    file_name_match = re.search(r'File Name:\s*\n\s*([^\n]+)', raw_mobsf_text)
    if file_name_match:
        report["scan_metadata"]["file_name"] = file_name_match.group(1).strip()

    version_match = re.search(r'Android Version Name:\s*\n\s*([^\n]+)', raw_mobsf_text)
    if version_match:
        report["scan_metadata"]["version_name"] = version_match.group(1).strip()

    version_code_match = re.search(r'Android Version Code:\s*\n\s*([^\n]+)', raw_mobsf_text)
    if version_code_match:
        report["scan_metadata"]["version_code"] = version_code_match.group(1).strip()

    # Extract Security Score
    score_match = re.search(r'App Security Score:\s*\n\s*(\d+)/100', raw_mobsf_text)
    if score_match:
        report["security_score"]["score"] = int(score_match.group(1))

    grade_match = re.search(r'Grade:\s*\n\s*([A-F])', raw_mobsf_text)
    if grade_match:
        report["security_score"]["grade"] = grade_match.group(1).strip()

    # Extract Findings Count
    findings_section = re.search(r'FINDINGS SEVERITY.*?(?=\n\s*\uF1AB)', raw_mobsf_text, re.DOTALL)
    if findings_section:
        findings_text = findings_section.group(0)
        
        # Extract counts for each severity
        for severity in ["HIGH", "MEDIUM", "INFO", "SECURE", "HOTSPOT"]:
            count_match = re.search(fr'{severity}\s*\n\s*(\d+)', findings_text, re.IGNORECASE)
            if count_match:
                count = int(count_match.group(1))
                if count > 0:
                    report["findings"][severity.lower()].append({
                        "count": count,
                        "description": f"Found {count} {severity.lower()} severity issues"
                    })

    # Extract Manifest Analysis
    manifest_section = re.search(r'MANIFEST ANALYSIS.*?(?=\n\s*\uF05A)', raw_mobsf_text, re.DOTALL)
    if manifest_section:
        manifest_text = manifest_section.group(0)
        
        # Extract high severity issues
        high_issues = re.findall(r'\d+\n([^\n]+?)\n\s*(high|warning|info)', manifest_text, re.IGNORECASE)
        for issue, severity in high_issues:
            if "high" in severity.lower():
                report["manifest_analysis"]["high"].append(issue.strip())
            elif "warning" in severity.lower():
                report["manifest_analysis"]["warning"].append(issue.strip())
            else:
                report["manifest_analysis"]["info"].append(issue.strip())

    # Extract Code Analysis
    code_section = re.search(r'CODE ANALYSIS.*?(?=\n\s*\uF05A)', raw_mobsf_text, re.DOTALL)
    if code_section:
        code_text = code_section.group(0)
        
        # Extract code issues
        code_issues = re.findall(r'\d+\n([^\n]+?)\n\s*(high|warning|info)', code_text, re.IGNORECASE)
        for issue, severity in code_issues:
            if "high" in severity.lower():
                report["code_analysis"]["high"].append(issue.strip())
            elif "warning" in severity.lower():
                report["code_analysis"]["warning"].append(issue.strip())
            else:
                report["code_analysis"]["info"].append(issue.strip())

    # Extract Certificate Analysis
    cert_section = re.search(r'CERTIFICATE ANALYSIS.*?(?=\n\s*\uF05A)', raw_mobsf_text, re.DOTALL)
    if cert_section:
        cert_text = cert_section.group(0)
        
        # Extract certificate issues
        cert_issues = re.findall(r'TITLE\s*\n\s*([^\n]+?)\s*\n\s*SEVERITY\s*\n\s*([^\n]+?)\s*\n\s*DESCRIPTION\s*\n\s*([^\n]+)', cert_text, re.IGNORECASE)
        for title, severity, description in cert_issues:
            if "high" in severity.lower():
                report["certificate_analysis"]["high"].append({
                    "title": title.strip(),
                    "description": description.strip()
                })
            elif "warning" in severity.lower():
                report["certificate_analysis"]["warning"].append({
                    "title": title.strip(),
                    "description": description.strip()
                })
            else:
                report["certificate_analysis"]["info"].append({
                    "title": title.strip(),
                    "description": description.strip()
                })

    # Extract Permissions
    perm_section = re.search(r'APPLICATION PERMISSIONS.*?(?=\n\s*\uF1AB)', raw_mobsf_text, re.DOTALL)
    if perm_section:
        perm_text = perm_section.group(0)
        
        # Extract dangerous permissions
        dangerous_perms = re.findall(r'android\.permission\.[A-Z_]+\s*\n\s*dangerous', perm_text)
        for perm in dangerous_perms:
            report["permissions"]["dangerous"].append(perm.strip())
        
        # Extract normal permissions
        normal_perms = re.findall(r'android\.permission\.[A-Z_]+\s*\n\s*normal', perm_text)
        for perm in normal_perms:
            report["permissions"]["normal"].append(perm.split('\n')[0].strip())

    # Extract File Information
    file_info_section = re.search(r'FILE INFORMATION.*?(?=\n\s*\uF05A)', raw_mobsf_text, re.DOTALL)
    if file_info_section:
        file_info = {}
        for line in file_info_section.group(0).split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                file_info[key.strip()] = value.strip()
        report["file_information"] = file_info

    # Set risk level based on score
    if report["security_score"]["score"] is not None:
        score = report["security_score"]["score"]
        if score >= 80:
            report["security_score"]["risk_level"] = "Low"
        elif score >= 50:
            report["security_score"]["risk_level"] = "Medium"
        else:
            report["security_score"]["risk_level"] = "High"

    return report


def process_mobsf_report_file(report_path: str) -> Dict[str, Any]:
    """
    Processes a MOBSF report file and returns structured data.

    Args:
        report_path: Path to the MOBSF report file (PDF or text).

    Returns:
        dict: Structured MOBSF report data.
    """
    try:
        # Check if it's a PDF or text file
        if report_path.lower().endswith('.pdf'):
            # Use the PDF extractor if available
            try:
                from .pdf_extractor import extract_text_from_pdf
                raw_text = extract_text_from_pdf(report_path)
            except ImportError:
                from pdf_extractor import extract_text_from_pdf
                raw_text = extract_text_from_pdf(report_path)
        else:
            # Assume it's a text file
            with open(report_path, 'r', encoding='utf-8', errors='ignore') as f:
                raw_text = f.read()
        
        return parse_mobsf_report(raw_text)
    
    except Exception as e:
        return {
            "error": f"Failed to process MOBSF report: {str(e)}",
            "exception": str(type(e).__name__)
        }


if __name__ == "__main__":
    # Example usage
    import sys
    
    if len(sys.argv) > 1:
        report_path = sys.argv[1]
        result = process_mobsf_report_file(report_path)
        print(json.dumps(result, indent=2))
    else:
        print("Usage: python mobsf_parser.py <path_to_mobsf_report>")
        print("Example: python mobsf_parser.py mobsf_report.pdf")
        sys.exit(1)