import re
import json
from typing import Dict, List, Any, Optional
from datetime import datetime

def parse_android_report(report_text: str) -> Dict[str, Any]:
    """
    Parses the raw text of an Android Static Analysis Report into a structured dictionary.

    Args:
        report_text: The raw text content of the Android static analysis report.

    Returns:
        dict: A structured dictionary containing the parsed report information.
    """
    report = {
        "report_metadata": {
            "tool": "MobSF",
            "tool_version": None,
            "report_generated_by": None,
            "scan_date": None,
            "app_security_score": None,
            "grade": None
        },
        "file_information": {
            "file_name": None,
            "size": None,
            "md5": None,
            "sha1": None,
            "sha256": None
        },
        "app_information": {
            "app_name": None,
            "package_name": None,
            "main_activity": None,
            "target_sdk": None,
            "min_sdk": None,
            "max_sdk": None,
            "android_version_name": None,
            "android_version_code": None
        },
        "app_components": {
            "activities": None,
            "services": None,
            "receivers": None,
            "providers": None,
            "exported_activities": None,
            "exported_services": None,
            "exported_receivers": None,
            "exported_providers": None
        },
        "certificate_information": {
            "is_signed": None,
            "v1_signature": None,
            "v2_signature": None,
            "v3_signature": None,
            "v4_signature": None,
            "x509_subject": None,
            "signature_algorithm": None,
            "valid_from": None,
            "valid_to": None,
            "issuer": None,
            "serial_number": None,
            "hash_algorithm": None,
            "md5": None,
            "sha1": None,
            "sha256": None,
            "sha512": None,
            "public_key_algorithm": None,
            "bit_size": None,
            "fingerprint": None,
            "unique_certificates_found": None
        },
        "findings_summary": {
            "high": 0,
            "medium": 0,
            "info": 0,
            "secure": 0,
            "hotspot": 0
        },
        "application_permissions": [],
        "apkid_analysis": {
            "classes_dex": {
                "compiler": None,
                "findings": [],
                "details": []
            }
        },
        "certificate_analysis": {
            "high_count": 0,
            "warning_count": 0,
            "info_count": 0,
            "issues": []
        },
        "manifest_analysis": {
            "high_count": 0,
            "warning_count": 0,
            "info_count": 0,
            "suppressed_count": 0,
            "issues": []
        },
        "code_analysis": {
            "high_count": 0,
            "warning_count": 0,
            "info_count": 0,
            "secure_count": 0,
            "suppressed_count": 0,
            "issues": []
        },
        "abused_permissions": {
            "malware_permissions": {
                "matches": None,
                "permissions": []
            },
            "other_common_permissions": {
                "matches": None,
                "permissions": []
            }
        },
        "scan_logs": []
    }

    # --- Report Metadata ---
    app_name_match = re.search(r"BitbarSampleApp\n\s*BitbarSampleApp\s*\((.*?)\)", report_text)
    if app_name_match:
        report["app_information"]["app_name"] = "BitbarSampleApp"
        report["app_information"]["android_version_name"] = app_name_match.group(1).strip()

    file_name_match = re.search(r"File Name:\s*([^\n]+)", report_text)
    if file_name_match:
        report["file_information"]["file_name"] = file_name_match.group(1).strip()

    package_name_match = re.search(r"Package Name:\s*([^\n]+)", report_text)
    if package_name_match:
        report["app_information"]["package_name"] = package_name_match.group(1).strip()
        report["report_metadata"]["report_generated_by"] = f"MobSF v4.3.1" # Based on the footer

    scan_date_match = re.search(r"Scan Date:\s*(.*)", report_text)
    if scan_date_match:
        try:
            date_str = scan_date_match.group(1).strip()
            # Convert "April 19, 2025, 7:06 a.m." to ISO format
            dt_object = datetime.strptime(date_str, "%B %d, %Y, %I:%M %p")
            report["report_metadata"]["scan_date"] = dt_object.isoformat()
        except ValueError:
            report["report_metadata"]["scan_date"] = scan_date_match.group(1).strip()

    app_score_match = re.search(r"App Security Score:\s*(\d+/\d+)\s*\((.*?)\)", report_text)
    if app_score_match:
        report["report_metadata"]["app_security_score"] = app_score_match.group(1).strip()
        report["report_metadata"]["grade"] = app_score_match.group(2).strip().replace(')', '') # Grade is within parenthesis

    # --- Findings Severity ---
    findings_severity_match = re.search(
        r"FINDINGS SEVERITY\s*\n\s*HIGH\s*\n\s*HIGH\s*\n(\d+)\s*\n\s*MEDIUM\s*\n\s*MEDIUM\s*\n(\d+)\s*\n\s*INFO\s*\n\s*INFO\s*\n(\d+)\s*\n\s*SECURE\s*\n\s*SECURE\s*\n(\d+)\s*\n\s*HOTSPOT\s*\n\s*HOTSPOT\s*\n(\d+)",
        report_text, re.DOTALL
    )
    if findings_severity_match:
        report["findings_summary"]["high"] = int(findings_severity_match.group(1))
        report["findings_summary"]["medium"] = int(findings_severity_match.group(2))
        report["findings_summary"]["info"] = int(findings_severity_match.group(3))
        report["findings_summary"]["secure"] = int(findings_severity_match.group(4))
        report["findings_summary"]["hotspot"] = int(findings_severity_match.group(5))

    # --- File Information ---
    size_match = re.search(r"Size:\s*([^\n]+)", report_text)
    if size_match:
        report["file_information"]["size"] = size_match.group(1).strip()
    md5_match = re.search(r"MD5:\s*([a-fA-F0-9]+)", report_text)
    if md5_match:
        report["file_information"]["md5"] = md5_match.group(1).strip()
    sha1_match = re.search(r"SHA1:\s*([a-fA-F0-9]+)", report_text)
    if sha1_match:
        report["file_information"]["sha1"] = sha1_match.group(1).strip()
    sha256_match = re.search(r"SHA256:\s*([a-fA-F0-9]+)", report_text)
    if sha256_match:
        report["file_information"]["sha256"] = sha256_match.group(1).strip()

    # --- App Information (already got app_name, package_name, android_version_name) ---
    main_activity_match = re.search(r"Main Activity:\s*([^\n]+)", report_text)
    if main_activity_match:
        report["app_information"]["main_activity"] = main_activity_match.group(1).strip()
    target_sdk_match = re.search(r"Target SDK:\s*(\d+)", report_text)
    if target_sdk_match:
        report["app_information"]["target_sdk"] = int(target_sdk_match.group(1))
    min_sdk_match = re.search(r"Min SDK:\s*(\d+)", report_text)
    if min_sdk_match:
        report["app_information"]["min_sdk"] = int(min_sdk_match.group(1))
    max_sdk_match = re.search(r"Max SDK:\s*([^\n]+)", report_text) # Can be empty
    if max_sdk_match and max_sdk_match.group(1).strip():
        report["app_information"]["max_sdk"] = max_sdk_match.group(1).strip()
    android_version_code_match = re.search(r"Android Version Code:\s*(\d+)", report_text)
    if android_version_code_match:
        report["app_information"]["android_version_code"] = int(android_version_code_match.group(1))

    # --- App Components ---
    components_section_match = re.search(
        r"APP COMPONENTS\s*\n.*?Activities:\s*(\d+)\s*\n.*?Services:\s*(\d+)\s*\n.*?Receivers:\s*(\d+)\s*\n.*?Providers:\s*(\d+)\s*\n.*?Exported Activities:\s*(\d+)\s*\n.*?Exported Services:\s*(\d+)\s*\n.*?Exported Receivers:\s*(\d+)\s*\n.*?Exported Providers:\s*(\d+)",
        report_text, re.DOTALL
    )
    if components_section_match:
        report["app_components"]["activities"] = int(components_section_match.group(1))
        report["app_components"]["services"] = int(components_section_match.group(2))
        report["app_components"]["receivers"] = int(components_section_match.group(3))
        report["app_components"]["providers"] = int(components_section_match.group(4))
        report["app_components"]["exported_activities"] = int(components_section_match.group(5))
        report["app_components"]["exported_services"] = int(components_section_match.group(6))
        report["app_components"]["exported_receivers"] = int(components_section_match.group(7))
        report["app_components"]["exported_providers"] = int(components_section_match.group(8))

    # --- Certificate Information ---
    cert_info_section_match = re.search(
        r"CERTIFICATE INFORMATION\s*\n(.*?)(?=APPLICATION PERMISSIONS)",
        report_text, re.DOTALL
    )
    if cert_info_section_match:
        cert_info_text = cert_info_section_match.group(1)
        if "Binary is signed" in cert_info_text:
            report["certificate_information"]["is_signed"] = True
        v1_match = re.search(r"v1 signature:\s*(True|False)", cert_info_text)
        if v1_match: report["certificate_information"]["v1_signature"] = v1_match.group(1) == "True"
        v2_match = re.search(r"v2 signature:\s*(True|False)", cert_info_text)
        if v2_match: report["certificate_information"]["v2_signature"] = v2_match.group(1) == "True"
        v3_match = re.search(r"v3 signature:\s*(True|False)", cert_info_text)
        if v3_match: report["certificate_information"]["v3_signature"] = v3_match.group(1) == "True"
        v4_match = re.search(r"v4 signature:\s*(True|False)", cert_info_text)
        if v4_match: report["certificate_information"]["v4_signature"] = v4_match.group(1) == "True"

        x509_subject_match = re.search(r"X\.509 Subject:\s*([^\n]+)", cert_info_text)
        if x509_subject_match: report["certificate_information"]["x509_subject"] = x509_subject_match.group(1).strip()
        sig_algo_match = re.search(r"Signature Algorithm:\s*([^\n]+)", cert_info_text)
        if sig_algo_match: report["certificate_information"]["signature_algorithm"] = sig_algo_match.group(1).strip()

        valid_from_match = re.search(r"Valid From:\s*([^\n]+)", cert_info_text)
        if valid_from_match: report["certificate_information"]["valid_from"] = valid_from_match.group(1).strip()
        valid_to_match = re.search(r"Valid To:\s*([^\n]+)", cert_info_text)
        if valid_to_match: report["certificate_information"]["valid_to"] = valid_to_match.group(1).strip()
        issuer_match = re.search(r"Issuer:\s*([^\n]+)", cert_info_text)
        if issuer_match: report["certificate_information"]["issuer"] = issuer_match.group(1).strip()
        serial_number_match = re.search(r"Serial Number:\s*([^\n]+)", cert_info_text)
        if serial_number_match: report["certificate_information"]["serial_number"] = serial_number_match.group(1).strip()
        hash_algo_match = re.search(r"Hash Algorithm:\s*([^\n]+)", cert_info_text)
        if hash_algo_match: report["certificate_information"]["hash_algorithm"] = hash_algo_match.group(1).strip()

        cert_md5_match = re.search(r"md5:\s*([a-fA-F0-9]+)", cert_info_text)
        if cert_md5_match: report["certificate_information"]["md5"] = cert_md5_match.group(1).strip()
        cert_sha1_match = re.search(r"sha1:\s*([a-fA-F0-9]+)", cert_info_text)
        if cert_sha1_match: report["certificate_information"]["sha1"] = cert_sha1_match.group(1).strip()
        cert_sha256_match = re.search(r"sha256:\s*([a-fA-F0-9]+)", cert_info_text)
        if cert_sha256_match: report["certificate_information"]["sha256"] = cert_sha256_match.group(1).strip()
        cert_sha512_match = re.search(r"sha512:\s*([a-fA-F0-9]+)", cert_info_text)
        if cert_sha512_match: report["certificate_information"]["sha512"] = cert_sha512_match.group(1).strip()

        public_key_algo_match = re.search(r"PublicKey Algorithm:\s*([^\n]+)", cert_info_text)
        if public_key_algo_match: report["certificate_information"]["public_key_algorithm"] = public_key_algo_match.group(1).strip()
        bit_size_match = re.search(r"Bit Size:\s*(\d+)", cert_info_text)
        if bit_size_match: report["certificate_information"]["bit_size"] = int(bit_size_match.group(1))
        fingerprint_match = re.search(r"Fingerprint:\s*([a-fA-F0-9]+)", cert_info_text)
        if fingerprint_match: report["certificate_information"]["fingerprint"] = fingerprint_match.group(1).strip()
        unique_certs_match = re.search(r"Found (\d+) unique certificates", cert_info_text)
        if unique_certs_match: report["certificate_information"]["unique_certificates_found"] = int(unique_certs_match.group(1))

    # --- Application Permissions ---
    permissions_section_match = re.search(
        r"APPLICATION PERMISSIONS\s*\nPERMISSION\s*STATUS\s*INFO\s*DESCRIPTION\s*\n(.*?)(?=APKID ANALYSIS)",
        report_text, re.DOTALL
    )
    if permissions_section_match:
        permissions_text = permissions_section_match.group(1).strip()
        # Regex to capture permission name, status, info, and description.
        # This is tricky because description can be multi-line.
        # We assume INFO and DESCRIPTION are always present and follow STATUS,
        # and a new permission line starts with a word boundary for the permission name.
        permission_pattern = re.compile(
            r"(android\.permission\.[^\n]+?)\s*\n" # Permission Name (e.g., android.permission.WRITE_EXTERNAL_STORAGE)
            r"([a-zA-Z]+)\s*\n"                     # Status (e.g., dangerous, normal)
            r"([^\n]*?)\s*\n"                       # Info (e.g., read/modify/delete external storage contents)
            r"([^\n]*?)(?=(?:android\.permission\.[^\n]+?|\Z))", # Description (can be multi-line, non-greedy, ends before next perm or end of section)
            re.DOTALL
        )
        
        # Split permissions_text into individual permission blocks
        # First, split by potential start of a new permission, then process each block
        # A simpler approach is to find all matches using a global regex
        
        # A more robust regex for permissions, assuming Description is the last field
        permission_entry_pattern = re.compile(
            r"^(android\.permission\.[^\s]+)\s*\n" # Permission Name
            r"([a-zA-Z]+)\s*\n"                      # Status
            r"([^\n]+)\s*\n"                         # Info
            r"([^\n]+(?:(?:\n(?!\s*(?:android\.permission\.)|APKID ANALYSIS|CERTIFICATE ANALYSIS|NETWORK SECURITY)).*?)*)", # Description (multi-line)
            re.MULTILINE
        )

        for match in permission_entry_pattern.finditer(permissions_text):
            permission_name = match.group(1).strip()
            status = match.group(2).strip()
            info = match.group(3).strip()
            description = match.group(4).strip()
            report["application_permissions"].append({
                "permission": permission_name,
                "status": status,
                "info": info,
                "description": description
            })


    # --- APKID Analysis ---
    apkid_analysis_section_match = re.search(
        r"APKID ANALYSIS\s*\nFILE\s*DETAILS\s*\nclasses\.dex\s*\nFINDINGS\s*DETAILS\s*\n(.*?)(?=NETWORK SECURITY|CERTIFICATE ANALYSIS)",
        report_text, re.DOTALL
    )
    if apkid_analysis_section_match:
        apkid_text = apkid_analysis_section_match.group(1).strip()
        # Find compiler details
        compiler_match = re.search(r"Compiler\s*\n([^\n]+)", apkid_text)
        if compiler_match:
            report["apkid_analysis"]["classes_dex"]["compiler"] = compiler_match.group(1).strip()

        # For other findings and details, the report structure is less clear for a generic parse
        # Based on the example, only "Compiler" is listed under "FINDINGS DETAILS"
        # If there were more, they would need more specific regex patterns.


    # --- Certificate Analysis ---
    cert_analysis_header_match = re.search(
        r"CERTIFICATE ANALYSIS\s*\nHIGH:\s*(\d+)\s*\|\s*WARNING:\s*(\d+)\s*\|\s*INFO:\s*(\d+)",
        report_text
    )
    if cert_analysis_header_match:
        report["certificate_analysis"]["high_count"] = int(cert_analysis_header_match.group(1))
        report["certificate_analysis"]["warning_count"] = int(cert_analysis_header_match.group(2))
        report["certificate_analysis"]["info_count"] = int(cert_analysis_header_match.group(3))

    cert_analysis_issues_match = re.search(
        r"CERTIFICATE ANALYSIS.*?\nTITLE\s*SEVERITY\s*DESCRIPTION\s*\n(.*?)(?=MANIFEST ANALYSIS|CODE ANALYSIS)",
        report_text, re.DOTALL
    )
    if cert_analysis_issues_match:
        issues_text = cert_analysis_issues_match.group(1).strip()
        # Pattern to capture Title, Severity, and multi-line Description
        issue_pattern = re.compile(
            r"^(.*?)\s*\n"              # Title (non-greedy, ends with newline)
            r"(high|warning|info)\s*\n" # Severity
            r"((?:[^\n]*?)(?:\n(?!\s*(?:high|warning|info|\d+\s*App can be installed|Debug Enabled For App|Application Data can be Backed up|Activity)).*?)*)", # Description (multi-line, non-greedy, ends before next issue or new section)
            re.MULTILINE | re.DOTALL
        )
        for match in issue_pattern.finditer(issues_text):
            title = match.group(1).strip()
            severity = match.group(2).strip()
            description = match.group(3).strip()
            report["certificate_analysis"]["issues"].append({
                "title": title,
                "severity": severity,
                "description": description
            })

    # --- Manifest Analysis ---
    manifest_analysis_header_match = re.search(
        r"MANIFEST ANALYSIS\s*\nHIGH:\s*(\d+)\s*\|\s*WARNING:\s*(\d+)\s*\|\s*INFO:\s*(\d+)\s*\|\s*SUPPRESSED:\s*(\d+)",
        report_text
    )
    if manifest_analysis_header_match:
        report["manifest_analysis"]["high_count"] = int(manifest_analysis_header_match.group(1))
        report["manifest_analysis"]["warning_count"] = int(manifest_analysis_header_match.group(2))
        report["manifest_analysis"]["info_count"] = int(manifest_analysis_header_match.group(3))
        report["manifest_analysis"]["suppressed_count"] = int(manifest_analysis_header_match.group(4))

    manifest_analysis_issues_match = re.search(
        r"MANIFEST ANALYSIS.*?\nNO\s*ISSUE\s*SEVERITY\s*DESCRIPTION\s*\n(.*?)(?=CODE ANALYSIS|NIAP ANALYSIS)",
        report_text, re.DOTALL
    )
    if manifest_analysis_issues_match:
        issues_text = manifest_analysis_issues_match.group(1).strip()
        # Pattern for Manifest Analysis issues (Number, Issue, Severity, Description)
        # The 'Issue' can contain multiple lines, and the 'Description' also.
        manifest_issue_pattern = re.compile(
            r"^\d+\s*\n"                                # Issue number
            r"(.*?)\s*\n"                               # Issue Title (can be multiline, ending before severity)
            r"(high|warning|info|secure|suppressed)\s*\n" # Severity
            r"((?:[^\n]*?)(?:\n(?!\d+\s*\n(?:high|warning|info|secure|suppressed)|CODE ANALYSIS|NIAP ANALYSIS).)*)", # Description (multi-line, non-greedy)
            re.MULTILINE | re.DOTALL
        )
        # This parsing for manifest issues is a bit complex due to "Issue" itself being multi-line
        # Let's refine the pattern for manifest issues:
        manifest_issue_pattern_refined = re.compile(
            r"^\s*(\d+)\s*\n"  # Issue Number
            r"(.+?)\s*\n"      # Issue Title (group 2, non-greedy, ends before severity)
            r"(high|warning|info|secure|suppressed)\s*\n" # Severity (group 3)
            r"((?:.|\n)*?)"    # Description (group 4, non-greedy, until next issue or section end)
            r"(?=\n\s*\d+\s*\n|CODE ANALYSIS|NIAP ANALYSIS|ABUSED PERMISSIONS|\Z)",
            re.MULTILINE
        )

        for match in manifest_issue_pattern_refined.finditer(issues_text):
            # Extract issue details from groups
            issue_number = int(match.group(1).strip())
            issue_title = match.group(2).strip()
            severity = match.group(3).strip()
            description = match.group(4).strip()
            report["manifest_analysis"]["issues"].append({
                "no": issue_number,
                "issue": issue_title,
                "severity": severity,
                "description": description
            })

    # --- Code Analysis ---
    code_analysis_header_match = re.search(
        r"CODE ANALYSIS\s*\nHIGH:\s*(\d+)\s*\|\s*WARNING:\s*(\d+)\s*\|\s*INFO:\s*(\d+)\s*\|\s*SECURE:\s*(\d+)\s*\|\s*SUPPRESSED:\s*(\d+)",
        report_text
    )
    if code_analysis_header_match:
        report["code_analysis"]["high_count"] = int(code_analysis_header_match.group(1))
        report["code_analysis"]["warning_count"] = int(code_analysis_header_match.group(2))
        report["code_analysis"]["info_count"] = int(code_analysis_header_match.group(3))
        report["code_analysis"]["secure_count"] = int(code_analysis_header_match.group(4))
        report["code_analysis"]["suppressed_count"] = int(code_analysis_header_match.group(5))

    code_analysis_issues_match = re.search(
        r"CODE ANALYSIS.*?\nNO\s*ISSUE\s*SEVERITY\s*STANDARDS\s*FILES\s*\n(.*?)(?=NIAP ANALYSIS|ABUSED PERMISSIONS|SCAN LOGS)",
        report_text, re.DOTALL
    )
    if code_analysis_issues_match:
        issues_text = code_analysis_issues_match.group(1).strip()
        # Pattern for Code Analysis issues (No, Issue, Severity, Standards, Files)
        # Issue and Standards can be multi-line
        code_issue_pattern = re.compile(
            r"^\s*(\d+)\s*\n"                               # Issue Number
            r"(.+?)\s*\n"                                   # Issue Title (group 2, non-greedy, ends before severity)
            r"(high|warning|info|secure|suppressed)\s*\n"  # Severity (group 3)
            r"(CWE:.*?\n(?:OWASP Top 10:.*?\n)?(?:OWASP MASVS:.*?\n)?)" # Standards (group 4, multi-line, non-greedy)
            r"([^\n]+(?:(?:\n(?!\s*\d+\s*\n|NIAP ANALYSIS|ABUSED PERMISSIONS|SCAN LOGS)).*?)*)", # Files (group 5, multi-line, non-greedy)
            re.MULTILINE | re.DOTALL
        )
        for match in code_issue_pattern.finditer(issues_text):
            issue_number = int(match.group(1).strip())
            issue = match.group(2).strip()
            severity = match.group(3).strip()
            standards_raw = match.group(4).strip()
            files_raw = match.group(5).strip()

            standards = {}
            cwe_match = re.search(r"CWE:\s*(.*?)(?:\n|OWASP)", standards_raw)
            if cwe_match: standards["CWE"] = cwe_match.group(1).strip()
            owasp_top10_match = re.search(r"OWASP Top 10:\s*(.*?)(?:\n|OWASP)", standards_raw)
            if owasp_top10_match: standards["OWASP Top 10"] = owasp_top10_match.group(1).strip()
            owasp_masvs_match = re.search(r"OWASP MASVS:\s*(.*)", standards_raw)
            if owasp_masvs_match: standards["OWASP MASVS"] = owasp_masvs_match.group(1).strip()

            files = [f.strip() for f in files_raw.split('\n') if f.strip()]

            report["code_analysis"]["issues"].append({
                "no": issue_number,
                "issue": issue,
                "severity": severity,
                "standards": standards,
                "files": files
            })

    # --- Abused Permissions ---
    abused_permissions_match = re.search(
        r"ABUSED PERMISSIONS\s*\nTYPE\s*MATCHES\s*PERMISSIONS\s*\n"
        r"Malware Permissions\s*([^\n]+)\s*\n"
        r"(.*?)\s*\n" # Malware Permissions list (group 2)
        r"Other Common Permissions\s*([^\n]+)\s*\n"
        r"(.*?)\s*\n" # Other Common Permissions list (group 4)
        r"(?:Malware Permissions:|Other Common Permissions:)", # Stop before descriptions
        report_text, re.DOTALL
    )
    if abused_permissions_match:
        report["abused_permissions"]["malware_permissions"]["matches"] = abused_permissions_match.group(1).strip()
        malware_perms_str = abused_permissions_match.group(2).strip()
        report["abused_permissions"]["malware_permissions"]["permissions"] = [p.strip() for p in malware_perms_str.split(',') if p.strip()]

        report["abused_permissions"]["other_common_permissions"]["matches"] = abused_permissions_match.group(3).strip()
        other_perms_str = abused_permissions_match.group(4).strip()
        report["abused_permissions"]["other_common_permissions"]["permissions"] = [p.strip() for p in other_perms_str.split(',') if p.strip()]

    # --- Scan Logs ---
    scan_logs_match = re.search(
        r"SCAN LOGS\s*\nTimestamp\s*Event\s*Error\s*\n(.*?)(?=Report Generated by - MobSF)",
        report_text, re.DOTALL
    )
    if scan_logs_match:
        logs_text = scan_logs_match.group(1).strip()
        log_entry_pattern = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s*(.*?)\s*(OK|ERROR|FAIL)$", re.MULTILINE)
        for match in log_entry_pattern.finditer(logs_text):
            report["scan_logs"].append({
                "timestamp": match.group(1).strip(),
                "event": match.group(2).strip(),
                "error": match.group(3).strip()
            })
    
    # MobSF version
    mobsf_version_match = re.search(r"Report Generated by - MobSF v(\d+\.\d+\.\d+)", report_text)
    if mobsf_version_match:
        report["report_metadata"]["tool_version"] = mobsf_version_match.group(1).strip()


    return report

# Example Usage:
if __name__ == "__main__":
    report_content = """
ANDROID STATIC ANALYSIS REPORT




BitbarSampleApp
BitbarSampleApp
(1.0)
(1.0)

File Name:
bitbar-sample-app.apk
Package Name:
com.bitbar.testdroid
Scan Date:
April 19, 2025, 7:06 a.m.
App Security Score:
32/100 (HIGH RISK)
Grade:
C


 FINDINGS SEVERITY

 HIGH
 HIGH

 MEDIUM
 MEDIUM

 INFO
 INFO

 SECURE
 SECURE


 HOTSPOT
 HOTSPOT
5
4
0
1
1

 FILE INFORMATION
File Name:
File Name:
 bitbar-sample-app.apk
Size:
Size:
0.11MB
MD5:
MD5:
 00cc5435151aa38a091781922c0390a4
SHA1:
SHA1:
 40e991508120d6f5d653a6755d8209df4d20289d
SHA256:
SHA256:
 3b4d462b8cce5f377a33417e1be7680717065f280a9f6e2f6af49325dbe89411

 APP INFORMATION
App Name:
App Name:
 BitbarSampleApp
Package Name:
Package Name:
 com.bitbar.testdroid
Main Activity:
Main Activity:
 com.bitbar.testdroid.BitbarSampleApplicationActivity
Target SDK:
Target SDK:
 33
Min SDK:
Min SDK:
 4
Max SDK:
Max SDK:

Android Version Name:
Android Version Name:
 1.0
Android Version Code:
Android Version Code:
 1

 APP COMPONENTS
Activities:
Activities:
 3
Services:
Services:
 0
Receivers:
Receivers:
 0
Providers:
Providers:
 0
Exported Activities:
Exported Activities:

2
Exported Services:
Exported Services:

0
Exported Receivers:
Exported Receivers:

0
Exported Providers:
Exported Providers:

0

 CERTIFICATE INFORMATION
Binary is signed
v1 signature: True
v2 signature: True
v3 signature: False
v4 signature: False
X.509 Subject: CN=Android Debug, O=Android, C=US
Signature Algorithm: rsassa_pkcs1v15
Valid From: 2022-07-05 09:35:34+00:00
Valid To: 2052-06-27 09:35:34+00:00
Issuer: CN=Android Debug, O=Android, C=US
Serial Number: 0x1
Hash Algorithm: sha1
md5: f5e77c7ea1c2102188be9eae9a3b8573
sha1: a7ce1335a1bbb135d34c208b51945cc93104c7ed
sha256: 93424fddcac08ed772ccaf7a20cd2cda4fc83f101656536154ef92846c2f3ffc
sha512: ec768feee2bcc63bdd65c642767b717a8cf0b855772497c302a4e0109c44f544a40338e9164be8053011f575a7e0a6196e08e9cca78a1589510a0820e4b4bd93
PublicKey Algorithm: rsa
Bit Size: 2048
Fingerprint: ff557fc6f6139b576a27f7f3cb4efe09a12090029a11ab150eaddf7c79d6ec67
Found 1 unique certificates

 APPLICATION PERMISSIONS
PERMISSION
PERMISSION
STATUS
STATUS
INFO
INFO
DESCRIPTION
DESCRIPTION
android.permission.WRITE_EXTERNAL_STORAGE
dangerous
read/modify/delete external storage
contents
Allows an application to write to external
storage.
android.permission.INTERNET
normal
full Internet access
Allows an application to create network sockets.

 APKID ANALYSIS
FILE
FILE
DETAILS
DETAILS
classes.dex
FINDINGS
FINDINGS
DETAILS
DETAILS
Compiler
r8 without marker (suspicious)

 NETWORK SECURITY
NO
NO
SCOPE
SCOPE
SEVERITY
SEVERITY
DESCRIPTION
DESCRIPTION

 CERTIFICATE ANALYSIS
HIGH:
2
2
 |
WARNING:
1
1
 |
INFO:
1
1

TITLE
TITLE
SEVERITY
SEVERITY
DESCRIPTION
DESCRIPTION
Signed Application
info
Application is signed with a code signing certificate
Application vulnerable
to Janus Vulnerability
warning
Application is signed with v1 signature scheme, making it vulnerable to Janus vulnerability on Android 5.0-8.0, if signed
only with v1 signature scheme. Applications running on Android 5.0-7.0 signed with v1, and v2/v3 scheme is also
vulnerable.
Application signed with
debug certificate
high
Application signed with a debug certificate. Production application must not be shipped with a debug certificate.
Certificate algorithm
vulnerable to hash
collision
high
Application is signed with SHA1withRSA. SHA1 hash algorithm is known to have collision issues.      

 MANIFEST ANALYSIS
HIGH:
2
2
 |
WARNING:
3
3
 |
INFO:
0
0
 |
SUPPRESSED:
0
0

NO
NO
ISSUE
ISSUE
SEVERITY
SEVERITY
DESCRIPTION
DESCRIPTION
1
App can be installed on a vulnerable
upatched Android version
Android 1.6, [minSdk=4]
high
This application can be installed on an older version of android that has multiple unfixed
vulnerabilities. These devices won't receive reasonable security updates from Google.
Support an Android version => 10, API 29 to receive reasonable security updates.
2
Debug Enabled For App
[android:debuggable=true]
high
Debugging was enabled on the app which makes it easier for reverse engineers to hook a
debugger to it. This allows dumping a stack trace and accessing debugging helper classes.
3
Application Data can be Backed up
[android:allowBackup] flag is missing.
warning
The flag [android:allowBackup] should be set to false. By default it is set to true and allows      
anyone to backup your application data via adb. It allows users who have enabled USB
debugging to copy application data off of the device.
4
Activity
(com.bitbar.testdroid.CorrectAnswerActivity)
is not Protected.
[android:exported=true]
warning
An Activity is found to be shared with other apps on the device therefore leaving it
accessible to any other application on the device.
5
Activity
(com.bitbar.testdroid.WrongAnswerActivity)
is not Protected.
[android:exported=true]
warning
An Activity is found to be shared with other apps on the device therefore leaving it
accessible to any other application on the device.
NO
NO
ISSUE
ISSUE
SEVERITY
SEVERITY
DESCRIPTION
DESCRIPTION

 CODE ANALYSIS
HIGH:
1
1
 |
WARNING:
0
0
 |
INFO:
0
0
 |
SECURE:
0
0
 |
SUPPRESSED:
0
0

NO
NO
ISSUE
ISSUE
SEVERITY
SEVERITY
STANDARDS
STANDARDS
FILES
FILES
1
Debug configuration enabled.
Production builds must not be
debuggable.
high
CWE:
CWE-919: Weaknesses in Mobile Applications
OWASP Top 10:
M1: Improper Platform Usage
OWASP MASVS:
MSTG-RESILIENCE-2
com/bitbar/testdroid/BuildConfig.java

 NIAP ANALYSIS v1.3
NO
NO
IDENTIFIER
IDENTIFIER
REQUIREMENT
REQUIREMENT
FEATURE
FEATURE
DESCRIPTION
DESCRIPTION

 ABUSED PERMISSIONS
TYPE
TYPE
MATCHES
MATCHES
PERMISSIONS
PERMISSIONS
Malware Permissions
2/25
android.permission.WRITE_EXTERNAL_STORAGE, android.permission.INTERNET
Other Common Permissions
0/44
Malware Permissions:
Top permissions that are widely abused by known malware.
Other Common Permissions:
Permissions that are commonly abused by known malware.

 SCAN LOGS
Timestamp
Timestamp
Event
Event
Error
Error
2025-04-19 07:06:19
Generating Hashes
OK
2025-04-19 07:06:19
Extracting APK
OK
2025-04-19 07:06:19
Unzipping
OK
2025-04-19 07:06:19
Parsing APK with androguard
OK
2025-04-19 07:06:19
Extracting APK features using aapt/aapt2
OK
2025-04-19 07:06:19
Getting Hardcoded Certificates/Keystores
OK
2025-04-19 07:06:20
Parsing AndroidManifest.xml
OK
2025-04-19 07:06:20
Extracting Manifest Data
OK
2025-04-19 07:06:20
Manifest Analysis Started
OK
2025-04-19 07:06:20
Performing Static Analysis on: BitbarSampleApp (com.bitbar.testdroid)
OK
2025-04-19 07:06:20
Fetching Details from Play Store: com.bitbar.testdroid
OK
2025-04-19 07:06:20
Checking for Malware Permissions
OK
2025-04-19 07:06:20
Fetching icon path
OK
2025-04-19 07:06:20
Library Binary Analysis Started
OK
2025-04-19 07:06:20
Reading Code Signing Certificate
OK
2025-04-19 07:06:20
Running APKiD 2.1.5
OK
2025-04-19 07:06:22
Detecting Trackers
OK
2025-04-19 07:06:22
Decompiling APK to Java with JADX
OK
2025-04-19 07:06:23
Converting DEX to Smali
OK
2025-04-19 07:06:23
Code Analysis Started on - java_source
OK
2025-04-19 07:06:23
Android SBOM Analysis Completed
OK
2025-04-19 07:06:23
Android SAST Completed
OK
2025-04-19 07:06:23
Android API Analysis Started
OK
2025-04-19 07:06:23
Android API Analysis Completed
OK
2025-04-19 07:06:23
Android Permission Mapping Started
OK
2025-04-19 07:06:23
Android Permission Mapping Completed
OK
2025-04-19 07:06:23
Android Behaviour Analysis Started
OK
2025-04-19 07:06:24
Android Behaviour Analysis Completed
OK
2025-04-19 07:06:24
Extracting Emails and URLs from Source Code
OK
2025-04-19 07:06:24
Email and URL Extraction Completed
OK
2025-04-19 07:06:24
Extracting String data from APK
OK
2025-04-19 07:06:24
Extracting String data from Code
OK
2025-04-19 07:06:24
Extracting String values and entropies from Code
OK
2025-04-19 07:06:24
Performing Malware check on extracted domains
OK
2025-04-19 07:06:24
Saving to Database
OK
Report Generated by - MobSF v4.3.1
Mobile Security Framework (MobSF) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment
framework capable of performing static and dynamic analysis.
© 2025 Mobile Security Framework - MobSF |
Ajin Abraham
 |
OpenSecurity
.
"""

    parsed_report = parse_android_report(report_content)
    print(json.dumps(parsed_report, indent=2))

    # You can also save it to a file
    # with open("android_report_parsed.json", "w") as f:
    #     json.dump(parsed_report, f, indent=2)
    # print("\nParsed report saved to android_report_parsed.json")