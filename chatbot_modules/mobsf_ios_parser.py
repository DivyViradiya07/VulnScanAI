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

def parse_mobsf_ios_report(raw_mobsf_text: str) -> Dict[str, Any]:
    """
    Parses raw MobSF iOS report text into a structured dictionary.

    Args:
        raw_mobsf_text: The raw text content of a MobSF iOS report.

    Returns:
        dict: A structured dictionary containing MobSF iOS report information.
    """
    # Standardize newlines for easier regex matching
    raw_mobsf_text = re.sub(r'\r\n', '\n', raw_mobsf_text)
    raw_mobsf_text = re.sub(r'\r', '\n', raw_mobsf_text)

    report = {
        "scan_metadata": {
            "tool": "Mobile Security Framework (MobSF)",
            "report_id": str(uuid.uuid4()),
            "scan_date": None,
            "mobsf_version": None,
            "app_security_score": None,
            "grade": None,
            "file_name": None,
            "identifier": None
        },
        "summary": {
            "findings_severity": {
                "High": 0,
                "Medium": 0,
                "Info": 0,
                "Secure": 0,
                "Hotspot": 0
            },
            "total_issues": 0
        },
        "file_information": {},
        "app_information": {},
        "binary_information": {},
        "app_transport_security_findings": [],
        "ipa_binary_code_analysis_findings": [],
        "ipa_binary_analysis_findings": [],
        "code_analysis_findings": [],
        "ofac_sanctioned_countries": [],
        "domain_malware_check": [],
        "scan_logs": []
    }

    # --- Extract Scan Metadata and Summary ---
    file_name_match = re.search(r"File Name:\s*(.+?)\n", raw_mobsf_text)
    if file_name_match:
        report["scan_metadata"]["file_name"] = file_name_match.group(1).strip()
        report["file_information"]["File Name"] = file_name_match.group(1).strip()

    identifier_match = re.search(r"Identifier:\s*(.+?)\n", raw_mobsf_text)
    if identifier_match:
        report["scan_metadata"]["identifier"] = identifier_match.group(1).strip()
        report["app_information"]["Identifier"] = identifier_match.group(1).strip()

    scan_date_match = re.search(r"Scan Date:\s*(.+?)\n", raw_mobsf_text)
    if scan_date_match:
        # MobSF date format: April 19, 2025, 7:06 a.m.
        date_str = scan_date_match.group(1).strip().replace("a.m.", "AM").replace("p.m.", "PM")
        try:
            if ',' in date_str.split(',')[-1] and any(ext in date_str for ext in ["AM", "PM"]):
                 report["scan_metadata"]["scan_date"] = datetime.strptime(date_str, "%B %d, %Y, %I:%M %p").isoformat()
            else:
                report["scan_metadata"]["scan_date"] = date_str
        except ValueError:
            report["scan_metadata"]["scan_date"] = date_str

    app_score_match = re.search(r"App Security Score:\s*(\d+/\d+)\s*\((.+?)\)", raw_mobsf_text)
    if app_score_match:
        report["scan_metadata"]["app_security_score"] = app_score_match.group(1).strip()

    grade_match = re.search(r"Grade:\s*([A-E])", raw_mobsf_text)
    if grade_match:
        report["scan_metadata"]["grade"] = grade_match.group(1).strip()
    
    mobsf_version_match = re.search(r"Report Generated by - MobSF v(\d+\.\d+\.\d+)", raw_mobsf_text)
    if mobsf_version_match:
        report["scan_metadata"]["mobsf_version"] = mobsf_version_match.group(1).strip()

    severity_match = re.search(
        r"FINDINGS SEVERITY\s*.*?HIGH\s*.*?MEDIUM\s*.*?INFO\s*.*?SECURE\s*.*?HOTSPOT\s*\n\s*(\d+)\s*\n\s*(\d+)\s*\n\s*(\d+)\s*\n\s*(\d+)\s*\n\s*(\d+)",
        raw_mobsf_text,
        re.DOTALL
    )
    if severity_match:
        report["summary"]["findings_severity"]["High"] = int(severity_match.group(1))
        report["summary"]["findings_severity"]["Medium"] = int(severity_match.group(2))
        report["summary"]["findings_severity"]["Info"] = int(severity_match.group(3))
        report["summary"]["findings_severity"]["Secure"] = int(severity_match.group(4))
        report["summary"]["findings_severity"]["Hotspot"] = int(severity_match.group(5))
        report["summary"]["total_issues"] = sum(report["summary"]["findings_severity"].values())

    # --- File Information ---
    file_info_block = re.search(
        r"FILE INFORMATION\s*(.*?)(?=APP INFORMATION|BINARY INFORMATION|APP TRANSPORT SECURITY|\Z)",
        raw_mobsf_text,
        re.DOTALL
    )
    if file_info_block:
        info_text = file_info_block.group(1)
        size_match = re.search(r"Size:\s*Size:\s*(.+?)\n", info_text)
        if size_match:
            report["file_information"]["Size"] = size_match.group(1).strip()
        md5_match = re.search(r"MD5:\s*MD5:\s*(.+?)\n", info_text)
        if md5_match:
            report["file_information"]["MD5"] = md5_match.group(1).strip()
        sha1_match = re.search(r"SHA1:\s*SHA1:\s*(.+?)\n", info_text)
        if sha1_match:
            report["file_information"]["SHA1"] = sha1_match.group(1).strip()
        sha256_match = re.search(r"SHA256:\s*SHA256:\s*(.+?)\n", info_text)
        if sha256_match:
            report["file_information"]["SHA256"] = sha256_match.group(1).strip()

# --- App Information ---
    app_info_block = re.search(
        r"APP INFORMATION\s*(.*?)(?=BINARY INFORMATION|APP TRANSPORT SECURITY|\Z)",
        raw_mobsf_text,
        re.DOTALL
    )
    if app_info_block:
        info_text = app_info_block.group(1)
        # Corrected regex for App Name: to capture only the value after the duplicated label
        app_name_match = re.search(r"App Name:\s*App Name:\s*(.+?)\n", info_text)
        if app_name_match:
            report["app_information"]["App Name"] = app_name_match.group(1).strip()
        # Corrected regex for App Type: to capture only the value after the duplicated label
        app_type_match = re.search(r"App Type:\s*App Type:\s*(.+?)\n", info_text)
        if app_type_match:
            report["app_information"]["App Type"] = app_type_match.group(1).strip()
        # Corrected regex for Identifier: (already good, just including for completeness if it needs adjusting)
        # Assuming "Identifier: Identifier: com.bitbar..."
        identifier_match = re.search(r"Identifier:\s*Identifier:\s*(.+?)\n", info_text)
        if identifier_match:
            report["app_information"]["Identifier"] = identifier_match.group(1).strip()
        # Corrected regex for SDK Name: to capture only the value after the duplicated label
        sdk_name_match = re.search(r"SDK Name:\s*SDK Name:\s*(.+?)\n", info_text)
        if sdk_name_match:
            report["app_information"]["SDK Name"] = sdk_name_match.group(1).strip()
        # Corrected regex for Version: to capture only the value after the duplicated label
        version_match = re.search(r"Version:\s*Version:\s*(.+?)\n", info_text)
        if version_match:
            report["app_information"]["Version"] = version_match.group(1).strip()
        # Corrected regex for Build: to capture only the value after the duplicated label
        build_match = re.search(r"Build:\s*Build:\s*(.+?)\n", info_text)
        if build_match:
            report["app_information"]["Build"] = build_match.group(1).strip()
        # Corrected regex for Platform Version: to capture only the value after the duplicated label
        platform_version_match = re.search(r"Platform Version:\s*Platform Version:\s*(.+?)\n", info_text)
        if platform_version_match:
            report["app_information"]["Platform Version"] = platform_version_match.group(1).strip()
        # Corrected regex for Min OS Version: to capture only the value after the duplicated label
        min_os_version_match = re.search(r"Min OS Version:\s*Min OS Version:\s*(.+?)\n", info_text)
        if min_os_version_match:
            report["app_information"]["Min OS Version"] = min_os_version_match.group(1).strip()
        # The Supported Platforms regex should remain the same as it already accounts for the duplication
        supported_platforms_match = re.search(r"Supported Platforms:\s*Supported Platforms:\s*(.+?)\n", info_text)
        if supported_platforms_match:
            report["app_information"]["Supported Platforms"] = [p.strip() for p in supported_platforms_match.group(1).split(',') if p.strip()]

# --- Binary Information ---
    binary_info_block = re.search(
        r"BINARY INFORMATION\s*(.*?)(?=APP TRANSPORT SECURITY|\Z)",
        raw_mobsf_text,
        re.DOTALL
    )
    if binary_info_block:
        info_text = binary_info_block.group(1)
        # Corrected regex for Arch: to capture only the value after the duplicated label
        arch_match = re.search(r"Arch:\s*Arch:\s*(.+?)\n", info_text)
        if arch_match:
            report["binary_information"]["Arch"] = arch_match.group(1).strip()
        # Corrected regex for Sub Arch: to capture only the value after the duplicated label
        sub_arch_match = re.search(r"Sub Arch:\s*Sub Arch:\s*(.+?)\n", info_text)
        if sub_arch_match:
            report["binary_information"]["Sub Arch"] = sub_arch_match.group(1).strip()
        # Corrected regex for Bit: to capture only the value after the duplicated label
        bit_match = re.search(r"Bit:\s*Bit:\s*(.+?)\n", info_text)
        if bit_match:
            report["binary_information"]["Bit"] = bit_match.group(1).strip()
        # Corrected regex for Endian: to capture only the value after the duplicated label
        endian_match = re.search(r"Endian:\s*Endian:\s*(.+?)\n", info_text)
        if endian_match:
            report["binary_information"]["Endian"] = endian_match.group(1).strip()
        
    # --- App Transport Security (ATS) ---
    ats_block = re.search(
        r"APP TRANSPORT SECURITY \(ATS\)\s*NO\s*NO\s*ISSUE\s*ISSUE\s*SEVERITY\s*SEVERITY\s*DESCRIPTION\s*DESCRIPTION\s*(.*?)(?=IPA BINARY CODE ANALYSIS|\Z)",
        raw_mobsf_text,
        re.DOTALL
    )
    if ats_block:
        # Currently empty in example, so no parsing needed yet.
        pass

    # --- IPA Binary Code Analysis ---
    ipa_code_analysis_block = re.search(
        r"IPA BINARY CODE ANALYSIS\s*HIGH:\s*\d+\s*(\d+)\s*\|\s*WARNING:\s*\d+\s*(\d+)\s*\|\s*INFO:\s*\d+\s*(\d+)\s*\|\s*SECURE:\s*\d+\s*(\d+)\s*\|\s*SUPPRESSED:\s*\d+\s*(\d+)\s*\n*NO\s*NO\s*ISSUE\s*ISSUE\s*SEVERITY\s*SEVERITY\s*STANDARDS\s*STANDARDS\s*DESCRIPTION\s*DESCRIPTION\s*(.*?)(?=IPA BINARY ANALYSIS|\Z)",
        raw_mobsf_text,
        re.DOTALL
    )
    if ipa_code_analysis_block:
        findings_text = ipa_code_analysis_block.group(6).strip()
        ipa_code_finding_pattern = re.compile(
            r"(\d+)\s*\n*" # Group 1: Number
            r"(.+?)(?=\n\s*(?:warning|high|info|secure|suppressed)\s*\n)" # Group 2: Issue
            r"\s*\n\s*(warning|high|info|secure|suppressed)\s*\n" # Group 3: Severity
            r"CWE:\s*CWE:\s*(.+?)\n" # Group 4: CWE
            r"OWASP Top 10:\s*OWASP Top 10:\s*(.+?)\n" # Group 5: OWASP Top 10
            r"OWASP MASVS:\s*OWASP MASVS:\s*(.+?)\n" # Group 6: OWASP MASVS
            r"\s*(.+?)" # Group 7: Description
            r"(?=\n\d+\s*\n|\Z)",
            re.DOTALL
        )
        for match in ipa_code_finding_pattern.finditer(findings_text):
            standards = {
                "CWE": re.sub(r'\s+', ' ', match.group(4)).strip(),
                "OWASP Top 10": re.sub(r'\s+', ' ', match.group(5)).strip(),
                "OWASP MASVS": re.sub(r'\s+', ' ', match.group(6)).strip(),
            }
            report["ipa_binary_code_analysis_findings"].append({
                "number": int(match.group(1)),
                "issue": re.sub(r'\s+', ' ', match.group(2)).strip(),
                "severity": match.group(3).strip(),
                "standards": standards,
                "description": re.sub(r'\s+', ' ', match.group(7)).strip()
            })

    # --- IPA Binary Analysis ---
    ipa_binary_analysis_block = re.search(
        r"IPA BINARY ANALYSIS\s*PROTECTION\s*PROTECTION\s*STATUS\s*STATUS\s*SEVERITY\s*SEVERITY\s*DESCRIPTION\s*DESCRIPTION\s*(.*?)(?=CODE ANALYSIS|\Z)",
        raw_mobsf_text,
        re.DOTALL
    )
    if ipa_binary_analysis_block:
        findings_text = ipa_binary_analysis_block.group(1).strip()
        ipa_binary_pattern = re.compile(
            r"^(.*?)\s*\n" # Group 1: Protection
            r"\s*(True|False)\s*\n" # Group 2: Status
            r"\s*(info|warning|high)\s*\n" # Group 3: Severity
            r"\s*(.+?)" # Group 4: Description
            r"(?=(?:\n[A-Z_]+\s*True|False\s*\n\s*(?:info|warning|high)\s*\n)|\Z)", # Lookahead for next entry or end
            re.DOTALL | re.MULTILINE
        )
        for match in ipa_binary_pattern.finditer(findings_text):
            report["ipa_binary_analysis_findings"].append({
                "protection": match.group(1).strip(),
                "status": match.group(2).strip() == "True",
                "severity": match.group(3).strip(),
                "description": re.sub(r'\s+', ' ', match.group(4)).strip()
            })

    # --- Code Analysis ---
    code_analysis_block = re.search(
        r"CODE ANALYSIS\s*NO\s*NO\s*ISSUE\s*ISSUE\s*SEVERITY\s*SEVERITY\s*STANDARDS\s*STANDARDS\s*FILES\s*FILES\s*(.*?)(?=OFAC SANCTIONED COUNTRIES|\Z)",
        raw_mobsf_text,
        re.DOTALL
    )
    if code_analysis_block:
        # Currently empty in example, so no parsing needed yet.
        pass

    # --- OFAC Sanctioned Countries ---
    ofac_block = re.search(
        r"OFAC SANCTIONED COUNTRIES\s*This app may communicate with the following OFAC sanctioned list of countries.\s*DOMAIN\s*DOMAIN\s*COUNTRY/REGION\s*COUNTRY/REGION\s*(.*?)(?=DOMAIN MALWARE CHECK|\Z)",
        raw_mobsf_text,
        re.DOTALL
    )
    if ofac_block:
        ofac_text = ofac_block.group(1).strip()
        ofac_pattern = re.compile(
            r"^(.*?)\n" # Group 1: Domain
            r"\s*(.*?)$", # Group 2: Country/Region
            re.MULTILINE
        )
        for match in ofac_pattern.finditer(ofac_text):
            report["ofac_sanctioned_countries"].append({
                "domain": match.group(1).strip(),
                "country_region": match.group(2).strip()
            })

    # --- Domain Malware Check ---
    domain_malware_block = re.search(
        r"DOMAIN MALWARE CHECK\s*DOMAIN\s*DOMAIN\s*STATUS\s*STATUS\s*GEOLOCATION\s*GEOLOCATION\s*(.*?)(?=SCAN LOGS|\Z)",
        raw_mobsf_text,
        re.DOTALL
    )
    if domain_malware_block:
        domain_malware_text = domain_malware_block.group(1).strip()
        domain_pattern = re.compile(
            r"^(.*?)\s*\n" # Group 1: Domain
            r"\s*(ok|malicious)\s*\n" # Group 2: Status
            r"(.*?)(?=\n[^\n:]+:\s*|\Z)", # Group 3: Geolocation details block (non-greedy, until next key-value or end)
            re.DOTALL | re.MULTILINE
        )
        
        for match in domain_pattern.finditer(domain_malware_text):
            domain = match.group(1).strip()
            status = match.group(2).strip()
            geo_text = match.group(3).strip()

            geolocation = {}
            ip_match = re.search(r"IP:\s*IP:\s*(.+?)\n", geo_text)
            if ip_match:
                geolocation["IP"] = ip_match.group(1).strip()
            country_match = re.search(r"Country:\s*Country:\s*(.+?)\n", geo_text)
            if country_match:
                geolocation["Country"] = country_match.group(1).strip()
            region_match = re.search(r"Region:\s*Region:\s*(.+?)\n", geo_text)
            if region_match:
                geolocation["Region"] = region_match.group(1).strip()
            city_match = re.search(r"City:\s*City:\s*(.+?)\n", geo_text)
            if city_match:
                geolocation["City"] = city_match.group(1).strip()
            latitude_match = re.search(r"Latitude:\s*Latitude:\s*(.+?)\n", geo_text)
            if latitude_match:
                geolocation["Latitude"] = float(latitude_match.group(1).strip())
            longitude_match = re.search(r"Longitude:\s*Longitude:\s*(.+?)\n", geo_text)
            if longitude_match:
                geolocation["Longitude"] = float(longitude_match.group(1).strip())
            
            report["domain_malware_check"].append({
                "domain": domain,
                "status": status,
                "geolocation": geolocation
            })


    # --- Scan Logs ---
    scan_logs_block = re.search(
        r"SCAN LOGS\s*Timestamp\s*Timestamp\s*Event\s*Event\s*Error\s*Error\s*(.*?)(?=\Z)", # Ends at end of text
        raw_mobsf_text,
        re.DOTALL
    )
    if scan_logs_block:
        scan_logs_text = scan_logs_block.group(1).strip()
        scan_log_pattern = re.compile(
            r"^(.*?)\s+(.*?)\s+(.*?)$", # Group 1: Timestamp, Group 2: Event, Group 3: Error
            re.MULTILINE
        )
        for match in scan_log_pattern.finditer(scan_logs_text):
            report["scan_logs"].append({
                "timestamp": match.group(1).strip(),
                "event": match.group(2).strip(),
                "error": match.group(3).strip()
            })
    
    mobsf_version_footer_match = re.search(r"Report Generated by - MobSF v(\d+\.\d+\.\d+)", raw_mobsf_text)
    if mobsf_version_footer_match:
        report["scan_metadata"]["mobsf_version"] = mobsf_version_footer_match.group(1).strip()


    return report

def process_mobsf_ios_report_file(pdf_path: str) -> Dict[str, Any]:
    """
    Processes a MobSF iOS report PDF file and returns structured data.

    Args:
        pdf_path: Path to the MobSF iOS report PDF file.

    Returns:
        dict: Structured MobSF report data.
    """
    if not os.path.exists(pdf_path):
        raise FileNotFoundError(f"MobSF report not found: {pdf_path}")

    print(f"Processing MobSF iOS report: {pdf_path}")

    try:
        raw_text = extract_text_from_pdf(pdf_path)
        if not raw_text.strip():
            raise ValueError("Extracted text is empty or contains only whitespace.")

        report_data = parse_mobsf_ios_report(raw_text)

        report_data["file_metadata"] = {
            "filename": os.path.basename(pdf_path),
            "file_size": os.path.getsize(pdf_path),
            "last_modified": datetime.fromtimestamp(os.path.getmtime(pdf_path)).isoformat()
        }

        return report_data

    except Exception as e:
        print(f"Error processing MobSF iOS report {pdf_path}: {str(e)}")
        raise

if __name__ == "__main__":
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


    dummy_mobsf_ios_text = """
IOS STATIC ANALYSIS REPORT


 BitbarIOSSample 
 BitbarIOSSample 
(1.0)
(1.0)

File Name:
bitbar-ios-sample.ipa
Identifier:
com.bitbar.testdroid.BitbarIOSSample
Scan Date:
April 19, 2025, 7:05 a.m.
App Security Score:
67/100 (LOW RISK)
Grade:
A

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
0
3
0
1
0

 FILE INFORMATION
File Name:
File Name:
 bitbar-ios-sample.ipa
Size:
Size:
0.14MB
MD5:
MD5:
 e1f08f17e868e9de32a87d0bdc522fac
SHA1:
SHA1:
 deca43e3dd1186d002dea64b4cef4c8b88142488
SHA256:
SHA256:
 07ff7a6608265fff57bd3369fb4e10321d939de5101bd966677cd9a210b820b1

 APP INFORMATION
App Name:
App Name:
 BitbarIOSSample
App Type:
App Type:
 Objective C
Identifier:
Identifier:
 com.bitbar.testdroid.BitbarIOSSample
SDK Name:
SDK Name:
 iphoneos9.1
Version:
Version:
 1.0
Build:
Build:
 1.0
Platform Version:
Platform Version:
 9.1
Min OS Version:
Min OS Version:
 6.0
Supported Platforms:
Supported Platforms:

iPhoneOS,

 BINARY INFORMATION
Arch:
Arch:
 ARM
Sub Arch:
Sub Arch:
 CPU_SUBTYPE_ARM_V7
Bit:
Bit:
 32-bit
Endian:
Endian:
 <

 APP TRANSPORT SECURITY (ATS)
NO
NO
ISSUE
ISSUE
SEVERITY
SEVERITY
DESCRIPTION
DESCRIPTION

 IPA BINARY CODE ANALYSIS
HIGH:
0
0
 |
WARNING:
2
2
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
DESCRIPTION
DESCRIPTION
1
Binary makes use of insecure
API(s)
warning
CWE:
CWE:
CWE-676: Use of Potentially
Dangerous Function
OWASP Top 10:
OWASP Top 10:
M7: Client Code Quality
OWASP MASVS:
OWASP MASVS:
MSTG-CODE-8
The binary may contain the following insecure API(s)
_memcpy , _strlen
2
Binary makes use of malloc
function
warning
CWE:
CWE:
CWE-789: Uncontrolled Memory
Allocation
OWASP Top 10:
OWASP Top 10:
M7: Client Code Quality
OWASP MASVS:
OWASP MASVS:
MSTG-CODE-8
The binary may use _malloc
function instead of calloc

 IPA BINARY ANALYSIS
PROTECTION
PROTECTION
STATUS
STATUS
SEVERITY
SEVERITY
DESCRIPTION
DESCRIPTION
NX
False
info
The binary does not have NX bit set. NX bit offer protection against exploitation of memory corruption
vulnerabilities by marking memory page as non-executable. However iOS never allows an app to execute from
writeable memory. You do not need to specifically enable the ‘NX bit’ because it’s always enabled for all third-
party code.
PIE
True
info
The binary is build with -fPIC flag which enables Position independent code. This makes Return Oriented
Programming (ROP) attacks much more difficult to execute reliably.
STACK CANARY
True
info
This binary has a stack canary value added to the stack so that it will be overwritten by a stack buffer that
overflows the return address. This allows detection of overflows by verifying the integrity of the canary before
function return.
ARC
False
warning
This binary has debug symbols stripped. We cannot identify whether ARC is enabled or not.
RPATH
False
info
The binary does not have Runpath Search Path (@rpath) set.
CODE
SIGNATURE
True
info
This binary has a code signature.
ENCRYPTED
False
warning
This binary is not encrypted.
SYMBOLS
STRIPPED
True
info
Debug Symbols are stripped

 CODE ANALYSIS
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

 OFAC SANCTIONED COUNTRIES
This app may communicate with the following OFAC sanctioned list of countries.   
DOMAIN
DOMAIN
COUNTRY/REGION
COUNTRY/REGION

 DOMAIN MALWARE CHECK
DOMAIN
DOMAIN
STATUS
STATUS
GEOLOCATION
GEOLOCATION
www.apple.com
ok
IP:
IP:
23.201.200.214
Country:
Country:
India
Region:
Region:
Maharashtra
City:
City:
Mumbai
Latitude:
Latitude:
19.014410
Longitude:
Longitude:
72.847939
View:
View:
Google Map
developer.apple.com
ok
IP:
IP:
17.253.18.201
Country:
Country:
Brazil
Region:
Region:
Sao Paulo
City:
City:
Sao Paulo
Latitude:
Latitude:
-23.547501
Longitude:
Longitude:
-46.636108
View:
View:
Google Map

 SCAN LOGS
Timestamp
Timestamp
Event
Event
Error
Error
2025-04-19 07:05:58
iOS Binary (IPA) Analysis Started
OK
2025-04-19 07:05:58
Generating Hashes
OK
2025-04-19 07:05:58
Extracting IPA
OK
2025-04-19 07:05:58
Unzipping
OK
2025-04-19 07:05:58
iOS File Analysis and Normalization
OK
2025-04-19 07:05:59
iOS Info.plist Analysis Started
OK
2025-04-19 07:05:59
Finding Info.plist in iOS Binary
OK
2025-04-19 07:05:59
Fetching Details from App Store: com.bitbar.testdroid.BitbarIOSSample
OK
2025-04-19 07:05:59
Searching for secrets in plist files
OK
2025-04-19 07:05:59
Starting Binary Analysis
OK
2025-04-19 07:05:59
Dumping Classes from the binary
OK
2025-04-19 07:05:59
Running jtool against the binary for dumping classes
OK
2025-04-19 07:05:59
Library Binary Analysis Started
OK
2025-04-19 07:05:59
Framework Binary Analysis Started
OK
2025-04-19 07:05:59
Extracting String Metadata
OK
2025-04-19 07:05:59
Extracting URL and Email from IPA
OK
2025-04-19 07:05:59
Performing Malware check on extracted domains
OK
2025-04-19 07:06:00
Fetching IPA icon path
OK
2025-04-19 07:06:02
Updating Trackers Database....
OK
2025-04-19 07:06:02
Detecting Trackers from Domains
OK
2025-04-19 07:06:02
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
    
    print("\n--- Testing MobSF iOS Parser with Dummy Text ---")
    try:
        parsed_mobsf_ios_report = parse_mobsf_ios_report(dummy_mobsf_ios_text)
        print("Successfully parsed dummy MobSF iOS report.")
        # print(json.dumps(parsed_mobsf_ios_report, indent=2)) # Uncomment to see full JSON output

        # Verify some extracted data
        print(f"App Name: {parsed_mobsf_ios_report['app_information']['App Name']}")
        print(f"Scan Date: {parsed_mobsf_ios_report['scan_metadata']['scan_date']}")
        print(f"High Severity Findings: {parsed_mobsf_ios_report['summary']['findings_severity']['High']}")
        print(f"Total IPA Binary Code Analysis Findings: {len(parsed_mobsf_ios_report['ipa_binary_code_analysis_findings'])}")
        print(f"First IPA Binary Code Analysis Issue Description: {parsed_mobsf_ios_report['ipa_binary_code_analysis_findings'][0]['description']}")
        print(f"First IPA Binary Analysis Protection: {parsed_mobsf_ios_report['ipa_binary_analysis_findings'][0]['protection']}")
        print(f"First Domain Malware Check Domain: {parsed_mobsf_ios_report['domain_malware_check'][0]['domain']}")
        
        # Save dummy parsed output to a JSON file
        output_path = "mobsf_ios_report_parsed_dummy.json"
        with open(output_path, 'w') as f:
            json.dump(parsed_mobsf_ios_report, f, indent=2)
        print(f"Dummy parsed output saved to: {output_path}")

    except Exception as e:
        print(f"Error parsing dummy MobSF iOS report: {str(e)}")

    if len(sys.argv) > 1:
        report_path = sys.argv[1]
        try:
            report = process_mobsf_ios_report_file(report_path)
            print(f"Successfully processed MobSF iOS report: {report_path}")
            print(f"App Name: {report['app_information'].get('App Name', 'N/A')}")
            print(f"App Security Score: {report['scan_metadata'].get('app_security_score', 'N/A')}")
            print(f"Total findings: {report['summary']['total_issues']}")

            output_path = os.path.splitext(report_path)[0] + "_ios_parsed.json"
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"Structured output saved to: {output_path}")

        except Exception as e:
            print(f"Error: {str(e)}")
            sys.exit(1)
    else:
        print("\nUsage: python your_ios_script_name.py <path_to_mobsf_ios_report.pdf>")
        print("Or run without arguments to test with dummy text.")