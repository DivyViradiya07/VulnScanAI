import re
from typing import Dict, Any, Optional
from chatbot_modules.pdf_extractor import extract_text_from_pdf
from chatbot_modules.nmap_parser import parse_nmap_report
from chatbot_modules.zap_parser import parse_zap_report

def detect_report_type(pdf_path: str) -> str:
    """
    Detects the type of security report by analyzing its content.
    This function reads a small portion of the PDF's raw text to infer the type.

    Args:
        pdf_path (str): Path to the report PDF file

    Returns:
        str: 'nmap', 'zap', or 'unknown'
    """
    try:
        text = extract_text_from_pdf(pdf_path)
        if not text:
            print(f"Warning: No text extracted from {pdf_path} for type detection.")
            return 'unknown'

        text_lower = text.lower()

        if 'nmap scan report' in text_lower or 'nmap.org' in text_lower or 'nmap version' in text_lower:
            return 'nmap'

        if 'zap version' in text_lower or 'summary of alerts' in text_lower or 'zap by checkmarx' in text_lower:
            return 'zap'

        return 'unknown'
    except Exception as e:
        print(f"Error detecting report type for '{pdf_path}': {e}")
        return 'unknown'

def parse_report_content(pdf_path: str) -> Optional[Dict[str, Any]]:
    """
    Extracts text and parses the security report based on detected type.

    Args:
        pdf_path (str): Path to the report PDF file.

    Returns:
        Optional[Dict[str, Any]]: Parsed report data or None if parsing fails.
    """
    print(f"\n--- Extracting text from {pdf_path.split('/')[-1]} ---")
    raw_text = extract_text_from_pdf(pdf_path)
    if not raw_text:
        print("Text extraction failed.")
        return None
    print("Text extraction complete.")

    report_type = detect_report_type(pdf_path)

    if report_type == 'unknown':
        print(f"Error: Could not determine report type for '{pdf_path.split('/')[-1]}'.")
        return None

    print(f"--- Inferred report type: {report_type.upper()} ---")
    try:
        parsed_data = {}
        if report_type == 'nmap':
            parsed_data = parse_nmap_report(raw_text)
        elif report_type == 'zap':
            parsed_data = parse_zap_report(raw_text)

        parsed_data['report_type'] = report_type
        return parsed_data
    except Exception as e:
        print(f"Error parsing {report_type.upper()} report: {e}")
        return None