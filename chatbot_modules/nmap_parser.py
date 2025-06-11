import os
import sys
import re
import json
import uuid
from typing import Union, Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime

# Add the current directory to Python path to ensure local imports work
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# Now import pdf_extractor
try:
    from pdf_extractor import extract_text_from_pdf
except ImportError as e:
    print(f"Error importing pdf_extractor: {e}")
    print(f"Current Python path: {sys.path}")
    print(f"Current directory: {os.getcwd()}")
    print("Files in current directory:", os.listdir('.'))
    
    # Define a fallback function if import fails
    def extract_text_from_pdf(pdf_path: str) -> Optional[str]:
        print(f"ERROR: Could not import pdf_extractor. Cannot extract text from {pdf_path}")
        return None

def parse_nmap_report(raw_nmap_text: str) -> Dict[str, Any]:
    """
    Transforms raw Nmap text into a structured, machine-readable dictionary.
    This parser is designed to extract details from various Nmap scan reports,
    including aggressive scans, port scans, OS detection, TCP SYN scans, and
    fragmented packet scans. It handles common sections like host info,
    ports, OS detection, and traceroute.

    Args:
        raw_nmap_text: The raw text output from an Nmap scan.

    Returns:
        dict: A structured dictionary containing Nmap scan information.
              The structure includes:
              - "scan_metadata": General information about the scan (initiated by, timestamp, target, Nmap version, duration).
              - "hosts": A list of dictionaries, each representing a scanned host.
                  - Each host dictionary contains:
                      - "ip_address", "hostname", "status", "latency", "rdns",
                      - "os_detection": Device type, OS guesses, OS CPE, aggressive guesses.
                      - "ports": A list of dictionaries, each for an open/filtered port.
                          - Each port dictionary includes: "port_id", "protocol", "state", "service", "version", "script_outputs".
                      - "traceroute": A list of dictionaries for each hop.
                          - Each hop dictionary includes: "hop", "rtt", "address".
                      - "network_distance", "other_addresses", "mac_address".
    """
    parsed_data: Dict[str, Any] = {
        "scan_metadata": {
            "scan_initiated_by": None,
            "timestamp": None,
            "target": None,
            "nmap_version": None,
            "scan_start_time": None,
            "scan_end_time": None, # Nmap output usually gives duration, not end time explicitly
            "scan_duration": None,
            "scan_type": None # Will be populated by the caller if identifiable
        },
        "hosts": []
    }
    current_host: Dict[str, Any] = {}
    current_port: Dict[str, Any] = {}
    
    # Clean up raw text by splitting lines and stripping whitespace,
    # then rejoin to standardize for regex matching.
    cleaned_lines = [line.strip() for line in raw_nmap_text.split('\n')]
    cleaned_text = "\n".join([line for line in cleaned_lines if line]) # Remove completely empty lines

    # --- Extract Scan Metadata from custom headers ---
    # These headers often have multiple commas or newlines, so use re.DOTALL and flexible whitespace matching.
    scan_initiated_match = re.search(r"Scan Initiated By:\s*[,:]*\s*\"(.*?)\"\s*", cleaned_text, re.IGNORECASE | re.DOTALL)
    if scan_initiated_match:
        parsed_data["scan_metadata"]["scan_initiated_by"] = scan_initiated_match.group(1).strip()
    
    timestamp_match = re.search(r"Timestamp:\s*[,:]*\s*\"(.*?)\"\s*", cleaned_text, re.IGNORECASE | re.DOTALL)
    if timestamp_match:
        parsed_data["scan_metadata"]["timestamp"] = timestamp_match.group(1).strip()
    
    target_match = re.search(r"Target:\s*[,:]*\s*\"(.*?)\"\s*", cleaned_text, re.IGNORECASE | re.DOTALL)
    if target_match:
        parsed_data["scan_metadata"]["target"] = target_match.group(1).strip()
    
    # --- Extract Nmap version and start time from Nmap's own output ---
    nmap_start_line_match = re.search(r"Starting Nmap ([\d.]+SVN)?\s*\(https:\/\/nmap\.org\)\s*at\s*(.*? IST)", cleaned_text)
    if nmap_start_line_match:
        parsed_data["scan_metadata"]["nmap_version"] = nmap_start_line_match.group(1) if nmap_start_line_match.group(1) else "N/A"
        parsed_data["scan_metadata"]["scan_start_time"] = nmap_start_line_match.group(2).strip()
    
    # --- Process scan duration ---
    done_match = re.search(r"Nmap done: .+? in ([\d.]+) seconds", cleaned_text)
    if done_match:
        parsed_data["scan_metadata"]["scan_duration"] = f"{done_match.group(1)} seconds"
    
    # --- Determine Scan Type (for better contextualization) ---
    if "Nmap Aggressive Scan Report" in cleaned_text:
        parsed_data["scan_metadata"]["scan_type"] = "Aggressive Scan"
    elif "Nmap Port Scan Report" in cleaned_text:
        parsed_data["scan_metadata"]["scan_type"] = "Port Scan"
    elif "Nmap Tcp Syn Scan Report" in cleaned_text:
        parsed_data["scan_metadata"]["scan_type"] = "TCP SYN Scan"
    elif "Nmap Os Detection Report" in cleaned_text:
        parsed_data["scan_metadata"]["scan_type"] = "OS Detection Scan"
    elif "Nmap Fragmented Packet Scan Report" in cleaned_text:
        parsed_data["scan_metadata"]["scan_type"] = "Fragmented Packet Scan"
    else:
        parsed_data["scan_metadata"]["scan_type"] = "Generic Nmap Scan"


    # --- Process Host Blocks ---
    # Splitting the report by "Nmap scan report for" to get individual host blocks.
    # Process line by line within each block.
    raw_lines = cleaned_text.split('\n')
    current_lines_block: List[str] = []
    
    # Find the start of the first host block
    start_parsing = False
    for line_idx, line in enumerate(raw_lines):
        if "Nmap scan report for" in line:
            start_parsing = True
            current_lines_block.append(line) # Add the first host report line
            continue
        if start_parsing:
            current_lines_block.append(line)

    # Re-split by "Nmap scan report for" after initial clean-up to ensure clean blocks
    # This ensures each block starts with the "Nmap scan report for" line
    host_blocks_cleaned = re.split(r"Nmap scan report for", "\n".join(current_lines_block))[1:] # Skip empty first part

    for block in host_blocks_cleaned:
        lines_in_block = [line.strip() for line in block.split('\n') if line.strip()]
        if not lines_in_block:
            continue

        # Host Information (first line of a host block)
        # Example: testphp.vulnweb.com (44.228.249.3)
        host_info_line = lines_in_block[0]
        ip_match = re.search(r"\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)", host_info_line)
        hostname_match = re.search(r"^([^\s\(]+)", host_info_line) # Capture hostname before potential IP in parenthesis
        
        ip_address = ip_match.group(1) if ip_match else "N/A"
        hostname = hostname_match.group(1) if hostname_match else "N/A"
        if hostname == "N/A" and ip_address != "N/A": # Fallback if hostname is missing but IP is found
            hostname = ip_address
        
        current_host = {
            "ip_address": ip_address,
            "hostname": hostname,
            "status": "unknown",
            "latency": "N/A",
            "rdns": "N/A",
            "other_addresses": [],
            "mac_address": "N/A",
            "network_distance": None,
            "os_detection": {
                "device_type": [],
                "os_guesses": [],
                "os_cpe": [],
                "aggressive_os_guesses": []
            },
            "ports": [],
            "traceroute": [],
            "extra_info": {} # For any unparsed or miscellaneous info
        }
        
        # Iterate through lines within the host block to find details
        i = 0
        while i < len(lines_in_block):
            line = lines_in_block[i].strip()
            if not line:
                i += 1
                continue
                
            # Host status and latency
            if "Host is up" in line:
                current_host["status"] = "up"
                latency_match = re.search(r"\((\d+\.\d+s)\)", line)
                if latency_match:
                    current_host["latency"] = latency_match.group(1)
            elif "Host is down" in line:
                current_host["status"] = "down"
            
            # rDNS record
            elif "rDNS record for" in line:
                # rDNS can be on the next line or on the same line after a colon.
                # Example: "rDNS record for 44.228.249.3: ec2-..."
                # Example: "rDNS record for 44.228.249.3:\n ec2-..."
                rdns_match = re.search(r"rDNS record for \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\s*(.*)", line)
                if rdns_match and rdns_match.group(1).strip():
                    current_host["rdns"] = rdns_match.group(1).strip()
                elif i + 1 < len(lines_in_block): # Check next line if not found on current
                    next_line_rdns = lines_in_block[i+1].strip()
                    if not re.match(r"^\d+/", next_line_rdns) and not "Not shown" in next_line_rdns: # Not a port or 'Not shown'
                        current_host["rdns"] = next_line_rdns
                        i += 1 # Consume this line
            
            # Other addresses
            elif "Other addresses for" in line and "(not scanned):" in line:
                other_addrs_str = re.search(r"Other addresses for .+? \(not scanned\):\s*(.*)", line)
                if other_addrs_str:
                    current_host["other_addresses"].extend([addr.strip() for addr in other_addrs_str.group(1).split()])
            
            # MAC Address
            elif "MAC Address:" in line:
                mac_match = re.search(r"MAC Address: ([\dA-Fa-f:]{17})\s*\((.*)\)", line)
                if mac_match:
                    current_host["mac_address"] = f"{mac_match.group(1)} ({mac_match.group(2)})"

            # Network distance
            elif "Network Distance:" in line:
                dist_match = re.search(r"Network Distance: (\d+)\s*hops", line)
                if dist_match:
                    current_host["network_distance"] = int(dist_match.group(1))
            
            # --- Port Information ---
            # Recognizes the start of the PORT section header or a port line
            elif re.match(r"^\s*PORT\s+STATE\s+SERVICE", line) or re.match(r"^\d+/(tcp|udp)", line):
                if re.match(r"^\s*PORT\s+STATE\s+SERVICE", line): # Skip the header itself
                    i += 1
                    continue
                
                # If we encounter a new port line, finalize any previous script output
                if current_port and current_port.get("script_outputs") and "_current_script_lines" in current_port:
                    script_name = current_port.pop("_current_script_name", None)
                    script_lines = current_port.pop("_current_script_lines", [])
                    if script_name and script_lines:
                        current_port["script_outputs"][script_name] = "\n".join(script_lines).strip()

                port_match = re.match(r"(\d+)/(tcp|udp)\s+(open|closed|filtered|unfiltered|open\|filtered|closed\|filtered|unknown)\s+([\w\-\.]+)\s*(.*)", line)
                if port_match:
                    port_id = int(port_match.group(1))
                    protocol = port_match.group(2)
                    state = port_match.group(3)
                    service = port_match.group(4)
                    version = port_match.group(5).strip() if port_match.group(5) else "N/A"

                    current_port = {
                        "port_id": port_id,
                        "protocol": protocol,
                        "state": state,
                        "service": service,
                        "version": version,
                        "script_outputs": {}
                    }
                    current_host["ports"].append(current_port)
                
                # Script output for the current port (can be multi-line)
                # This needs to look ahead as script outputs immediately follow a port line.
                script_line_idx = i + 1
                while script_line_idx < len(lines_in_block):
                    script_line = lines_in_block[script_line_idx].strip()
                    if script_line.startswith("|__"):
                        script_detail_match = re.match(r"\|\__(\S+):\s*(.*)", script_line)
                        if script_detail_match and current_port:
                            script_name = script_detail_match.group(1)
                            script_value = script_detail_match.group(2).strip()
                            current_port["script_outputs"][script_name] = script_value
                            
                            # Check for multi-line script output
                            multi_line_content = []
                            next_script_line_idx = script_line_idx + 1
                            while next_script_line_idx < len(lines_in_block):
                                next_script_line = lines_in_block[next_script_line_idx].strip()
                                if next_script_line.startswith("| ") or next_script_line.startswith("|_"):
                                    multi_line_content.append(next_script_line.lstrip('|_ ').strip())
                                    next_script_line_idx += 1
                                else:
                                    break
                            if multi_line_content:
                                current_port["script_outputs"][script_name] += "\n" + "\n".join(multi_line_content)
                            script_line_idx = next_script_line_idx -1 # Adjust index to end of script output
                        else:
                            break # Not a recognized script format or no current port
                    elif script_line.startswith("| "): # Continuation of multi-line script output that doesn't start with |__
                        # This case should be handled by the logic above for multi_line_content
                        # but for robustness, if missed, can be added to last script.
                        break # Likely end of script block
                    else: # Not a script line, break from script parsing
                        break
                    script_line_idx += 1
                i = script_line_idx -1 # Adjust main loop index to avoid re-processing script lines

            # --- OS Detection ---
            elif "Device type:" in line:
                current_host["os_detection"]["device_type"] = [x.strip() for x in line.split(":", 1)[1].split("|") if x.strip()]
            
            elif "Running (JUST GUESSING):" in line:
                # This regex splits by ') ,' to get individual guesses
                guesses = line.split(":", 1)[1].strip()
                current_host["os_detection"]["os_guesses"] = [g.strip() for g in re.split(r'\)\s*,\s*', guesses) if g.strip()]
            
            elif "OS CPE:" in line:
                cpes = line.split(":", 1)[1].strip()
                current_host["os_detection"]["os_cpe"] = [cpe.strip() for cpe in re.split(r'\s+(?=cpe:)' , cpes) if cpe.strip()]
            
            elif "Aggressive OS guesses:" in line:
                # Similar splitting logic for aggressive guesses
                guesses = line.split(":", 1)[1].strip()
                # Handle cases where multiple guesses are on one line
                current_host["os_detection"]["aggressive_os_guesses"] = [g.strip() for g in re.split(r'\)\s*,\s*', guesses) if g.strip()]
            
            elif "Warning: OSScan results may be unreliable" in line:
                current_host["os_detection"]["warning"] = line.strip()
            elif "No exact OS matches for host" in line:
                current_host["os_detection"]["no_exact_match_reason"] = line.strip()


            # --- TRACEROUTE Section ---
            elif "TRACEROUTE" in line.upper():
                current_host["traceroute"] = []
                # Find the "HOP RTT ADDRESS" header
                traceroute_header_found = False
                temp_idx = i
                while temp_idx < len(lines_in_block):
                    if "HOP RTT ADDRESS" in lines_in_block[temp_idx].upper():
                        traceroute_header_found = True
                        break
                    temp_idx += 1

                if traceroute_header_found:
                    j = temp_idx + 1 # Start parsing from line after header
                    while j < len(lines_in_block):
                        trace_line = lines_in_block[j].strip()
                        
                        # Stop conditions for traceroute parsing
                        if not trace_line or \
                           re.match(r"^(Nmap done|OS and Service detection performed|Sec SERVICES PVT\.LTD\.)", trace_line) or \
                           re.match(r"^\s*PORT\s+STATE\s+SERVICE", trace_line): # If another section header appears
                            break
                        
                        if trace_line == "...":
                            current_host["traceroute"].append({"hop": "...", "rtt": "N/A", "address": "N/A"})
                        else:
                            # Regex to capture hop, RTT, and address. RTT can be 'ms' or just a number. Address can have spaces.
                            hop_match = re.match(r'^(\d+)\s+([\d.]+\s*ms|[\d.]+\s*)\s*(.+)', trace_line)
                            if hop_match:
                                try:
                                    hop = int(hop_match.group(1))
                                    rtt = hop_match.group(2).strip()
                                    address = hop_match.group(3).strip()
                                    
                                    current_host["traceroute"].append({
                                        "hop": hop,
                                        "rtt": rtt,
                                        "address": address
                                    })
                                except (ValueError, IndexError, AttributeError):
                                    pass # Skip problematic lines but continue parsing
                        j += 1
                    i = j - 1 # Adjust main loop's index to just before where traceroute parsing stopped
                # Continue to the next line in the main loop after processing traceroute
                
            i += 1
        
        parsed_data["hosts"].append(current_host)
    
    return parsed_data

# --- Main Nmap Report Processing Function for Files ---

def process_nmap_report_file(pdf_file_path: str) -> Optional[Dict[str, Any]]:
    """
    Reads an Nmap PDF report, extracts text, identifies its type (if possible),
    and calls the general parser function.
    Returns a dictionary with overall report metadata and a list of structured host data.
    """
    print(f"\nProcessing Nmap PDF: {pdf_file_path}")
    raw_text = extract_text_from_pdf(pdf_file_path)

    if not raw_text:
        print(f"  Failed to extract text from {pdf_file_path}. Skipping.")
        return None

    # The parse_nmap_report function now handles internal type detection and general parsing
    structured_data = parse_nmap_report(raw_text)

    # Add source file name to metadata
    structured_data["scan_metadata"]["source_file_name"] = os.path.basename(pdf_file_path)

    # It's good to also add the report ID here, which would ideally be passed through
    # For now, let's generate one if not already set by an overarching process
    if "report_id" not in structured_data["scan_metadata"]:
        structured_data["scan_metadata"]["report_id"] = str(uuid.uuid4())

    print(f"  Processed {len(structured_data['hosts'])} host(s) from {os.path.basename(pdf_file_path)}.")
    
    return structured_data

# --- Main Execution Flow for Testing ---
if __name__ == "__main__":
    # Ensure this script can find pdf_extractor.py
    current_script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root_dir = os.path.dirname(current_script_dir)  # Go up one level to VulnScanAI
    
    # Add project root to path for module imports
    if project_root_dir not in sys.path:
        sys.path.insert(0, project_root_dir)
    
    # Use the nmap_reports_data directory in the project root
    pdf_reports_directory = os.path.join(project_root_dir, "nmap_reports_data")
    
    print(f"Looking for Nmap PDF files in: {pdf_reports_directory}\n")

    if not os.path.exists(pdf_reports_directory):
        print(f"Error: Directory '{pdf_reports_directory}' not found.")
        sys.exit(1)
    
    # Get all PDF files in the directory
    pdf_files = [f for f in os.listdir(pdf_reports_directory) 
                if f.lower().endswith('.pdf') and os.path.isfile(os.path.join(pdf_reports_directory, f))]
    
    if not pdf_files:
        print(f"No PDF files found in {pdf_reports_directory}")
        sys.exit(1)
    
    print(f"Found {len(pdf_files)} PDF file(s) to process:\n")
    
    for filename in pdf_files:
        pdf_path = os.path.join(pdf_reports_directory, filename)
        print(f"--- Processing {filename} ---")
        
        try:
            # Extract text from PDF
            raw_text = extract_text_from_pdf(pdf_path)
            if not raw_text:
                print(f"  Failed to extract text from {filename}")
                continue
                
            # Parse the Nmap report
            parsed_data = parse_nmap_report(raw_text)
            
            # Add source file info
            parsed_data["scan_metadata"]["source_file"] = filename
            
            # Print the parsed data
            print(json.dumps(parsed_data, indent=2))
            print("\n" + "="*80 + "\n")  # Separator for clarity
            
        except Exception as e:
            print(f"Error processing {filename}: {e}")
            import traceback
            traceback.print_exc()  # Print full traceback for debugging
            print("\n" + "="*80 + "\n")
