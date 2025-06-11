import os
import json
import sys
import re
from typing import Dict, Any, Optional, List
from pathlib import Path

# Add the current directory to Python path to ensure local imports work
project_root_dir = os.path.abspath(os.path.dirname(__file__))
if project_root_dir not in sys.path:
    sys.path.insert(0, project_root_dir)

# Try to import from the chatbot_modules package
try:
    from chatbot_modules.pdf_extractor import extract_text_from_pdf
    from chatbot_modules.nmap_parser import parse_nmap_report, process_nmap_report_file
    from chatbot_modules.local_llm import load_model, generate_response
except ImportError as e:
    print(f"Error importing from chatbot_modules: {e}")
    print("Current Python path:", sys.path)
    print("Current directory:", os.getcwd())
    print("Files in current directory:", os.listdir('.'))
    sys.exit(1)

# --- Import for Semantic Search (SentenceTransformer and Pinecone) ---
try:
    from sentence_transformers import SentenceTransformer, util
    from pinecone import Pinecone, ServerlessSpec
    from dotenv import load_dotenv # For loading API keys from .env file
    load_dotenv() # Load environment variables from .env file
except ImportError as e:
    print(f"Error importing semantic search libraries: {e}")
    print("Please install them using: pip install sentence-transformers pinecone-client python-dotenv")
    sys.exit(1)

# --- Configuration for Local Language Model ---
MODEL_ID = "TheBloke/OpenHermes-2.5-Mistral-7B-GGUF"
MODEL_BASENAME = "openhermes-2.5-mistral-7b.Q4_K_M.gguf"
MODEL_LOCAL_DIR = os.path.join(project_root_dir, "pretrained_language_model")

# --- Configuration for Semantic Search Model and Pinecone ---
SEMANTIC_MODEL_PATH = os.path.join(project_root_dir, "fine_tuned_owasp_model_advanced")
PINECONE_INDEX_NAME = "owasp-qa"
PINECONE_NAMESPACE_NMAP = "Nmap_Port_Scanning" # Specific namespace for Nmap-related Q&A
EMBEDDING_DIM = 768 # Standard for 'all-mpnet-base-v2'

# Pinecone API Key and Environment from .env (or hardcoded for testing, but not recommended for production)
PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")
PINECONE_ENVIRONMENT = os.getenv("PINECONE_ENVIRONMENT", "us-east-1") # Default region if not set

# Global variables
current_loaded_report_data = None
model_instance = None
semantic_model = None # For the SentenceTransformer model
pinecone_index = None # For the Pinecone connection


def load_model_once():
    """Loads the local language model instance globally if not already loaded."""
    global model_instance
    if model_instance is None:
        print(f"Attempting to load local language model from {MODEL_LOCAL_DIR}...")
        try:
            model_instance = load_model(MODEL_ID, MODEL_BASENAME, MODEL_LOCAL_DIR)
            print("Local language model successfully initialized.")
        except Exception as e:
            print(f"Failed to load local language model: {e}")
            model_instance = None # Ensure it remains None on failure
    return model_instance is not None

def load_semantic_model_once():
    """Loads the SentenceTransformer model for semantic search globally if not already loaded."""
    global semantic_model
    if semantic_model is None:
        print(f"Attempting to load Semantic Model from {SEMANTIC_MODEL_PATH}...")
        try:
            semantic_model = SentenceTransformer(SEMANTIC_MODEL_PATH)
            print("Semantic Model loaded successfully.")
        except Exception as e:
            print(f"Failed to load Semantic Model: {e}")
            semantic_model = None
            return False
    return semantic_model is not None

def initialize_pinecone_client_once():
    """Initializes Pinecone client and connects to the index globally if not already connected."""
    global pinecone_index
    if pinecone_index is None:
        if not PINECONE_API_KEY:
            print("Error: PINECONE_API_KEY not found in environment variables. Cannot initialize Pinecone.")
            return False
        
        print(f"Attempting to initialize Pinecone client and connect to index '{PINECONE_INDEX_NAME}'...")
        try:
            pc = Pinecone(api_key=PINECONE_API_KEY)
            
            # Check if index exists, create if not (only if serverless spec is available)
            if PINECONE_INDEX_NAME not in [index.name for index in pc.list_indexes()]:
                print(f"Creating new Pinecone index: {PINECONE_INDEX_NAME} in region {PINECONE_ENVIRONMENT}")
                pc.create_index(
                    name=PINECONE_INDEX_NAME,
                    dimension=EMBEDDING_DIM,
                    metric="cosine",
                    spec=ServerlessSpec(cloud='aws', region=PINECONE_ENVIRONMENT) # Assuming AWS for ServerlessSpec
                )
                print(f"Index '{PINECONE_INDEX_NAME}' created.")

            pinecone_index = pc.Index(PINECONE_INDEX_NAME)
            print(f"Connected to Pinecone index: {PINECONE_INDEX_NAME}")
            # print(f"Pinecone Index stats: {pinecone_index.describe_index_stats()}") # Uncomment for debug
        except Exception as e:
            print(f"Failed to initialize Pinecone: {e}")
            pinecone_index = None
            return False
    return pinecone_index is not None


def retrieve_from_pinecone(query: str, top_k: int = 3, namespace: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Retrieves relevant information from the Pinecone index based on a user query.

    Args:
        query (str): The user's query.
        top_k (int): Number of top results to retrieve.
        namespace (Optional[str]): Specific Pinecone namespace to search within.

    Returns:
        List[Dict[str, Any]]: A list of dictionaries containing retrieved matches (e.g., {'text': ..., 'answer': ..., 'score': ...}).
    """
    if not load_semantic_model_once() or not initialize_pinecone_client_once():
        print("Semantic model or Pinecone not ready. Cannot perform retrieval.")
        return []

    try:
        # Generate query embedding
        query_embedding = semantic_model.encode(query, convert_to_tensor=True).cpu().numpy().tolist()
        
        # Query Pinecone
        query_params = {
            'vector': query_embedding,
            'top_k': top_k,
            'include_metadata': True
        }
        if namespace:
            query_params['namespace'] = namespace

        search_results = pinecone_index.query(**query_params)
        
        retrieved_data = []
        for match in search_results.matches:
            retrieved_data.append({
                'score': match.score,
                'question': match.metadata.get('text', 'N/A'), # The question in the QA pair
                'answer': match.metadata.get('answer', 'N/A'), # The answer in the QA pair
                'source': match.metadata.get('source', 'Pinecone-KB'),
                'type': match.metadata.get('type', 'N/A'),
                'intent': match.metadata.get('intent', 'N/A'),
                'related_topics': match.metadata.get('related_topics', 'N/A')
            })
        return retrieved_data
    except Exception as e:
        print(f"Error during Pinecone retrieval: {e}")
        return []


def answer_query_about_report(user_query: str) -> str:
    """
    Answers a user query, intelligently routing between the Nmap report data
    and the Pinecone knowledge base, then uses the language model to synthesize the response.

    Args:
        user_query (str): The question from the user.

    Returns:
        str: The language model-generated answer.
    """
    global current_loaded_report_data, model_instance

    if not load_model_once():
        return "Sorry, the main language model is not loaded. Please try again later."

    context_for_model = ""
    source_of_context = "no_context"

    # --- Routing Logic: Nmap Report Specific vs. General KB Query ---
    nmap_keywords = ["port", "service", "os", "host", "latency", "rdns", "scan type", "traceroute", "mac address", "vulnerability"]
    # Broader check for Nmap related query if it involves specific data points or an IP/hostname
    is_nmap_data_query = any(keyword in user_query.lower() for keyword in nmap_keywords) or \
                         re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\b(?:[a-z0-9-]+\.)+[a-z]{2,6}\b', user_query.lower()) # check for IP/hostname (e.g., example.com)


    if current_loaded_report_data and is_nmap_data_query:
        # Attempt to extract *relevant* snippets from the Nmap report
        print("Routing query to Nmap report data for targeted extraction.")
        extracted_nmap_snippets = []
        user_query_lower = user_query.lower()

        # Try to identify a specific target (IP or hostname) in the query
        target_ip_or_hostname = None
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', user_query_lower)
        if ip_match:
            target_ip_or_hostname = ip_match.group(1)
        else:
            # More robust hostname extraction, avoiding common words that might look like hostnames
            # This regex looks for patterns like example.com, sub.domain.co.uk etc.
            # It's imperfect but better than simple word matching.
            hostname_match = re.search(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,6}\b', user_query_lower)
            if hostname_match and "what is" not in user_query_lower and "how to" not in user_query_lower: # Avoid matching "what is example.com" as a target
                target_ip_or_hostname = hostname_match.group(0)

        relevant_hosts = []
        if target_ip_or_hostname:
            for host in current_loaded_report_data.get('hosts', []):
                if target_ip_or_hostname in host.get('ip_address', '').lower() or \
                   target_ip_or_hostname in host.get('hostname', '').lower():
                    relevant_hosts.append(host)
        else: # If no specific target mentioned, assume query is about the primary target or first host
            if current_loaded_report_data.get('hosts'):
                relevant_hosts = [current_loaded_report_data['hosts'][0]]


        for host in relevant_hosts:
            host_identifier = host.get('hostname', host.get('ip_address', 'Unknown Host'))
            host_summary_line = f"Host: {host_identifier} (IP: {host.get('ip_address', 'N/A')})"
            
            # Conditionally add sections based on user query keywords
            added_any_host_info = False

            if "port" in user_query_lower or "service" in user_query_lower:
                if host.get('ports'):
                    ports_info = []
                    for port in host['ports']:
                        ports_info.append(f"  Port: {port['port_id']}/{port['protocol']}, State: {port['state']}, Service: {port['service']}, Version: {port['version']}")
                        if port.get('script_outputs'):
                            for script_name, script_output in port['script_outputs'].items():
                                # Limit script output to prevent overwhelming context
                                script_truncated = script_output.splitlines()[0][:150] + "..." if len(script_output.splitlines()[0]) > 150 else script_output
                                ports_info.append(f"    Script ({script_name}): {script_truncated}")
                    extracted_nmap_snippets.append(f"{host_summary_line}\nOpen/Filtered Ports:\n" + "\n".join(ports_info))
                    added_any_host_info = True
            
            if "os" in user_query_lower or "device" in user_query_lower:
                if host.get('os_detection') and (host['os_detection'].get('os_guesses') or host['os_detection'].get('device_type')):
                    os_info = []
                    if host['os_detection'].get('device_type'):
                        os_info.append(f"  Device Type: {', '.join(host['os_detection']['device_type'])}")
                    if host['os_detection'].get('os_guesses'):
                        os_info.append(f"  OS Guesses: {', '.join(host['os_detection']['os_guesses'])}")
                    if host['os_detection'].get('aggressive_os_guesses'):
                        os_info.append(f"  Aggressive OS Guesses: {', '.join(host['os_detection']['aggressive_os_guesses'])}")
                    extracted_nmap_snippets.append(f"{host_summary_line}\nOS Detection:\n" + "\n".join(os_info))
                    added_any_host_info = True

            if "traceroute" in user_query_lower:
                if host.get('traceroute'):
                    trace_info = [f"  Hop {h['hop']}: {h['rtt']} to {h['address']}" for h in host['traceroute']]
                    extracted_nmap_snippets.append(f"{host_summary_line}\nTraceroute:\n" + "\n".join(trace_info))
                    added_any_host_info = True

            if ("latency" in user_query_lower or "speed" in user_query_lower) and host.get('latency'):
                extracted_nmap_snippets.append(f"{host_summary_line}\nLatency: {host['latency']}")
                added_any_host_info = True
            
            if "rdns" in user_query_lower and host.get('rdns'):
                extracted_nmap_snippets.append(f"{host_summary_line}\nrDNS Record: {host['rdns']}")
                added_any_host_info = True
            
            if "mac address" in user_query_lower and host.get('mac_address'):
                extracted_nmap_snippets.append(f"{host_summary_line}\nMAC Address: {host['mac_address']}")
                added_any_host_info = True

            # If no specific host section was explicitly requested but a host was found and it's an Nmap data query
            if relevant_hosts and not added_any_host_info:
                # Provide a more general summary of the first relevant host if no specific section was hit
                general_host_info = f"{host_summary_line}\nStatus: {host.get('status', 'N/A')}, Latency: {host.get('latency', 'N/A')}"
                if host.get('ports'):
                    general_host_info += f", Open Ports: {len(host['ports'])}"
                extracted_nmap_snippets.append(general_host_info)

        # Also add general scan metadata if relevant keywords are in the query
        if current_loaded_report_data.get('scan_metadata') and \
           any(k in user_query_lower for k in ["scan type", "initiated by", "timestamp", "target", "duration", "nmap version"]):
            metadata_info = current_loaded_report_data['scan_metadata']
            metadata_summary = (
                f"Scan Type: {metadata_info.get('scan_type', 'N/A')}\n"
                f"Initiated By: {metadata_info.get('scan_initiated_by', 'N/A')}\n"
                f"Timestamp: {metadata_info.get('timestamp', 'N/A')}\n"
                f"Target: {metadata_info.get('target', 'N/A')}\n"
                f"Nmap Version: {metadata_info.get('nmap_version', 'N/A')}\n"
                f"Duration: {metadata_info.get('scan_duration', 'N/A')}"
            )
            extracted_nmap_snippets.append("Scan Metadata:\n" + metadata_summary)


        if extracted_nmap_snippets:
            context_for_model = "\n\n".join(extracted_nmap_snippets)
            source_of_context = "nmap_report"
        else:
            # If Nmap-specific keywords were used but no data extracted, revert to Pinecone/general
            print("Nmap-specific query, but no relevant structured data found after extraction attempt. Attempting Pinecone search.")
            is_nmap_data_query = False # Reset for Pinecone path to force KB lookup

    if not is_nmap_data_query: # If not Nmap specific or no Nmap data extracted from report
        print("Routing query to Pinecone knowledge base.")
        # Prioritize Nmap_Port_Scanning namespace if query contains port scanning or mitigation keywords
        is_mitigation_query = any(k in user_query_lower for k in ["how to", "prevent", "mitigate", "close", "secure", "fix", "remediation"])
        is_port_scanning_related = any(k in user_query_lower for k in ["port", "scan", "tcp", "udp", "syn", "stealth", "firewall"])
        
        target_namespace = PINECONE_NAMESPACE_NMAP if (is_mitigation_query or is_port_scanning_related) else None
        
        # Retrieve more results for better context when asking for mitigation
        pinecone_top_k = 7 if is_mitigation_query else 5 

        pinecone_results = retrieve_from_pinecone(user_query, top_k=pinecone_top_k, namespace=target_namespace)
        
        if pinecone_results:
            context_items = []
            for item in pinecone_results:
                # Include answer as it's the most useful part from Pinecone for the language model
                context_items.append(f"Question: {item['question']}\nAnswer: {item['answer']}\nSource: {item['source']}")
            context_for_model = "\n---\n".join(context_items)
            source_of_context = "pinecone_kb"
        else:
            print("No relevant information found in Pinecone. Relying on general language model knowledge.")
            source_of_context = "no_context"

    # --- Construct the Model Prompt ---
    system_instruction = (
        "You are a highly skilled cybersecurity analyst and an expert in Nmap reports. "
        "Your primary goal is to provide accurate, concise, and actionable answers to user queries. "
        "Always respond in markdown format. "
    )

    if source_of_context == "nmap_report":
        user_prompt = (
            f"The following are relevant snippets from a structured Nmap scan report:\n```\n{context_for_model}\n```\n\n"
            f"Based *only* on this Nmap report data, please answer the following question:\n"
            f"User Query: {user_query}\n\n"
            "If the information is not explicitly available in the provided Nmap scan data, state that the information is not found in the report. "
            "Prioritize factual data directly from the report."
        )
    elif source_of_context == "pinecone_kb":
        # Enhanced prompt for mitigation and action when Pinecone is used
        user_prompt = (
            f"The following are relevant knowledge snippets from a cybersecurity knowledge base:\n```\n{context_for_model}\n```\n\n"
            f"Based *only* on these snippets, please answer the following question. "
            "If the user's query asks for 'how to', 'prevent', 'mitigate', 'close', 'secure', or 'fix', prioritize providing actionable steps and recommendations found in the snippets. "
            "Do not fabricate information. If the information is not explicitly available in the provided snippets, state that you cannot answer based on the given context. "
            f"User Query: {user_query}\n\n"
        )
    else: # No specific context found, rely on language model's general knowledge
        user_prompt = (
            f"I do not have specific context for the following question, but please answer it based on your general cybersecurity knowledge. "
            f"If you are unsure or the question is outside your scope, please state so politely.\n"
            f"User Query: {user_query}\n\n"
        )

    full_prompt = f"<s>[INST] {system_instruction}\n\n{user_prompt} [/INST]"

    # Step 4: Generate a response from the language model
    try:
        answer = generate_response(model_instance, full_prompt, max_tokens=1500)
        return answer
    except Exception as e:
        print(f"Error generating language model response for query: {e}")
        return "Sorry, I encountered an error while trying to answer your question."


def process_and_summarize_report(pdf_path: str) -> Optional[str]:
    """
    Processes a given Nmap PDF report and generates an initial summary using the language model.

    Args:
        pdf_path (str): The full path to the Nmap PDF report.

    Returns:
        Optional[str]: The language model-generated summary, or None if processing fails.
    """
    global current_loaded_report_data, model_instance

    if not os.path.exists(pdf_path):
        print(f"Error: File not found at '{pdf_path}'")
        return None

    # Step 1: Extract text from PDF
    print(f"\n--- Extracting text from {os.path.basename(pdf_path)} ---")
    raw_text = extract_text_from_pdf(pdf_path)
    if not raw_text:
        print("Text extraction failed.")
        return None
    print("Text extraction complete.")

    # Step 2: Parse raw Nmap text into structured data
    print("--- Parsing Nmap report ---")
    try:
        parsed_nmap_data = parse_nmap_report(raw_text)
        current_loaded_report_data = parsed_nmap_data  # Store for future interactions
        print("Nmap report parsing complete.")
    except Exception as e:
        print(f"Error parsing Nmap report: {e}")
        current_loaded_report_data = None
        return None

    if not load_model_once():
        print("Language model is not loaded. Cannot generate summary.")
        return None

    # Step 3: Craft a prompt for the language model based on the structured data
    report_json_str = json.dumps(current_loaded_report_data, indent=2)

    prompt = (
        "You are a highly skilled cybersecurity analyst. "
        "Your task is to review the provided Nmap scan report data (in JSON format) "
        "and provide a concise, actionable summary. "
        "Highlight key findings, potential vulnerabilities, and immediate remediation steps. "
        "Focus on critical information from open ports, service versions, and OS detection.\n"
        "Only respond with the summary and recommendations in markdown format.\n"
        "\nNmap Report Data:\n"
        f"```json\n{report_json_str}\n```\n\n"
        "Please provide your summary and recommendations:"
    )

    # Step 4: Generate a response from the language model
    print("--- Generating summary using language model ---")
    try:
        summary = generate_response(model_instance, prompt, max_tokens=1000)
        print("Language model summary generation complete.")
        return summary
    except Exception as e:
        print(f"Error generating language model summary: {e}")
        return None

def print_header():
    """Print a clean header for the application."""
    print("\n" + "=" * 70)
    print("  Nmap Report Analyzer & Cybersecurity Assistant")
    print("=" * 70)

def print_section(title):
    """Print a section header."""
    print(f"\n{' ' + title + ' ':-^70}")

def print_help():
    """Display help information."""
    print_section("HELP")
    print("  Commands:")
    print("  - new report : Load a different Nmap report")
    print("  - help      : Show this help message")
    print("  - exit      : Exit the application")
    print("\n  Ask questions about the loaded Nmap report or general cybersecurity topics.")

def main_cli_interface():
    """
    Provides a clean command-line interface for uploading and summarizing Nmap reports,
    with improved readability and user experience.
    """
    print_header()
    print("\nWelcome! Upload an Nmap PDF report to begin analysis.")
    print("Type 'help' for commands or 'exit' to quit.\n")

    while True:
        try:
            # Get user input with a clear prompt
            user_input = input("\n[?] Enter PDF path or command: ").strip()

            if user_input.lower() == 'exit':
                print("\n[+] Thank you for using Nmap Report Analyzer. Goodbye!")
                return
                
            if user_input.lower() == 'help':
                print_help()
                continue
                
            if not user_input:
                print("[!] Please enter a file path or command.")
                continue

            # Process the Nmap report
            print("\n[+] Processing Nmap report...")
            summary = process_and_summarize_report(user_input)
            
            if summary:
                print_section("REPORT SUMMARY")
                print(summary)
                print_section("INTERACTIVE ANALYSIS")
                print("You can now ask questions about the report or cybersecurity topics.")
                print("Type 'new report' to analyze a different scan or 'exit' to quit.\n")
                
                # Interactive Q&A loop
                while True:
                    try:
                        question = input("\n[?] Your question: ").strip()
                        
                        if not question:
                            continue
                            
                        if question.lower() == 'exit':
                            print("\n[+] Thank you for using Nmap Report Analyzer. Goodbye!")
                            return
                            
                        if question.lower() == 'new report':
                            print("\n[+] Loading new report...")
                            current_loaded_report_data = None
                            break
                            
                        if question.lower() == 'help':
                            print_help()
                            continue
                        
                        print("\n[+] Analyzing your question...")
                        answer = answer_query_about_report(question)
                        
                        print("\n[+] Analysis Results:")
                        print("-" * 70)
                        print(answer)
                        print("-" * 70)
                        
                    except KeyboardInterrupt:
                        print("\n[!] Operation cancelled. Type 'exit' to quit or continue asking questions.")
                    except Exception as e:
                        print(f"\n[!] Error processing your question: {str(e)}")
            else:
                print("\n[!] Failed to process the report. Please check the file and try again.")
                
        except KeyboardInterrupt:
            print("\n[!] Operation cancelled. Type 'exit' to quit or enter a file path.")
        except Exception as e:
            print(f"\n[!] An error occurred: {str(e)}")

def cleanup():
    """Cleanup function to properly close resources."""
    global model_instance
    if model_instance is not None:
        try:
            # Properly close the language model instance if it has a close method
            if hasattr(model_instance, 'close') and callable(getattr(model_instance, 'close')):
                model_instance.close()
            model_instance = None
        except Exception as e:
            print(f"Error during cleanup: {e}")

def main():
    try:
        # Ensure local language model and semantic search model/Pinecone are ready
        print("Initializing components...")
        model_ready = load_model_once()
        semantic_model_ready = load_semantic_model_once()
        pinecone_ready = initialize_pinecone_client_once()

        if not model_ready:
            print("Cannot start application without the local language model. Please check configuration and model files.")
            return 1
        
        if not (semantic_model_ready and pinecone_ready):
            print("Warning: Semantic search (Pinecone) components could not be fully loaded. "
                  "General cybersecurity questions might not be as effective, but Nmap report analysis will still work.")

        main_cli_interface()
        return 0
    except KeyboardInterrupt:
        print("\nReceived keyboard interrupt. Exiting...")
        return 0
    except Exception as e:
        print(f"An error occurred: {e}")
        return 1
    finally:
        cleanup()

if __name__ == "__main__":
    sys.exit(main())
