import os
import json
import sys
import re
from typing import Dict, Any, Optional, List, Union
from pathlib import Path
from collections import Counter # Added for extract_keywords

# Add the current directory to Python path to ensure local imports work
project_root_dir = os.path.abspath(os.path.dirname(__file__))
if project_root_dir not in sys.path:
    sys.path.insert(0, project_root_dir)

# Try to import from the chatbot_modules package
try:
    from chatbot_modules.pdf_extractor import extract_text_from_pdf
    from chatbot_modules.nmap_parser import parse_nmap_report
    from chatbot_modules.local_llm import load_model, generate_response
except ImportError as e:
    print(f"Error importing from chatbot_modules: {e}")
    print(f"Current Python path: {sys.path}")
    print(f"Current directory: {os.getcwd()}")
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

# --- Configuration for Local LLM ---
LLM_MODEL_ID = "TheBloke/OpenHermes-2.5-Mistral-7B-GGUF"
LLM_MODEL_BASENAME = "openhermes-2.5-mistral-7b.Q4_K_M.gguf"
LLM_LOCAL_DIR = os.path.join(project_root_dir, "pretrained_language_model")

# --- Configuration for Semantic Search Model and Pinecone ---
SEMANTIC_MODEL_PATH = os.path.join(project_root_dir, "fine_tuned_owasp_model_advanced")
PINECONE_INDEX_NAME = "owasp-qa" # This remains the overall index name
UNIFIED_PINECONE_NAMESPACE = "owasp-cybersecurity-kb"
EMBEDDING_DIM = 768 # Standard for 'all-mpnet-base-v2'

# Pinecone API Key and Environment from .env (or hardcoded for testing, but not recommended for production)
PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")
PINECONE_ENVIRONMENT = os.getenv("PINECONE_ENVIRONMENT", "us-east-1") # Default region if not set

# Global variables
current_loaded_report_data: Optional[Dict[str, Any]] = None
llm_instance = None
semantic_model = None # For the SentenceTransformer model
pinecone_index = None # For the Pinecone connection
chat_history: List[Dict[str, str]] = [] # Stores {"role": "user/model", "content": "message"}
MAX_CHAT_HISTORY_TURNS = 5 # Keep last N turns of conversation

def load_llm_once():
    """Loads the local LLM instance globally if not already loaded."""
    global llm_instance
    if llm_instance is None:
        print(f"Attempting to load Local LLM from {LLM_LOCAL_DIR}...")
        try:
            llm_instance = load_model(LLM_MODEL_ID, LLM_MODEL_BASENAME, LLM_LOCAL_DIR)
            print("Local LLM successfully initialized.")
        except Exception as e:
            print(f"Failed to load Local LLM: {e}")
            llm_instance = None # Ensure it remains None on failure
            return False
    return llm_instance is not None

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


def retrieve_from_pinecone(query: str, top_k: int = 3) -> List[Dict[str, Any]]:
    """
    Retrieves relevant information from the Pinecone index based on a user query.
    This version always queries the UNIFIED_PINECONE_NAMESPACE.

    Args:
        query (str): The user's query.
        top_k (int): Number of top results to retrieve.

    Returns:
        List[Dict[str, Any]]: A list of dictionaries containing retrieved matches
                               (e.g., {'question': ..., 'answer': ..., 'score': ..., 'source_file': ..., 'top_level_category': ...}).
    """
    if not load_semantic_model_once() or not initialize_pinecone_client_once():
        print("Semantic model or Pinecone not ready. Cannot perform retrieval.")
        return []

    try:
        # Generate query embedding
        query_embedding = semantic_model.encode(query, convert_to_tensor=True).cpu().numpy().tolist()
        
        # Pinecone query parameters - always query the unified namespace
        query_params = {
            'vector': query_embedding,
            'top_k': top_k,
            'include_metadata': True,
            'namespace': UNIFIED_PINECONE_NAMESPACE # Always query the unified namespace
        }
        
        print(f"--- Querying Pinecone for query: '{query}' (Namespace: '{UNIFIED_PINECONE_NAMESPACE}') ---")
        search_results = pinecone_index.query(**query_params)
        
        retrieved_data = []
        if not search_results.matches:
            print(f"No matches found in Pinecone namespace '{UNIFIED_PINECONE_NAMESPACE}'.")
        for match in search_results.matches:
            # We expect 'question' and 'answer' in metadata from S2_Embedding_Generation.ipynb
            question_text = match.metadata.get('question', 'N/A')
            answer_text = match.metadata.get('answer', 'N/A')
            
            # Skip if question or answer are effectively missing
            if question_text == 'N/A' or answer_text == 'N/A' or not question_text.strip() or not answer_text.strip():
                # print(f"  Skipping Pinecone result due to missing/empty Q/A in metadata for ID: {match.id}") # Removed for cleaner output
                continue

            retrieved_data.append({
                'score': match.score,
                'question': question_text,
                'answer': answer_text,
                # Using the new metadata keys from S2_Embedding_Generation.ipynb
                'source_file': match.metadata.get('source_file', 'Pinecone-KB'),
                'top_level_category': match.metadata.get('top_level_category', 'N/A'),
                'type': match.metadata.get('type', 'N/A'),
                'intent': match.metadata.get('intent', 'N/A'),
                'related_topics': match.metadata.get('related_topics', 'N/A')
            })
            print(f"  Score: {match.score:.4f}, Q: {question_text[:70]}..., A: {answer_text[:100]}..., Source: {retrieved_data[-1]['source_file']}")
        print("--- End Pinecone Retrieval Results ---\n")
        
        return retrieved_data
    except Exception as e:
        print(f"Error during Pinecone retrieval: {e}")
        return []

# === START: New/Modified functions from Chatbot.py for query enhancement ===

def extract_keywords(text: str) -> List[str]:
    """Extract important keywords from text for query expansion."""
    # Remove common stopwords, but keep security terms
    stopwords = {"a", "an", "the", "and", "or", "but", "if", "then", "else", "when", 
                "at", "by", "for", "with", "about", "against", "between", "into", 
                "through", "during", "before", "after", "above", "below", "to", "from", 
                "up", "down", "in", "out", "on", "off", "over", "under", "again", 
                "further", "then", "once", "here", "there", "all", "any", "both", 
                "each", "few", "more", "most", "other", "some", "such", "no", "nor", 
                "not", "only", "own", "same", "so", "than", "too", "very", "can", 
                "will", "just", "should", "now", "what", "which", "how", "where", "is", "are"}
    
    security_terms = {"vulnerability", "exploit", "cve", "attack", "threat", "risk", 
                     "compromise", "security", "breach", "patch", "fix", "update", 
                     "mitigation", "remediation", "severity", "impact", "unauthorized", 
                     "access", "disclosure", "injection", "overflow", "credentials",
                     "port", "scan", "tcp", "udp", "http", "https", "ssh", "smtp", "dns", "firewall", "os"} # Added Nmap specific terms
    
    # Remove security terms from stopwords to ensure they're kept
    stopwords = stopwords - security_terms
    
    # Tokenize and filter words
    words = text.lower().split()
    important_words = [word for word in words if word not in stopwords and len(word) > 2]
    
    # Get most common words that might be important
    word_counts = Counter(important_words)
    keywords = [word for word, count in word_counts.most_common(7)]
    
    # Combine original query words with common keywords
    all_keywords = list(set(important_words + keywords)) # Use important_words, not original words, for better filtering
    
    print(f"Extracted keywords: {all_keywords}")
    return all_keywords

def expand_query(question: str) -> List[str]:
    """Generate multiple query variations to improve retrieval."""
    print(f"Expanding query: '{question}'")
    # Extract keywords
    keywords = extract_keywords(question)
    
    # Original query is always included
    queries = [question]
    
    # Add keyword-only query
    if keywords:
        keyword_query = " ".join(keywords)
        if keyword_query != question.lower() and keyword_query not in queries:
            queries.append(keyword_query)
    
    # Generate variations
    # 1. Remove question words (only if they start the sentence)
    question_lower = question.lower()
    question_words = ["what is", "what are", "how to", "how do", "explain", "tell me about"]
    for q_word in question_words:
        if question_lower.startswith(q_word):
            clean_q = question_lower.replace(q_word, "", 1).strip()
            if clean_q and clean_q not in queries:
                queries.append(clean_q)
    
    # 2. Create n-gram combinations of keywords
    if len(keywords) >= 2:
        for i in range(len(keywords)):
            for j in range(i+1, len(keywords)):
                bigram = f"{keywords[i]} {keywords[j]}"
                if bigram not in queries and len(bigram.split()) <= 3: # Limit to trigrams for brevity
                    queries.append(bigram)
    
    # 3. Add security-specific query variations (can be refined based on our Pinecone content)
    if any(term in question_lower for term in ["vulnerability", "security", "risk", "threat", "hack"]):
        if "high" in question_lower or "critical" in question_lower:
            queries.append("high severity vulnerability security risk")
        if "remediation" in question_lower or "solution" in question_lower or "fix" in question_lower:
            queries.append("vulnerability remediation solution fix best practices")
    
    # Deduplicate and keep order somewhat stable
    unique_queries = []
    seen_queries = set()
    for q in queries:
        if q not in seen_queries:
            unique_queries.append(q)
            seen_queries.add(q)
    
    print(f"Expanded queries: {unique_queries}")
    return unique_queries

def is_general_cybersecurity_question(question: str) -> bool:
    """Check if the user is asking a general cybersecurity question not specific to the Nmap report."""
    question_lower = question.lower()
    
    # General cybersecurity keywords
    cybersecurity_keywords = [
        "cybersecurity", "security best practices", "security policy", "cyber attack", 
        "phishing", "ransomware", "malware", "zero day", "firewall", "encryption", 
        "security framework", "compliance", "security standard", "penetration testing", 
        "security awareness", "data breach", "incident response", "security controls",
        "authentication", "authorization", "zero trust", "security posture", "threat actor",
        "social engineering", "mfa", "2fa", "access control", "security audit", "ddos", "dos",
        "vpn", "cloud security", "iot security", "secure coding", "devsecops", "threat intelligence",
        "sql injection", "xss", "cross-site scripting", "fin scan", "xmas scan", "tcp", "udp" # Added specific terms from your provided Chatbot.py context
    ]
    
    # Keywords typically found in Nmap reports or specific to Nmap scan findings
    nmap_report_specific_terms = [
        "nmap", "scan", "report", "host", "ip address", "port", "service", "os detection", 
        "traceroute", "latency", "mac address", "open port", "filtered port", "closed port",
        "script output", "version detection", "aggressive scan", "syn scan", "udp scan",
        "on the report", "in this report", "from this scan"
    ]
    
    # Check if general cybersecurity keywords are present
    contains_cyber_keywords = any(keyword in question_lower for keyword in cybersecurity_keywords)
    
    # Check if Nmap-specific keywords are absent or less prominent
    contains_nmap_keywords = any(term in question_lower for term in nmap_report_specific_terms)

    # Heuristics:
    # 1. If it contains general cyber keywords AND no strong Nmap keywords indicating report specificity.
    # 2. If it asks "what is X" where X is a general cyber concept (even if some Nmap terms are present in a mixed query, it leans general).
    # 3. If it contains a general cyber keyword AND mentions something from the loaded report (e.g., "what is SQL injection on port 80?").
    #    In this case, it's a mixed query and we want both contexts, so we'll treat it as general to ensure Pinecone is queried.
    
    # A question is general cybersecurity if:
    #   - It contains a general cybersecurity keyword AND does NOT contain strong Nmap report specific terms.
    #   - It asks "what is X" about a general cybersecurity topic, irrespective of Nmap terms.
    #   - It contains a general cybersecurity keyword AND also refers to an Nmap detail (this will result in a mixed query, but we ensure Pinecone is called).

    if contains_cyber_keywords:
        # If it's a "what is X" type question for a general cyber topic, it's general.
        if any(re.search(pattern, question_lower) for pattern in [
            r"what is (a|an|the)?\s*(phishing|ransomware|malware|sql injection|xss|ddos|firewall|encryption|vpn|mfa|zero trust|social engineering|fin scan|xmas scan|tcp|udp)",
            r"(explain|tell me about)\s*(phishing|ransomware|malware|sql injection|xss|ddos|firewall|encryption|vpn|mfa|zero trust|social engineering|fin scan|xmas scan|tcp|udp)"
        ]):
            return True
        
        # If it contains general cyber keywords and does not contain strong Nmap report specific terms
        if not contains_nmap_keywords:
            return True

    return False


def categorize_nmap_report_question(question: str) -> str:
    """
    Categorizes Nmap-report specific questions to guide context extraction and LLM response.
    Returns a specific category or "not_nmap_specific" if it's primarily general.
    """
    question_lower = question.lower()

    # Prioritize specific Nmap categories
    if "summary" in question_lower or "overview" in question_lower or "explain the report" in question_lower or "tell me about this report" in question_lower:
        return "report_summary"
    if "open ports" in question_lower or "which ports are open" in question_lower or ("ports" in question_lower and "open" in question_lower):
        return "open_ports"
    if "closed ports" in question_lower or "filtered ports" in question_lower:
        return "closed_filtered_ports"
    if "services" in question_lower or "what services" in question_lower:
        return "services_info"
    if "os" in question_lower or "operating system" in question_lower or "device type" in question_lower:
        return "os_info"
    if "vulnerability" in question_lower or "vulnerabilities" in question_lower or "security issues" in question_lower:
        return "vulnerability_info"
    if "how to fix" in question_lower or "remediation" in question_lower or "mitigate" in question_lower or "prevent" in question_lower or "secure" in question_lower:
        return "remediation_advice"
    if "target" in question_lower or "ip address" in question_lower or "hostname" in question_lower:
        return "target_info"
    if "scan type" in question_lower or "initiated" in question_lower or "timestamp" in question_lower or "duration" in question_lower or "nmap version" in question_lower:
        return "scan_metadata"
    if "traceroute" in question_lower or "hops" in question_lower:
        return "traceroute_info"
    if "latency" in question_lower or "speed" in question_lower:
        return "latency_info"
    if "mac address" in question_lower:
        return "mac_info"
    
    # If none of the specific Nmap categories match, consider if it's generally Nmap-related
    nmap_general_terms = ["nmap", "scan", "report", "host", "this report"]
    if any(term in question_lower for term in nmap_general_terms):
        return "general_nmap"
    
    return "not_nmap_specific" # Default when it doesn't seem directly Nmap-related

# === END: New/Modified functions from Chatbot.py for query enhancement ===


def format_chat_history(history: List[Dict[str, str]]) -> str:
    """Formats the chat history for inclusion in the LLM prompt."""
    formatted_history = []
    for turn in history:
        # Limit content length for history to prevent overwhelming LLM
        content_preview = turn['content'][:200] + "..." if len(turn['content']) > 200 else turn['content']
        formatted_history.append(f"{turn['role'].capitalize()}: {content_preview}")
    return "\n".join(formatted_history)

def answer_query_about_report(user_query: str, current_chat_history: List[Dict[str, str]]) -> str:
    """
    Answers a user query by combining relevant information from the Nmap report
    and the Pinecone knowledge base, then uses the LLM to synthesize the response.

    Args:
        user_query (str): The question from the user.
        current_chat_history (List[Dict[str, str]]): The recent history of the conversation.

    Returns:
        str: The LLM-generated answer.
    """
    global current_loaded_report_data, llm_instance

    if not load_llm_once():
        return "Sorry, the main language model is not loaded. Please try again later."

    all_context_snippets = []
    user_query_lower = user_query.lower()

    # --- Step 1: Attempt to answer directly from Nmap Report data first (if loaded) ---
    nmap_metadata_info = current_loaded_report_data.get('scan_metadata') if current_loaded_report_data else None
    
    direct_nmap_metadata_map = {}
    if nmap_metadata_info:
        direct_nmap_metadata_map = {
            "target ip address": nmap_metadata_info.get('target_ip'),
            "target": nmap_metadata_info.get('target'),
            "scan type": nmap_metadata_info.get('scan_type'),
            "initiated by": nmap_metadata_info.get('scan_initiated_by'),
            "timestamp": nmap_metadata_info.get('timestamp'),
            "nmap version": nmap_metadata_info.get('nmap_version'),
            "duration": nmap_metadata_info.get('scan_duration'),
        }
        if current_loaded_report_data and current_loaded_report_data.get('hosts'):
            primary_host = current_loaded_report_data['hosts'][0] 
            direct_nmap_metadata_map["rdns record"] = primary_host.get('rdns')
            direct_nmap_metadata_map["mac address"] = primary_host.get('mac_address')
            direct_nmap_metadata_map["latency"] = primary_host.get('latency')

    found_direct_nmap_answer = False
    for phrase, value in direct_nmap_metadata_map.items():
        if value and isinstance(value, str) and value.strip() != 'N/A' and phrase in user_query_lower:
            direct_answer_text = f"The Nmap report states the {phrase} is: {value}."
            print(f"--- Direct Nmap Answer Found for '{phrase}' ---")
            print(direct_answer_text)
            print("------------------------------------------")
            
            concise_system_prompt = "You are a helpful assistant. Provide the factual answer directly based on the provided Nmap snippet. Do not add extra commentary. If the snippet doesn't contain the direct answer, state so concisely."
            concise_user_prompt = f"Nmap Snippet: {direct_answer_text}\n\nUser Question: {user_query}"
            concise_full_prompt = f"<s>[INST] {concise_system_prompt}\n\n{concise_user_prompt} [/INST]"

            print("\n--- Concise Prompt for Direct Nmap Answer ---")
            print(concise_full_prompt)
            print("------------------------------------------\n")

            try:
                final_answer = generate_response(llm_instance, concise_full_prompt, max_tokens=100) 
                if final_answer and final_answer.strip() != '' and "cannot answer" not in final_answer.lower():
                    return final_answer
            except Exception as e:
                print(f"Error generating direct Nmap answer: {e}")
            
            found_direct_nmap_answer = True
            break 

    # If a direct Nmap answer was found and successfully returned by the LLM, we exit.
    if found_direct_nmap_answer:
        return "" # If direct answer was attempted but LLM didn't return (handled by fallback earlier)


    # --- Step 2: Extract broader Nmap context (if relevant) and Always retrieve from Pinecone ---
    
    nmap_question_category = categorize_nmap_report_question(user_query)
    is_general_cyber_q = is_general_cybersecurity_question(user_query)
    
    print(f"Nmap question category: {nmap_question_category}")
    print(f"Is general cybersecurity question: {is_general_cyber_q}")

    # Determine if Nmap context is needed beyond direct answers
    # Nmap context is needed if it's an Nmap-specific category OR if it's a mixed query (general cyber + Nmap terms)
    is_nmap_context_needed = (nmap_question_category != "not_nmap_specific") or \
                             (is_general_cyber_q and any(term in user_query_lower for term in ["port", "host", "ip address", "service", "report"]))

    if current_loaded_report_data and is_nmap_context_needed:
        print("Attempting to extract broader relevant snippets from Nmap report.")
        
        if nmap_metadata_info:
            raw_target = nmap_metadata_info.get('target')
            target_str_meta = raw_target if isinstance(raw_target, str) else 'N/A'
            raw_target_ip = nmap_metadata_info.get('target_ip')
            target_ip_str_meta = raw_target_ip if isinstance(raw_target_ip, str) else 'N/A'

            metadata_summary = (
                f"Scan Type: {nmap_metadata_info.get('scan_type', 'N/A')}\n"
                f"Initiated By: {nmap_metadata_info.get('scan_initiated_by', 'N/A')}\n"
                f"Timestamp: {nmap_metadata_info.get('timestamp', 'N/A')}\n"
                f"Target: {target_str_meta} (IP: {target_ip_str_meta})\n"
                f"Nmap Version: {nmap_metadata_info.get('nmap_version', 'N/A')}\n"
                f"Duration: {nmap_metadata_info.get('scan_duration', 'N/A')}"
            )
            all_context_snippets.append("--- Nmap Scan Report Snippets (General Overview) ---\n" + metadata_summary)
            
        relevant_hosts_data = []
        target_in_query = None
        ip_or_hostname_pattern = r'\b(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,6})\b'
        target_match_in_query = re.search(ip_or_hostname_pattern, user_query_lower)
        if target_match_in_query:
            target_in_query = target_match_in_query.group(0)

        if target_in_query:
            for host in current_loaded_report_data.get('hosts', []):
                if target_in_query in host.get('ip_address', '').lower() or \
                   target_in_query in host.get('hostname', '').lower():
                    relevant_hosts_data.append(host)
        elif current_loaded_report_data.get('hosts'):
            primary_target_from_metadata_val = nmap_metadata_info.get('target') if nmap_metadata_info else None
            primary_target_from_metadata = primary_target_from_metadata_val.lower() if isinstance(primary_target_from_metadata_val, str) else ''
            
            found_primary_host = False
            for host in current_loaded_report_data['hosts']:
                host_ip_lower = host.get('ip_address', '').lower()
                host_hostname_lower = host.get('hostname', '').lower()
                if primary_target_from_metadata and (primary_target_from_metadata in host_ip_lower or primary_target_from_metadata in host_hostname_lower):
                    relevant_hosts_data.append(host)
                    found_primary_host = True
                    break
            if not found_primary_host and current_loaded_report_data['hosts']:
                relevant_hosts_data = [current_loaded_report_data['hosts'][0]]


        for host in relevant_hosts_data:
            host_identifier = host.get('hostname', host.get('ip_address', 'Unknown Host'))
            host_summary_line = f"Host: {host_identifier} (IP: {host.get('ip_address', 'N/A')})"
            
            host_specific_snippets = []

            # Extract info based on category
            # Always include ports if the query is for report_summary, open_ports, services_info, or general_nmap
            if nmap_question_category in ["report_summary", "open_ports", "services_info", "general_nmap"] and host.get('ports'):
                ports_info = []
                for port in host['ports']:
                    ports_info.append(f"  Port: {port['port_id']}/{port['protocol']}, State: {port['state']}, Service: {port['service']}, Version: {port['version']}")
                    if port.get('script_outputs'):
                        for script_name, script_output in port['script_outputs'].items():
                            script_truncated = script_output.splitlines()[0][:150] + "..." if len(script_output.splitlines()[0]) > 150 else script_output
                            ports_info.append(f"    Script ({script_name}): {script_truncated}")
                if ports_info:
                    host_specific_snippets.append(f"{host_summary_line}\nOpen/Filtered Ports:\n" + "\n".join(ports_info))
            
            # Include OS info based on category
            if nmap_question_category in ["os_info", "report_summary", "general_nmap"] and host.get('os_detection') and (host['os_detection'].get('os_guesses') or host['os_detection'].get('device_type')):
                os_info = []
                if host['os_detection'].get('device_type'):
                    os_info.append(f"  Device Type: {', '.join(host['os_detection']['device_type'])}")
                if host['os_detection'].get('os_guesses'):
                    os_info.append(f"  OS Guesses: {', '.join(host['os_detection']['os_guesses'])}")
                if host['os_detection'].get('aggressive_os_guesses'):
                    os_info.append(f"  Aggressive OS Guesses: {', '.join(host['os_detection']['aggressive_os_guesses'])}")
                if os_info:
                    host_specific_snippets.append(f"{host_summary_line}\nOS Detection:\n" + "\n".join(os_info))

            # Include Traceroute info based on category
            if nmap_question_category in ["traceroute_info", "general_nmap"] and host.get('traceroute'):
                trace_info = [f"  Hop {h['hop']}: {h['rtt']} to {h['address']}" for h in host['traceroute']]
                if trace_info:
                    host_specific_snippets.append(f"{host_summary_line}\nTraceroute:\n" + "\n".join(trace_info))

            # Other specific host details
            if nmap_question_category in ["latency_info", "general_nmap"] and host.get('latency'):
                host_specific_snippets.append(f"{host_summary_line}\nLatency: {host['latency']}")
            if nmap_question_category in ["rdns_info", "general_nmap"] and host.get('rdns'):
                host_specific_snippets.append(f"{host_summary_line}\nrDNS Record: {host['rdns']}")
            if nmap_question_category in ["mac_info", "general_nmap"] and host.get('mac_address'):
                host_specific_snippets.append(f"{host_summary_line}\nMAC Address: {host['mac_address']}")

            if host_specific_snippets:
                if not any("--- Nmap Scan Report Snippets (Host Details) ---" in s for s in all_context_snippets):
                    all_context_snippets.append("\n--- Nmap Scan Report Snippets (Host Details) ---")
                all_context_snippets.extend(host_specific_snippets)

        if all_context_snippets: # Check if any Nmap snippets were added
            print(f"Nmap report snippets extracted. Total size: {len('\n'.join(all_context_snippets))} characters.")
        else:
            print("No relevant Nmap report snippets extracted for this query after initial check.")

    # --- Step 3: Always retrieve relevant information from Pinecone ---
    # This ensures general cybersecurity questions are always answered from the KB,
    # and also supplements Nmap report questions with general cybersecurity knowledge.
    print("Attempting to retrieve information from Pinecone knowledge base.")
    
    # Use expanded queries for Pinecone retrieval
    expanded_user_queries = expand_query(user_query)
    
    all_pinecone_results = []
    for query_variant in expanded_user_queries:
        is_mitigation_query = any(k in query_variant.lower() for k in ["how to", "prevent", "mitigate", "close", "secure", "fix", "remediation", "solution"])
        is_port_scanning_related_pinecone = any(k in query_variant.lower() for k in ["port", "scan", "tcp", "udp", "syn", "stealth", "firewall", "vulnerability"])
        
        pinecone_top_k = 7 if is_mitigation_query or is_port_scanning_related_pinecone else 5 

        results_for_variant = retrieve_from_pinecone(query_variant, top_k=pinecone_top_k)
        all_pinecone_results.extend(results_for_variant)

    # Deduplicate Pinecone results by question/answer pair to avoid redundancy
    unique_pinecone_results = []
    seen_qa_pairs = set()
    for res in all_pinecone_results:
        qa_hash = (res.get('question', ''), res.get('answer', ''))
        if qa_hash not in seen_qa_pairs:
            unique_pinecone_results.append(res)
            seen_qa_pairs.add(qa_hash)
    
    # Sort unique Pinecone results by score
    unique_pinecone_results.sort(key=lambda x: x['score'], reverse=True)
    pinecone_results = unique_pinecone_results[:7] # Limit overall Pinecone results to top 7 after deduplication

    if pinecone_results:
        pinecone_context_items = []
        for item in pinecone_results:
            if item.get('question') and item.get('answer') and \
               item.get('question').strip() != 'N/A' and item.get('answer').strip() != 'N/A':
                pinecone_context_items.append(
                    f"Question: {item['question']}\n"
                    f"Answer: {item['answer']}\n"
                    f"Source File: {item['source_file']} (Category: {item['top_level_category']})"
                )
                if item.get('related_topics') != 'N/A' and item.get('related_topics'):
                    pinecone_context_items[-1] += f" | Related Topics: {item['related_topics']}"

        if pinecone_context_items:
            all_context_snippets.append("\n--- Cybersecurity Knowledge Base Snippets (Pinecone) ---")
            all_context_snippets.extend(pinecone_context_items)
            print(f"Pinecone KB snippets retrieved. Total size: {len('\n'.join(pinecone_context_items))} characters.")
        else:
            print("No *usable* Pinecone KB snippets retrieved for this query.")
    else:
        print("No relevant Pinecone KB snippets retrieved for this query.")


    # --- Step 4: Combine all contexts for the LLM prompt ---
    context_for_llm = "\n\n".join(all_context_snippets)

    # --- Format Chat History ---
    formatted_history_str = format_chat_history(current_chat_history)
    if formatted_history_str:
        formatted_history_str = "\n\nPrevious Conversation:\n" + formatted_history_str + "\n"

    # --- Construct the LLM Prompt ---
    system_instruction = (
        "You are a highly skilled cybersecurity analyst and an expert in Nmap reports and general cybersecurity. "
        "Your primary goal is to provide accurate, concise, and actionable answers to user queries. "
        "Always respond in markdown format. "
        "You have access to information from the following sources:\n"
        "1. A structured Nmap scan report (if provided in '--- Nmap Scan Report Snippets ---' section).\n"
        "2. A unified cybersecurity knowledge base (if provided in '--- Cybersecurity Knowledge Base Snippets (Pinecone) ---' section).\n\n"
        "Synthesize information from *all provided contexts* to answer the user's question comprehensively. "
        "Prioritize factual data directly from the Nmap report when explicitly asked about specific report details. "
        "If the question is general cybersecurity knowledge or asks for 'how to', 'prevent', 'mitigate', 'close', 'secure', or 'fix', "
        "leverage the cybersecurity knowledge base snippets to provide detailed, actionable steps and recommendations. "
        "Do not fabricate information. If information is not explicitly available in *any* provided context (Nmap or Pinecone), "
        "then provide a concise answer based on your general cybersecurity knowledge. Clearly state if the answer is based on general knowledge and not from the provided context."
    )

    user_prompt_content = f"User Query: {user_query}\n\n"

    if context_for_llm:
        user_prompt_content = f"Here is the relevant context:\n```\n{context_for_llm}\n```\n\n" + user_prompt_content
    else:
        # Explicit instruction to use general knowledge if no specific context is found
        user_prompt_content = "No specific context found from the loaded Nmap report or external knowledge base for your query. Please answer based on your general cybersecurity knowledge.\n" + user_prompt_content


    # Combine history, system instruction, and user prompt content
    full_prompt = f"<s>[INST] {system_instruction}"
    if formatted_history_str:
        full_prompt += f"\n{formatted_history_str}"
    full_prompt += f"\n\n{user_prompt_content} [/INST]"

    # Debugging: Print the full prompt before sending to LLM
    print("\n--- Full Prompt Sent to LLM ---")
    print(full_prompt)
    print("--------------------------------\n")

    # Step 5: Generate a response from the LLM
    print("[+] LLM is generating response... Please wait.") # Loading indicator
    try:
        answer = generate_response(llm_instance, full_prompt, max_tokens=1500)
        print("[+] LLM response generated.") # Completion indicator
        
        # --- Fallback for empty/whitespace answer (only if LLM truly failed to generate anything) ---
        if not answer or answer.strip() == '':
            print("[!] LLM returned an empty or whitespace-only response. Providing a generic fallback.")
            return "I'm sorry, I couldn't generate a response for your query at this moment. There might have been an internal issue with the language model."

        return answer
    except Exception as e:
        print(f"Error generating LLM response for query: {e}")
        return "Sorry, I encountered an error while trying to answer your question due to an internal error."


def process_and_summarize_report(pdf_path: str) -> Optional[str]:
    """
    Processes a given Nmap PDF report and generates an initial summary using the LLM.

    Args:
        pdf_path (str): The full path to the Nmap PDF report.

    Returns:
        Optional[str]: The LLM-generated summary, or None if processing fails.
    """
    global current_loaded_report_data, llm_instance

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

    if not load_llm_once():
        print("LLM is not loaded. Cannot generate summary.")
        return None

    # Step 3: Craft a prompt for the LLM based on the structured data
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

    # Step 4: Generate a response from the LLM
    print("--- Generating summary with LLM ---")
    print("[+] LLM is generating summary... Please wait.") # Loading indicator
    try:
        summary = generate_response(llm_instance, prompt, max_tokens=1000)
        print("[+] LLM summary generated.") # Completion indicator
        # Ensure summary is actually generated, if not, return None to trigger error handling
        if not summary or summary.strip() == '':
            return None
        return summary
    except Exception as e:
        print(f"Error generating LLM summary: {e}")
        return None

def print_header():
    """Print a clean header for the application."""
    print("\n" + "=" * 70)
    print("      Nmap Report Analyzer & Cybersecurity Assistant")
    print("=" * 70)

def print_section(title):
    """Print a section header."""
    print(f"\n{' ' + title + ' ':-^70}")

def print_help():
    """Display help information."""
    print_section("HELP")
    print("  Commands:")
    print("  - new report : Load a different Nmap report")
    print("  - help       : Show this help message")
    print("  - exit       : Exit the application")
    print("\n  Ask questions about the loaded Nmap report or general cybersecurity topics.")

def main_cli_interface():
    """
    Provides a clean command-line interface for uploading and summarizing Nmap reports,
    with improved readability and user experience.
    """
    global chat_history, current_loaded_report_data 
    
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
            
            # Handle empty input explicitly
            if not user_input:
                print("[!] Please enter a valid command, PDF path, or a question.")
                continue
                
            # Check if the input is a command that clears the report or a file path
            if user_input.lower() == 'new report' or user_input.lower().endswith('.pdf'):
                pdf_file_path_input = ""
                if user_input.lower() == 'new report':
                    print("\n[+] Initiating new report upload...")
                    current_loaded_report_data = None # Clear previous report data
                    chat_history.clear() # Clear chat history for new report
                    pdf_file_path_input = input("\n[?] Enter PDF report path: ").strip()
                else: # It's a direct PDF path input
                    pdf_file_path_input = user_input

                # Resolve the full path
                reports_dir = os.path.join(project_root_dir, "documents")
                # Use os.path.join with reports_dir and then os.path.basename of pdf_file_path_input
                # to handle cases where user pastes a full path vs just a filename
                pdf_file_path = os.path.join(reports_dir, os.path.basename(pdf_file_path_input))

                if not os.path.isfile(pdf_file_path):
                    print(f"Error: No file found at '{pdf_file_path}'. Please check the path and try again.")
                    continue
                if not pdf_file_path.lower().endswith('.pdf'):
                    print(f"Error: '{pdf_file_path}' is not a PDF file. Please provide a PDF.")
                    continue

                print(f"Loading and analyzing report: {os.path.basename(pdf_file_path)}")
                summary = process_and_summarize_report(pdf_file_path)
                
                if summary:
                    print_section("REPORT SUMMARY")
                    print(summary)
                    chat_history.append({"role": "model", "content": summary}) # Add summary to history
                    print_section("INTERACTIVE ANALYSIS")
                    print("Report loaded. You can now ask questions about this report or general cybersecurity topics.")
                    print("Type 'new report' to analyze a different scan or 'exit' to quit.\n")
                else:
                    print("\n[!] Failed to process the report. Please check the file and try again.")
                # After trying to load a report, regardless of success, continue to the next iteration
                # to allow the user to ask questions or load another report.
                continue 

            # If we reach here, it means the input was not a file path or 'new report'
            # So, it must be a question or an unrecognized command
            
            if current_loaded_report_data is None:
                print("[!] No Nmap report is currently loaded. Please load a report first (e.g., enter its PDF path).")
                continue

            # It's a question about the loaded report or general cybersecurity
            user_question = user_input
            chat_history.append({"role": "user", "content": user_question}) # Add user question to history
            
            # Trim history to maintain context window limits
            if len(chat_history) > MAX_CHAT_HISTORY_TURNS * 2: # Max turns * 2 (user + model per turn)
                chat_history = chat_history[-(MAX_CHAT_HISTORY_TURNS * 2):]

            print("\n[+] Analyzing your question...")
            answer = answer_query_about_report(user_question, chat_history)
            
            print("\n[+] Analysis Results:")
            print("-" * 70)
            print(answer)
            print("-" * 70)
            chat_history.append({"role": "model", "content": answer}) # Add model response to history
                
        except KeyboardInterrupt:
            print("\n[!] Operation cancelled. Type 'exit' to quit or enter a file path/command.")
        except Exception as e:
            print(f"\n[!] An error occurred: {str(e)}")
            import traceback
            traceback.print_exc() # Print full traceback for debugging

def cleanup():
    """Cleanup function to properly close resources."""
    global llm_instance
    if llm_instance is not None:
        try:
            # Properly close the language model instance if it has a close method
            if hasattr(llm_instance, 'close') and callable(getattr(llm_instance, 'close')):
                llm_instance.close()
            llm_instance = None
        except Exception as e:
            print(f"Error during cleanup: {e}")

def main():
    try:
        # Ensure local LLM and semantic search model/Pinecone are ready
        print("Initializing components...")
        llm_ready = load_llm_once()
        semantic_model_ready = load_semantic_model_once()
        pinecone_ready = initialize_pinecone_client_once()

        if not llm_ready:
            print("Cannot start application without the local LLM. Please check configuration and model files.")
            return 1
        
        if not (semantic_model_ready and pinecone_ready):
            print("Warning: Semantic search (Pinecone) components could not be fully loaded. "
                  "General cybersecurity questions might not be as effective, but Nmap report analysis will still work.")
            # We don't exit here, as the core Nmap analysis with LLM is still possible.

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
