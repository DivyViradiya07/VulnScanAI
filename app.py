import os
import sys
import json
from typing import Dict, Any, List, Optional
import atexit

# --- Import RAG components for type hinting ---
try:
    from sentence_transformers import SentenceTransformer
    from pinecone import Index # Only import Index class for type hinting, not the main Pinecone class
except ImportError:
    # Dummy classes for type hinting if libraries are not installed yet
    class SentenceTransformer:
        def __init__(self, *args, **kwargs): pass
    class Index:
        def __init__(self, *args, **kwargs): pass


# Ensure the 'chatbot_modules' directory is in the Python path for module imports
current_dir = os.path.dirname(os.path.abspath(__file__))
# Add the 'chatbot_modules' directory to sys.path
chatbot_modules_path = os.path.join(current_dir, "chatbot_modules")
if chatbot_modules_path not in sys.path:
    sys.path.insert(0, chatbot_modules_path)

# Import core modules from chatbot_modules
try:
    # Import configuration settings
    from chatbot_modules import config # Import the config module

    from local_llm import load_model, generate_response
    from nmap_parser import process_nmap_report_file
    from zap_parser import process_zap_report_file
    from ssl_parser import process_sslscan_report_file # New import for SSLScan parser
    from summarizer import summarize_report_with_llm, summarize_chat_history_segment
    from pdf_extractor import extract_text_from_pdf
    # Import RAG utilities
    from utils import (
        load_embedding_model, 
        initialize_pinecone_index, 
        retrieve_rag_context, 
        load_report_chunks_and_embeddings, 
        retrieve_internal_rag_context, 
        delete_report_namespace 
    )
except ImportError as e:
    print(f"Error importing a module: {e}")
    print("Please ensure all modules (local_llm.py, nmap_parser.py, zap_parser.py, sslscan_parser.py, pdf_extractor.py, summarizer.py, chatbot_utils.py, config.py) are located within the 'chatbot_modules' directory and correctly configured in your Python path.")
    sys.exit(1)

# --- Configuration for Local LLM (now from config.py) ---
MODEL_ID = config.LLM_MODEL_ID
MODEL_BASENAME = config.LLM_MODEL_BASENAME
MODEL_DIR = config.LLM_MODEL_DIR 

# --- Global Variables for Chatbot State (Initialized once) ---
llm_instance = None
current_parsed_report: Optional[Dict[str, Any]] = None
current_report_type: Optional[str] = None
current_report_namespace: Optional[str] = None 
chat_history: List[Dict[str, str]] = [] # Initialized as an empty list here

# Global variables for RAG components
_embedding_model_instance: Optional[SentenceTransformer] = None
_pinecone_index_instance: Optional[Index] = None


def load_llm_model_once():
    """Loads the LLM model only if it hasn't been loaded yet."""
    global llm_instance
    if llm_instance is None:
        try:
            from local_llm import load_model
            llm_instance = load_model(
                model_id=config.LLM_MODEL_ID,
                model_basename=config.LLM_MODEL_BASENAME,
                local_dir=config.LLM_MODEL_DIR
            )
            # Register cleanup function
            atexit.register(cleanup_llm)
        except Exception as e:
            print(f"Error loading language model: {e}")
            sys.exit(1)
    return llm_instance

def cleanup_llm():
    """Clean up the LLM instance on program exit."""
    global llm_instance
    if llm_instance is not None:
        try:
            # Properly clean up the model instance
            if hasattr(llm_instance, 'close'):
                llm_instance.close()
            llm_instance = None
        except Exception as e:
            # Ignore errors during cleanup
            pass

def load_rag_components_once():
    """Loads the SentenceTransformer model and initializes Pinecone index only if not loaded yet."""
    global _embedding_model_instance, _pinecone_index_instance
    if _embedding_model_instance is None:
        try:
            _embedding_model_instance = load_embedding_model()
        except Exception as e:
            print(f"Failed to load embedding model for RAG: {e}")
            _embedding_model_instance = None
    
    if _pinecone_index_instance is None and _embedding_model_instance is not None:
        try:
            _pinecone_index_instance = initialize_pinecone_index()
        except Exception as e:
            print(f"Failed to initialize Pinecone index for RAG: {e}")
            _pinecone_index_instance = None


def reset_chat_context():
    """Resets the parsed report and chat history for a new report."""
    global current_parsed_report, current_report_type, current_report_namespace, chat_history
    # Delete the old report's namespace if it exists
    if current_report_namespace:
        delete_report_namespace(current_report_namespace)
    
    current_parsed_report = None
    current_report_type = None
    current_report_namespace = None # Reset the namespace
    chat_history = [] # Clear history for new report

def detect_report_type(pdf_path: str) -> Optional[str]:
    """
    Attempts to detect the type of the security report (Nmap, ZAP, or SSLScan)
    by reading a small portion of its text and looking for keywords.

    Args:
        pdf_path (str): The path to the PDF file.

    Returns:
        Optional[str]: "nmap", "zap", "sslscan", or None if detection fails.
    """
    try:
        raw_text = extract_text_from_pdf(pdf_path)
        lower_text = raw_text.lower()

        nmap_keywords = ["nmap scan report for", "starting nmap", "port state service", "network distance", "traceroute"]
        if any(keyword in lower_text for keyword in nmap_keywords):
            return "nmap"

        zap_keywords = ["checkmarx zap report", "zap version:", "alert detail", "summary of alerts", "risk level", "cwe id"]
        if any(keyword in lower_text for keyword in zap_keywords):
            return "zap"
        
        # New keywords for SSLScan
        sslscan_keywords = ["ssl/tls vulnerability scan report", "ssl/tls protocols:", "supported server cipher(s):", "ssl certificate:"]
        if any(keyword in lower_text for keyword in sslscan_keywords):
            return "sslscan"

        return None
    except Exception as e:
        print(f"Error during report type detection: {e}")
        return None

def is_report_specific_question(question: str, report_data: Dict[str, Any]) -> bool:
    """
    Heuristically determines if a question is specific to the loaded Nmap/ZAP/SSLScan report.
    This check is performed only if a report is currently loaded.
    """
    if not report_data:
        return False # Cannot be report-specific if no report is loaded

    question_lower = question.lower()

    # Use keywords from config.py
    if any(keyword in question_lower for keyword in config.REPORT_SPECIFIC_KEYWORDS):
        return True

    # More specific checks using data from the loaded report
    report_tool = report_data.get("scan_metadata", {}).get("tool", "").lower()

    if "nmap" in report_tool:
        for host in report_data.get("hosts", []):
            if host.get("ip_address") and host["ip_address"].lower() in question_lower:
                return True
            if host.get("hostname") and host["hostname"].lower() in question_lower:
                return True
            for port in host.get("ports", []):
                if f"port {port.get('port_id')}" in question_lower or f":{port.get('port_id')}" in question_lower:
                    return True
                if port.get("service") and port["service"].lower() in question_lower:
                    return True

    elif "zap" in report_tool:
        for vuln in report_data.get("vulnerabilities", []):
            if vuln.get("name") and vuln["name"].lower() in question_lower:
                return True
            if vuln.get("cwe_id") and f"cwe {vuln['cwe_id']}" in question_lower:
                return True
            if vuln.get("wasc_id") and f"wasc {vuln['wasc_id']}" in question_lower:
                return True
            if vuln.get("risk") and vuln["risk"].lower() in question_lower: # e.g., "high risk vulnerabilities"
                return True
            for url_detail in vuln.get("urls", []):
                if url_detail.get("url") and url_detail["url"].lower() in question_lower:
                    # Check if the full URL or parts of it are in the question
                    if url_detail["url"].lower() in question_lower or \
                       url_detail["url"].split('//')[-1].split('/')[0].lower() in question_lower:
                        return True
    
    # New checks for SSLScan
    elif "sslscan" in report_tool:
        ssl_metadata = report_data.get("scan_metadata", {})
        if ssl_metadata.get("target_host") and ssl_metadata["target_host"].lower() in question_lower:
            return True
        if ssl_metadata.get("connected_ip") and ssl_metadata["connected_ip"].lower() in question_lower:
            return True
        if ssl_metadata.get("sni_name") and ssl_metadata["sni_name"].lower() in question_lower:
            return True
        
        # Check for protocols, ciphers, certificate details
        if any(p.get("name", "").lower() in question_lower for p in report_data.get("protocols", [])):
            return True
        if any(c.get("name", "").lower() in question_lower for c in report_data.get("supported_ciphers", [])):
            return True
        if report_data.get("ssl_certificate", {}).get("subject", "").lower() in question_lower:
            return True
        if report_data.get("ssl_certificate", {}).get("issuer", "").lower() in question_lower:
            return True
        if "tls" in question_lower or "ssl" in question_lower or "cipher" in question_lower or "certificate" in question_lower:
            return True


    return False


def main_cli_loop():
    """
    Main loop for the command-line interface of the chatbot.
    Handles file upload, parsing, initial summary, and interactive chat.
    """
    # Declare global variables that will be reassigned within this function
    global chat_history 
    
    print("--- Welcome to the Security Report Chatbot (CLI Version) ---")
    print("Enter 'exit' or 'quit' at any time to end the session.")
    print("Enter 'new_report' to process another PDF.")

    llm_instance = load_llm_model_once()
    load_rag_components_once() # Load RAG components at startup

    try: # Start of try block for controlled LLM shutdown
        while True:
            report_path = input("\nPlease enter the path to your Nmap, ZAP, or SSLScan PDF report: ").strip()
            if report_path.lower() in ['exit', 'quit']:
                break
            if report_path.lower() == 'new_report':
                reset_chat_context() 
                continue

            if not os.path.exists(report_path):
                print(f"Error: File not found at '{report_path}'. Please check the path and try again.")
                continue
            if not report_path.lower().endswith(".pdf"):
                print("Error: Only PDF files are supported. Please provide a .pdf file.")
                continue

            # --- Report Type Auto-Detection ---
            print("\n--- Detecting report type... ---")
            report_type = detect_report_type(report_path)

            if report_type is None:
                print("Could not automatically detect report type. Please ensure it's a valid Nmap, ZAP, or SSLScan PDF report.")
                continue # Ask for a new report path
            
            print(f"Detected report type: {report_type.upper()}")

            print(f"\n--- Processing {report_type.upper()} report from '{report_path}' ---")

            parsed_data = None
            try:
                if report_type.lower() == 'nmap':
                    parsed_data = process_nmap_report_file(report_path)
                elif report_type.lower() == 'zap':
                    parsed_data = process_zap_report_file(report_path)
                elif report_type.lower() == 'sslscan': # New call for SSLScan parser
                    parsed_data = process_sslscan_report_file(report_path)
                
                if parsed_data:
                    global current_parsed_report, current_report_type, current_report_namespace
                    current_parsed_report = parsed_data
                    current_report_type = report_type.lower()
                    print(f"Successfully parsed {report_type.upper()} report.")

                    # --- Load report chunks and upsert to temporary Pinecone namespace ---
                    # The current_report_namespace is now managed as an in-memory list in utils.py
                    # load_report_chunks_and_embeddings now returns the list of chunks with embeddings
                    if _embedding_model_instance and _pinecone_index_instance:
                        print("\n--- Loading report data into temporary Pinecone namespace... ---")
                        # The return type of load_report_chunks_and_embeddings changed
                        # We still need a namespace to query within Pinecone, so let's stick to the current design
                        current_report_namespace = load_report_chunks_and_embeddings(parsed_data, report_type)
                        if current_report_namespace:
                            print(f"Report data loaded into namespace: {current_report_namespace}")
                        else:
                            print("Failed to load report data into Pinecone namespace.")
                    else:
                        print("RAG components (embedding model or Pinecone) not available. Cannot load report data into Pinecone.")

                else:
                    print(f"Failed to parse {report_type.upper()} report. No data returned.")
                    continue
            except Exception as e:
                print(f"An error occurred during parsing or loading into Pinecone: {e}")
                import traceback
                traceback.print_exc()
                continue

            # --- Generate Initial Summary and Remediation Steps ---
            if current_parsed_report and llm_instance:
                print("\n--- Generating initial report summary and remediation steps... ---")
                initial_summary = summarize_report_with_llm(llm_instance, current_parsed_report, current_report_type)
                print("\n--- Report Analysis ---")
                print(initial_summary)
                chat_history.append({"role": "assistant", "content": initial_summary})
            else:
                print("Could not generate initial summary. Parsed data or LLM not available.")
                continue

            # --- Interactive Chat Loop ---
            print("\n--- You can now ask questions about the report or general cybersecurity topics. ---")
            print("Type 'new_report' to upload another PDF, or 'exit' to quit.")

            while True:
                user_question = input("\nYour question: ").strip()
                if user_question.lower() in ['exit', 'quit']:
                    print("Exiting chat. Goodbye!")
                    return
                if user_question.lower() == 'new_report':
                    reset_chat_context() 
                    break

                chat_history.append({"role": "user", "content": user_question})
                print("Thinking...")

                # --- Chat History Management (Sliding Window) ---
                # Check if history needs summarization
                if len(chat_history) > config.CHAT_HISTORY_MAX_TURNS:
                    print(f"--- Chat history exceeding {config.CHAT_HISTORY_MAX_TURNS} turns. Summarizing older segments. ---")
                    
                    # Determine the segment to summarize (all turns except the last N recent ones)
                    segment_to_summarize = chat_history[0 : len(chat_history) - config.CHAT_HISTORY_SUMMARIZE_THRESHOLD]
                    
                    if segment_to_summarize:
                        summarized_segment_text = summarize_chat_history_segment(llm_instance, segment_to_summarize)
                        
                        # Create a new, condensed chat history
                        # This replaces the old segment with the summary and keeps the recent turns.
                        new_chat_history = [
                            {"role": "system", "content": f"Summary of previous conversation: {summarized_segment_text}"}
                        ]
                        # Append the recent turns that were not summarized
                        new_chat_history.extend(chat_history[len(chat_history) - config.CHAT_HISTORY_SUMMARIZE_THRESHOLD:])
                        
                        # Update the global chat_history
                        chat_history = new_chat_history
                        print("--- Chat history summarized. ---")
                    else:
                        print("--- No segment to summarize based on threshold. ---")


                llm_prompt_content = ""
                rag_context = ""

                # Determine question type and prepare context
                if current_parsed_report and is_report_specific_question(user_question, current_parsed_report):
                    print(" (Determined as report-specific question - attempting INTERNAL RAG)")
                    if current_report_namespace and _embedding_model_instance and _pinecone_index_instance:
                        rag_context = retrieve_internal_rag_context(user_question, current_report_namespace, top_k=config.DEFAULT_RAG_TOP_K)
                        if rag_context:
                            llm_prompt_content += f"Here is some relevant information from the current report:\n{rag_context}\n\n"
                        else:
                            llm_prompt_content += "No specific relevant information found in the current report for this query. "
                            print(" (No INTERNAL RAG context found for report-specific question)")
                    else:
                        llm_prompt_content += "Internal RAG components not available or report not loaded into Pinecone. Answering based on initial summary and general knowledge.\n"
                        print(" (Internal RAG not available for report-specific question)")
                    
                    llm_prompt_content += f"The user is asking a question related to the previously provided {current_report_type.upper()} security report."
                    llm_prompt_content += " Please refer to the report's content and your previous summary to answer.\n"
                else:
                    print(" (Determined as general cybersecurity question - attempting EXTERNAL RAG)")
                    if _embedding_model_instance and _pinecone_index_instance:
                        rag_context = retrieve_rag_context(user_question, top_k=config.DEFAULT_RAG_TOP_K, namespace="owasp-cybersecurity-kb") 
                        if rag_context:
                            llm_prompt_content += f"Here is some relevant information from a cybersecurity knowledge base:\n{rag_context}\n\n"
                        else:
                            llm_prompt_content += "No specific relevant information found in the knowledge base for this query. "
                            print(" (No EXTERNAL RAG context found)")
                    else:
                        llm_prompt_content += "RAG components not loaded or initialized. Answering based on general knowledge and chat history.\n"
                        print(" (RAG components not available for general question)")

                # Combine chat history with new context/instruction for the LLM
                # The chat_history list now potentially contains a 'system' summary message.
                concatenated_prompt = ""
                for msg in chat_history:
                    # Format roles correctly for LLM, especially the new 'system' role
                    if msg["role"] == "user":
                        concatenated_prompt += f"User: {msg['content']}\n"
                    elif msg["role"] == "assistant":
                        concatenated_prompt += f"Assistant: {msg['content']}\n"
                    elif msg["role"] == "system":
                        concatenated_prompt += f"System: {msg['content']}\n" # Include system message for LLM
                
                final_llm_prompt = f"{llm_prompt_content}\n{concatenated_prompt}\nAssistant:"

                try:
                    llm_response = generate_response(llm_instance, final_llm_prompt, max_tokens=config.DEFAULT_MAX_TOKENS)
                    
                    print(f"\nBot: {llm_response}")
                    chat_history.append({"role": "assistant", "content": llm_response})

                except Exception as e:
                    print(f"Error generating LLM response: {e}")
                    import traceback
                    traceback.print_exc()
                    if chat_history and chat_history[-1]["role"] == "user": # Ensure we pop user message if assistant failed
                        chat_history.pop()

    finally: # Ensure LLM model and Pinecone namespace are explicitly closed/deleted
        try:
            if current_report_namespace:
                delete_report_namespace(current_report_namespace)
            
            if 'llm_instance' in globals() and llm_instance is not None:
                print("\n--- Closing LLM model ---")
                try:
                    if hasattr(llm_instance, 'close') and callable(llm_instance.close):
                        if hasattr(llm_instance, '_model') and llm_instance._model is not None:
                            llm_instance.close()
                            print("LLM model closed successfully.")
                        else:
                            print("LLM model already closed or invalid.")
                    else:
                        print("LLM model does not have a close method.")
                except Exception as e:
                    print(f"Error during explicit LLM model closing: {e}")
                    import traceback
                    traceback.print_exc()
        except Exception as e:
            print(f"Error during cleanup: {e}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    try:
        main_cli_loop()
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        # Ensure cleanup happens even if there's an error
        cleanup_llm()
        sys.exit(0)
