import os
import sys
import json
from typing import Dict, Any, List, Optional

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
    from summarizer import summarize_report_with_llm
    from pdf_extractor import extract_text_from_pdf
    # Import RAG utilities
    from utils import (
        load_embedding_model, 
        initialize_pinecone_index, 
        retrieve_rag_context, 
        load_report_chunks_and_embeddings, # New import for internal RAG
        retrieve_internal_rag_context, # New import for internal RAG
        delete_report_namespace # New import for cleanup
    )
except ImportError as e:
    print(f"Error importing a module: {e}")
    print("Please ensure all modules (local_llm.py, nmap_parser.py, zap_parser.py, pdf_extractor.py, summarizer.py, chatbot_utils.py, config.py) are located within the 'chatbot_modules' directory and correctly configured in your Python path.")
    sys.exit(1)

# --- Configuration for Local LLM (now from config.py) ---
MODEL_ID = config.LLM_MODEL_ID
MODEL_BASENAME = config.LLM_MODEL_BASENAME
MODEL_DIR = config.LLM_MODEL_DIR # This path is built in config.py based on PROJECT_ROOT

# --- Global Variables for Chatbot State ---
llm_model = None
current_parsed_report: Optional[Dict[str, Any]] = None
current_report_type: Optional[str] = None
current_report_namespace: Optional[str] = None # New global variable for report's Pinecone namespace
chat_history: List[Dict[str, str]] = []

# Global variables for RAG components
_embedding_model_instance: Optional[SentenceTransformer] = None
_pinecone_index_instance: Optional[Index] = None


def load_llm_model_once():
    """Loads the LLM model only if it hasn't been loaded yet."""
    global llm_model
    if llm_model is None:
        print(f"\n--- Loading LLM model from {MODEL_DIR} ---")
        try:
            llm_model = load_model(MODEL_ID, MODEL_BASENAME, MODEL_DIR)
            print("LLM model loaded successfully.")
        except Exception as e:
            print(f"Failed to load LLM model: {e}")
            print("Please check your local_llm.py configuration, model ID, basename, and local directory.")
            sys.exit(1)
    return llm_model

def load_rag_components_once():
    """Loads the SentenceTransformer model and initializes Pinecone index only if not loaded yet."""
    global _embedding_model_instance, _pinecone_index_instance
    if _embedding_model_instance is None:
        try:
            _embedding_model_instance = load_embedding_model()
        except Exception as e:
            print(f"Failed to load embedding model for RAG: {e}")
            # Do not exit, allow general LLM interaction without RAG if RAG fails
            _embedding_model_instance = None
    
    if _pinecone_index_instance is None and _embedding_model_instance is not None:
        try:
            _pinecone_index_instance = initialize_pinecone_index()
        except Exception as e:
            print(f"Failed to initialize Pinecone index for RAG: {e}")
            # Do not exit, allow general LLM interaction without RAG if RAG fails
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
    Attempts to detect the type of the security report (Nmap or ZAP)
    by reading a small portion of its text and looking for keywords.

    Args:
        pdf_path (str): The path to the PDF file.

    Returns:
        Optional[str]: "nmap", "zap", or None if detection fails.
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

        return None
    except Exception as e:
        print(f"Error during report type detection: {e}")
        return None

def is_report_specific_question(question: str, report_data: Dict[str, Any]) -> bool:
    """
    Heuristically determines if a question is specific to the loaded Nmap/ZAP report.
    This check is performed only if a report is currently loaded.
    """
    if not report_data:
        return False # Cannot be report-specific if no report is loaded

    question_lower = question.lower()

    # Use keywords from config.py
    if any(keyword in question_lower for keyword in config.REPORT_SPECIFIC_KEYWORDS):
        return True

    # More specific checks using data from the loaded report
    report_type = report_data.get("scan_metadata", {}).get("scan_type") if "scan_metadata" in report_data else None
    tool_type = report_data.get("scan_metadata", {}).get("tool") if "scan_metadata" in report_data else None

    if report_type and ("nmap" in report_type.lower() or "nmap" in tool_type.lower() if tool_type else False): # Nmap specific checks
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

    elif tool_type and "zap" in tool_type.lower(): # ZAP specific checks
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
    
    return False


def main_cli_loop():
    """
    Main loop for the command-line interface of the chatbot.
    Handles file upload, parsing, initial summary, and interactive chat.
    """
    print("--- Welcome to the Security Report Chatbot (CLI Version) ---")
    print("Enter 'exit' or 'quit' at any time to end the session.")
    print("Enter 'new_report' to process another PDF.")

    llm_instance = load_llm_model_once()
    load_rag_components_once() # Load RAG components at startup

    try: # Start of try block for controlled LLM shutdown
        while True:
            report_path = input("\nPlease enter the path to your Nmap or ZAP PDF report: ").strip()
            if report_path.lower() in ['exit', 'quit']:
                break
            if report_path.lower() == 'new_report':
                reset_chat_context() # This now handles namespace deletion
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
                print("Could not automatically detect report type. Please ensure it's a valid Nmap or ZAP PDF report.")
                continue # Ask for a new report path
            
            print(f"Detected report type: {report_type.upper()}")

            print(f"\n--- Processing {report_type.upper()} report from '{report_path}' ---")

            parsed_data = None
            try:
                if report_type.lower() == 'nmap':
                    parsed_data = process_nmap_report_file(report_path)
                elif report_type.lower() == 'zap':
                    parsed_data = process_zap_report_file(report_path)
                
                if parsed_data:
                    global current_parsed_report, current_report_type, current_report_namespace
                    current_parsed_report = parsed_data
                    current_report_type = report_type.lower()
                    print(f"Successfully parsed {report_type.upper()} report.")

                    # --- Load report chunks and upsert to temporary Pinecone namespace ---
                    if _embedding_model_instance and _pinecone_index_instance:
                        print("\n--- Loading report data into temporary Pinecone namespace... ---")
                        current_report_namespace = load_report_chunks_and_embeddings(parsed_data, report_type)
                        if current_report_namespace:
                            print(f"Report data loaded into namespace: {current_report_namespace}")
                        else:
                            print("Failed to load report data into Pinecone namespace.")
                            # Optionally, continue without internal RAG or exit
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
                    reset_chat_context() # This now handles namespace deletion
                    break

                chat_history.append({"role": "user", "content": user_question})
                print("Thinking...")

                llm_prompt_content = ""
                rag_context = ""

                # Determine question type and prepare context
                if current_parsed_report and is_report_specific_question(user_question, current_parsed_report):
                    print(" (Determined as report-specific question - attempting INTERNAL RAG)")
                    if current_report_namespace and _embedding_model_instance and _pinecone_index_instance:
                        # Use internal RAG for report-specific questions
                        rag_context = retrieve_internal_rag_context(user_question, current_report_namespace, top_k=config.DEFAULT_RAG_TOP_K)
                        if rag_context:
                            llm_prompt_content += f"Here is some relevant information from the current report:\n{rag_context}\n\n"
                        else:
                            llm_prompt_content += "No specific relevant information found in the current report for this query. "
                            print(" (No INTERNAL RAG context found for report-specific question)")
                    else:
                        llm_prompt_content += "Internal RAG components not available or report not loaded into Pinecone. Answering based on initial summary and general knowledge.\n"
                        print(" (Internal RAG not available for report-specific question)")
                    
                    # Also include a general instruction to the LLM to emphasize it's about the report
                    llm_prompt_content += f"The user is asking a question related to the previously provided {current_report_type.upper()} security report."
                    llm_prompt_content += " Please refer to the report's content and your previous summary to answer.\n"
                else:
                    # General cybersecurity question (or no report loaded) -> Use EXTERNAL RAG
                    print(" (Determined as general cybersecurity question - attempting EXTERNAL RAG)")
                    if _embedding_model_instance and _pinecone_index_instance:
                        rag_context = retrieve_rag_context(user_question, top_k=config.DEFAULT_RAG_TOP_K, namespace="owasp-cybersecurity-kb") # Explicitly use external namespace
                        if rag_context:
                            llm_prompt_content += f"Here is some relevant information from a cybersecurity knowledge base:\n{rag_context}\n\n"
                        else:
                            llm_prompt_content += "No specific relevant information found in the knowledge base for this query. "
                            print(" (No EXTERNAL RAG context found)")
                    else:
                        llm_prompt_content += "RAG components not loaded or initialized. Answering based on general knowledge and chat history.\n"
                        print(" (RAG components not available for general question)")

                # Combine chat history with new context/instruction for the LLM
                concatenated_prompt = ""
                for msg in chat_history:
                    if msg["role"] == "user":
                        concatenated_prompt += f"User: {msg['content']}\n"
                    elif msg["role"] == "assistant":
                        concatenated_prompt += f"Assistant: {msg['content']}\n"
                
                final_llm_prompt = f"{llm_prompt_content}\n{concatenated_prompt}\nAssistant:"

                try:
                    llm_response = generate_response(llm_instance, final_llm_prompt, max_tokens=config.DEFAULT_MAX_TOKENS)
                    
                    print(f"\nBot: {llm_response}")
                    chat_history.append({"role": "assistant", "content": llm_response})

                except Exception as e:
                    print(f"Error generating LLM response: {e}")
                    import traceback
                    traceback.print_exc()
                    if chat_history and chat_history[-1]["role"] == "user":
                        chat_history.pop()

    finally: # Ensure LLM model and Pinecone namespace are explicitly closed/deleted
        try:
            # Clean up the current report's namespace on exit if it was created
            if current_report_namespace:
                delete_report_namespace(current_report_namespace)
            
            # Clean up LLM model if it exists
            if 'llm_model' in globals() and llm_model is not None:
                print("\n--- Closing LLM model ---")
                try:
                    # Try to close the model if it has a close method
                    if hasattr(llm_model, 'close') and callable(llm_model.close):
                        # Check if the model has the necessary attributes before calling close
                        if hasattr(llm_model, '_model') and llm_model._model is not None:
                            llm_model.close()
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
    main_cli_loop()

