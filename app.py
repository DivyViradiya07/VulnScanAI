import os
import sys
import json
from typing import Dict, Any, List, Optional
import atexit # Import atexit for cleanup

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
    from summarizer import summarize_report_with_llm, summarize_chat_history_segment, summarize_raw_text_report_with_llm
    from utils import (
        retrieve_rag_context, 
        load_report_chunks_and_embeddings,
        load_raw_text_chunks_and_embeddings, # NEW: Import for raw text reports
        retrieve_internal_rag_context, 
        delete_report_namespace,
        load_embedding_model, # For initial loading feedback
        initialize_pinecone_index, # For initial loading feedback
        is_report_specific_question # ADDED: Import for report specific question detection
    )
    from pdf_extractor import extract_text_from_pdf # For MobSF raw text extraction


except ImportError as e:
    print(f"Error importing a module: {e}")
    print("Please ensure all dependencies are installed and the 'chatbot_modules' directory is correctly set up.")
    sys.exit(1)


# Global variables for LLM model, Pinecone index, and current report namespace
llm_instance = None
current_report_namespace: Optional[str] = None
current_report_type: Optional[str] = None
# Store the raw text content of the MobSF report for RAG
current_mobsf_raw_text: Optional[str] = None 


def cleanup_llm():
    """Explicitly closes the LLM model to free up resources and deletes Pinecone namespace."""
    global llm_instance
    global current_report_namespace

    try:
        if current_report_namespace:
            print(f"\n--- Cleaning up Pinecone namespace: {current_report_namespace} ---")
            delete_report_namespace(current_report_namespace)
            current_report_namespace = None
        
        if llm_instance is not None:
            print("\n--- Closing LLM model ---")
            # Check if the model object has a 'close' method and call it
            if hasattr(llm_instance, 'close') and callable(llm_instance.close):
                # llama_cpp models might have an internal _model to check
                if hasattr(llm_instance, '_model') and llm_instance._model is not None:
                    llm_instance.close()
                    print("LLM model closed successfully.")
                else:
                    print("LLM model already closed or invalid.")
            else:
                print("LLM model does not have a close method.")
            llm_instance = None # Clear the instance
    except Exception as e:
        print(f"Error during cleanup: {e}")
        import traceback
        traceback.print_exc()

# Register cleanup function to be called on script exit
atexit.register(cleanup_llm)


def identify_report_type(file_path: str) -> Optional[str]:
    """
    Identifies the type of the security report based on its content (file extension or internal keywords).
    
    Args:
        file_path (str): The path to the report file.
        
    Returns:
        Optional[str]: The identified report type ('nmap', 'zap', 'sslscan', 'mobsf'), or None if unknown.
    """
    # Simple check for file extension (most common PDF names often contain the tool name)
    filename = os.path.basename(file_path).lower()

    if "nmap" in filename:
        return "nmap"
    elif "zap" in filename or "checkmarx" in filename: # ZAP reports might contain "Checkmarx" in their name/content
        return "zap"
    elif "sslscan" in filename:
        return "sslscan"
    elif "mobsf" in filename:
        return "mobsf"
    
    # For more robust identification, you might read the first few lines of the PDF
    # or look for specific keywords in the extracted text.
    # For now, we rely on filename.
    print(f"Could not conclusively determine report type from filename: {filename}. Attempting to extract text for more robust detection...")
    try:
        # Extract a small portion of text to infer type if filename isn't clear
        raw_text_sample = extract_text_from_pdf(file_path)[:2000].lower() # Read first 2KB
        if "nmap scan report" in raw_text_sample or "nmap done" in raw_text_sample:
            return "nmap"
        elif "zap" in raw_text_sample and ("report" in raw_text_sample or "vulnerabilities" in raw_text_sample):
            return "zap"
        elif "ssl/tls vulnerability scan report" in raw_text_sample or "sslscan" in raw_text_sample:
            return "sslscan"
        elif "mobsf" in raw_text_sample and ("android static analysis report" in raw_text_sample or "ios static analysis report" in raw_text_sample):
            return "mobsf"
    except Exception as e:
        print(f"Error reading PDF sample for type detection: {e}")

    return None

def main_cli_loop():
    """
    Main command-line interface loop for the security chatbot.
    Handles report processing, summarization, and interactive Q&A.
    """
    global llm_instance
    global current_report_namespace
    global current_report_type
    global current_mobsf_raw_text

    # --- Initial Model and Pinecone Setup ---
    print("Loading language model and RAG components. This may take a moment...")
    try:
        llm_instance = load_model(config.LLM_MODEL_ID, config.LLM_MODEL_BASENAME, config.LLM_MODEL_DIR)
        _ = load_embedding_model() # Ensure embedding model is loaded
        _ = initialize_pinecone_index() # Ensure Pinecone is initialized
        print("Language model and RAG components loaded successfully.")
    except Exception as e:
        print(f"Failed to load essential components: {e}")
        print("Exiting. Please check your model paths, API keys, and internet connection.")
        sys.exit(1)

    chat_history: List[Dict[str, str]] = []

    while True:
        try:
            if not current_report_type:
                report_path = input("\nPlease enter the path to your Nmap, ZAP, SSLScan, or MobSF PDF report (or 'exit'/'quit'): ").strip()
                if report_path.lower() in ['exit', 'quit']:
                    break
                if not os.path.exists(report_path):
                    print(f"Error: File not found at '{report_path}'. Please try again.")
                    continue

                print("\n--- Detecting report type... ---")
                current_report_type = identify_report_type(report_path)

                if not current_report_type:
                    print("Could not identify report type. Please ensure it's a supported Nmap, ZAP, SSLScan, or MobSF PDF.")
                    continue

                print(f"Detected report type: {current_report_type.upper()}")
                print(f"\n--- Processing {current_report_type.upper()} report from '{report_path}' ---")

                # --- Process and Load Report Data for RAG ---
                # Based on report type, call the appropriate parser and then load into Pinecone
                processed_report_data = None
                if current_report_type == "nmap":
                    processed_report_data = process_nmap_report_file(report_path)
                    print("\n--- Loading report data into temporary Pinecone namespace... ---")
                    current_report_namespace = load_report_chunks_and_embeddings(processed_report_data, current_report_type)
                elif current_report_type == "zap":
                    processed_report_data = process_zap_report_file(report_path)
                    print("\n--- Loading report data into temporary Pinecone namespace... ---")
                    current_report_namespace = load_report_chunks_and_embeddings(processed_report_data, current_report_type)
                elif current_report_type == "sslscan":
                    processed_report_data = process_sslscan_report_file(report_path)
                    print("\n--- Loading report data into temporary Pinecone namespace... ---")
                    current_report_namespace = load_report_chunks_and_embeddings(processed_report_data, current_report_type)
                elif current_report_type == "mobsf":
                    # For MobSF, we extract raw text first, then use that for RAG and summarization
                    print("MobSF report detected. Proceeding with raw text extraction for RAG.")
                    current_mobsf_raw_text = extract_text_from_pdf(report_path)
                    if not current_mobsf_raw_text.strip():
                        print("Error: Could not extract meaningful text from MobSF report.")
                        current_report_type = None
                        continue
                    print("\n--- Loading report data into temporary Pinecone namespace (from raw text)... ---")
                    # Using default chunk_size and chunk_overlap as defined in utils.py
                    current_report_namespace = load_raw_text_chunks_and_embeddings(current_mobsf_raw_text, current_report_type)
                
                if not current_report_namespace:
                    print("Failed to load report data into Pinecone namespace. Please check the report format and try again.")
                    current_report_type = None # Reset to allow re-upload
                    current_mobsf_raw_text = None
                    continue

                print(f"Report data loaded into Pinecone namespace: {current_report_namespace}")

                # --- Generate Initial Summary ---
                print(f"\n--- Generating initial summary for the {current_report_type.upper()} report... ---")
                initial_summary = ""
                if current_report_type in ["nmap", "zap", "sslscan"]:
                    initial_summary = summarize_report_with_llm(llm_instance, processed_report_data, current_report_type)
                elif current_report_type == "mobsf":
                    # Use the new summarization function for raw text
                    initial_summary = summarize_raw_text_report_with_llm(llm_instance, current_mobsf_raw_text, current_report_type)

                print("\n--- Initial Report Summary ---")
                print(initial_summary)
                chat_history.append({"role": "assistant", "content": initial_summary})

            # --- Interactive Chat Loop ---
            user_query = input("\nHow can I help with this report? (Type 'new_report' to upload another, 'exit' to quit): ").strip()
            if user_query.lower() in ['exit', 'quit']:
                break
            if user_query.lower() == 'new_report':
                if current_report_namespace:
                    print(f"Clearing previous report data from Pinecone namespace: {current_report_namespace}")
                    delete_report_namespace(current_report_namespace)
                current_report_namespace = None
                current_report_type = None
                current_mobsf_raw_text = None
                chat_history = [] # Clear chat history for new report
                continue

            # Add user query to chat history
            chat_history.append({"role": "user", "content": user_query})

            # --- Chat History Management ---
            # Summarize old chat history if it exceeds a certain length
            if len(chat_history) > config.CHAT_HISTORY_MAX_TURNS:
                # Summarize the oldest turns (e.g., first N turns)
                # We want to summarize from the beginning up to CHAT_HISTORY_SUMMARIZE_THRESHOLD turns from the end
                turns_to_summarize = chat_history[0 : len(chat_history) - config.CHAT_HISTORY_SUMMARIZE_THRESHOLD]
                
                if turns_to_summarize: # Only summarize if there's a segment to summarize
                    print(f"\n--- Summarizing {len(turns_to_summarize)} oldest chat turns... ---")
                    summary_of_old_chat = summarize_chat_history_segment(llm_instance, turns_to_summarize)
                    print(f"--- Summarized chat segment: {summary_of_old_chat[:100]}... ---") # Print a snippet
                    
                    # Replace the old turns with the summary and keep the most recent ones
                    new_chat_history = [{"role": "system", "content": f"Summary of previous conversation: {summary_of_old_chat}"}]
                    new_chat_history.extend(chat_history[len(chat_history) - config.CHAT_HISTORY_SUMMARIZE_THRESHOLD:])
                    chat_history = new_chat_history
                    print(f"(Chat history condensed. New history length: {len(chat_history)} turns)")
                else:
                    print("(No chat turns to summarize yet.)")


            # --- Determine RAG Strategy (External KB vs. Internal Report) ---
            # Check if the user's query is likely about the current report
            is_report_specific = False
            # Ensure current_parsed_report is available before checking report specificity
            if current_report_namespace and current_report_type: # Using current_report_namespace to imply report is loaded
                 # This heuristic function relies on current_parsed_report, which is only set for structured reports
                 # For raw text MobSF, we can't use current_parsed_report, so we rely on keywords and the namespace being present.
                if current_report_type != "mobsf":
                    # For Nmap, ZAP, SSLScan (structured), use the detailed check
                    # processed_report_data is only available here if a new report was just loaded.
                    # It's better to pass it from the outer scope if it was set.
                    # For a fresh query after initial summary, processed_report_data might be None.
                    # This needs to be passed correctly or accessed from a global if maintained.
                    # Assuming processed_report_data is available in this scope after report processing.
                    is_report_specific = is_report_specific_question(user_query, processed_report_data if processed_report_data else {})
                else:
                    # For MobSF (raw text), just check general keywords and if a namespace exists for it
                    is_report_specific = any(keyword in user_query.lower() for keyword in config.REPORT_SPECIFIC_KEYWORDS)

            rag_context = ""
            if is_report_specific and current_report_namespace:
                # Use internal RAG for report-specific questions
                print(f"\n--- Retrieving context from current '{current_report_type.upper()}' report for query: '{user_query}' ---")
                rag_context = retrieve_internal_rag_context(user_query, current_report_namespace, config.DEFAULT_RAG_TOP_K)
                if rag_context:
                    print(f"--- Retrieved INTERNAL RAG Context (first 100 chars): {rag_context[:100]}... ---")
                else:
                    print("--- No highly relevant context found in the current report for your query. ---")
                    # Fallback to external KB if internal RAG yields nothing for a report-specific query
                    print("--- Falling back to general knowledge base (EXTERNAL RAG)... ---")
                    rag_context = retrieve_rag_context(user_query, config.DEFAULT_RAG_TOP_K)
                    if rag_context:
                        print(f"--- Retrieved EXTERNAL RAG Context (first 100 chars): {rag_context[:100]}... ---")
                    else:
                        print("--- No EXTERNAL RAG context retrieved either. ---")
            else:
                # Use external RAG for general cybersecurity questions
                print(f"\n--- Retrieving context from general knowledge base for query: '{user_query}' ---")
                rag_context = retrieve_rag_context(user_query, config.DEFAULT_RAG_TOP_K)
                if rag_context:
                    print(f"--- Retrieved EXTERNAL RAG Context (first 100 chars): {rag_context[:100]}... ---")
                else:
                    print("--- No EXTERNAL RAG context retrieved. ---")
            
            # --- Construct Prompt for LLM ---
            messages_for_llm = []

            # Add system instruction (persona)
            messages_for_llm.append({
                "role": "system",
                "content": "You are a helpful cybersecurity assistant that specializes in analyzing Nmap, ZAP, SSLScan, and MobSF reports and answering questions based on them, as well as providing general cybersecurity knowledge. Provide concise and accurate answers."
            })
            
            # Add RAG context if available (as a system message)
            if rag_context:
                messages_for_llm.append({"role": "system", "content": f"Relevant background information:\n{rag_context}"})

            # Add recent chat history (including the current user query and any summarized history)
            # Ensure the structure is correct for the LLM's chat completion API
            for msg in chat_history:
                # The 'chat_history' list now correctly contains 'user', 'assistant', and 'system' roles.
                messages_for_llm.append({"role": msg["role"], "content": msg["content"]})
            
            # Print the full prompt being sent to the LLM for debugging
            print("\n--- FULL PROMPT SENT TO LLM FOR DEBUGGING ---")
            for msg in messages_for_llm:
                print(f"{msg['role'].upper()}: {msg['content']}")
            print("--- END FULL PROMPT ---")

            # --- Generate Response from LLM ---
            print("\n--- Generating response... ---")
            llm_response_content = generate_response(llm_instance, messages_for_llm, config.DEFAULT_MAX_TOKENS)
            
            # Add assistant's response to chat history
            chat_history.append({"role": "assistant", "content": llm_response_content})

            print("\n--- Assistant's Response ---")
            print(llm_response_content)

        except KeyboardInterrupt:
            print("\nExiting chat. Goodbye!")
            break
        except Exception as e:
            print(f"An error occurred: {e}")
            import traceback
            traceback.print_exc()
            print("Please try again or type 'new_report' to upload a different file.")
            if chat_history and chat_history[-1]["role"] == "user": # Ensure we pop user message if assistant failed
                    chat_history.pop()

if __name__ == "__main__":
    try:
        main_cli_loop()
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        # Ensure cleanup happens even if there's an error during initial setup or main loop
        cleanup_llm()
        sys.exit(0)
