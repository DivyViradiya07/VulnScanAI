import os
import sys
import json
from flask import Flask, request, jsonify, render_template, session, g
from werkzeug.utils import secure_filename
from datetime import datetime
import atexit
import threading
import time
from typing import Dict, Any, List, Optional # Import Optional here

# Ensure the 'chatbot_modules' directory is in the Python path for module imports
current_dir = os.path.dirname(os.path.abspath(__file__))
chatbot_modules_path = os.path.join(current_dir, "chatbot_modules")
if chatbot_modules_path not in sys.path:
    sys.path.insert(0, chatbot_modules_path)

# Import core modules from chatbot_modules
try:
    from chatbot_modules import config
    from chatbot_modules.local_llm import load_model, generate_response as llm_generate_response
    from chatbot_modules.nmap_parser import process_nmap_report_file
    from chatbot_modules.zap_parser import process_zap_report_file
    from chatbot_modules.ssl_parser import process_sslscan_report_file
    from chatbot_modules.mobsf_android_parser import process_mobsf_android_report_file
    from chatbot_modules.mobsf_ios_parser import process_mobsf_ios_report_file
    from chatbot_modules.summarizer import summarize_report_with_llm, summarize_chat_history_segment
    from chatbot_modules.pdf_extractor import extract_text_from_pdf
    from chatbot_modules.utils import (
        load_embedding_model, 
        initialize_pinecone_index, 
        retrieve_rag_context, 
        load_report_chunks_and_embeddings, 
        retrieve_internal_rag_context, 
        delete_report_namespace 
    )
except ImportError as e:
    print(f"Error importing a module: {e}")
    print("Please ensure all modules are correctly configured in your Python path.")
    sys.exit(1)

app = Flask(__name__)
app.secret_key = os.urandom(24) # Set a secret key for session management

# Configuration for file uploads
UPLOAD_FOLDER = os.path.join(current_dir, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max file size

# Global state for LLM and RAG components (loaded once)
_llm_instance_global = None
_embedding_model_instance_global = None
_pinecone_index_instance_global = None

# A lock to prevent multiple threads from initializing LLM/RAG simultaneously
_init_lock = threading.Lock()

def _init_global_llm_and_rag():
    """Initializes global LLM and RAG components if they haven't been already."""
    global _llm_instance_global, _embedding_model_instance_global, _pinecone_index_instance_global

    with _init_lock:
        if _llm_instance_global is None:
            print("Initializing global LLM instance...")
            try:
                _llm_instance_global = load_model(
                    model_id=config.LLM_MODEL_ID,
                    model_basename=config.LLM_MODEL_BASENAME,
                    local_dir=config.LLM_MODEL_DIR
                )
                print("Global LLM instance loaded.")
            except Exception as e:
                print(f"Failed to load global LLM instance: {e}")
                _llm_instance_global = None
                return

        if _embedding_model_instance_global is None:
            print("Initializing global embedding model...")
            try:
                _embedding_model_instance_global = load_embedding_model()
                print("Global embedding model loaded.")
            except Exception as e:
                print(f"Failed to load global embedding model: {e}")
                _embedding_model_instance_global = None

        if _pinecone_index_instance_global is None and _embedding_model_instance_global is not None:
            print("Initializing global Pinecone index...")
            try:
                _pinecone_index_instance_global = initialize_pinecone_index()
                print("Global Pinecone index initialized.")
            except Exception as e:
                print(f"Failed to initialize global Pinecone index: {e}")
                _pinecone_index_instance_global = None

def get_llm_instance():
    """Returns the global LLM instance, initializing if necessary."""
    if _llm_instance_global is None:
        _init_global_llm_and_rag()
    return _llm_instance_global

def get_embedding_model_instance():
    """Returns the global embedding model instance, initializing if necessary."""
    if _embedding_model_instance_global is None:
        _init_global_llm_and_rag()
    return _embedding_model_instance_global

def get_pinecone_index_instance():
    """Returns the global Pinecone index instance, initializing if necessary."""
    if _pinecone_index_instance_global is None:
        _init_global_llm_and_rag()
    return _pinecone_index_instance_global


# Register cleanup for LLM and Pinecone at app shutdown
@atexit.register
def cleanup_resources():
    """Ensures LLM and Pinecone resources are properly cleaned up on application exit."""
    global _llm_instance_global, _embedding_model_instance_global, _pinecone_index_instance_global

    print("Cleaning up global resources...")
    # The current_report_namespace deletion is handled in /upload_report and /clear_chat
    # as it depends on Flask's session context which is not available here.

    # Close LLM model
    if _llm_instance_global is not None:
        try:
            if hasattr(_llm_instance_global, 'close') and callable(_llm_instance_global.close):
                _llm_instance_global.close()
                print("Global LLM model closed.")
            _llm_instance_global = None
        except Exception as e:
            print(f"Error during global LLM model closing: {e}")

    # Pinecone connection is usually managed by the client library and doesn't require explicit close
    _embedding_model_instance_global = None
    _pinecone_index_instance_global = None
    print("Resources cleanup complete.")


def detect_report_type_web(pdf_path: str) -> Optional[str]:
    """
    Attempts to detect the type of the security report (Nmap, ZAP, SSLScan, MobSF Android, MobSF iOS)
    by reading a small portion of its text and looking for keywords.
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
        
        sslscan_keywords = ["ssl/tls vulnerability scan report", "ssl/tls protocols:", "supported server cipher(s):", "ssl certificate:"]
        if any(keyword in lower_text for keyword in sslscan_keywords):
            return "sslscan"
        
        mobsf_android_keywords = ["android static analysis report", "apkid", "manifest analysis"]
        if any(keyword in lower_text for keyword in mobsf_android_keywords):
            return "mobsf_android"

        mobsf_ios_keywords = ["ios static analysis report", "ipa","binary"]
        if any(keyword in lower_text for keyword in mobsf_ios_keywords):
            return "mobsf_ios"

        return None
    except Exception as e:
        app.logger.error(f"Error during report type detection: {e}")
        return None

def is_report_specific_question_web(question: str) -> bool:
    """
    Heuristically determines if a question is specific to the loaded Nmap/ZAP/SSLScan report.
    This check uses the session's current_parsed_report.
    """
    report_data = session.get('current_parsed_report')
    if not report_data:
        return False

    question_lower = question.lower()

    if any(keyword in question_lower for keyword in config.REPORT_SPECIFIC_KEYWORDS):
        return True

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
            if vuln.get("risk") and vuln["risk"].lower() in question_lower:
                return True
            for url_detail in vuln.get("urls", []):
                if url_detail.get("url") and url_detail["url"].lower() in question_lower:
                    if url_detail["url"].lower() in question_lower or \
                       url_detail["url"].split('//')[-1].split('/')[0].lower() in question_lower:
                        return True
    
    elif "sslscan" in report_tool:
        ssl_metadata = report_data.get("scan_metadata", {})
        if ssl_metadata.get("target_host") and ssl_metadata["target_host"].lower() in question_lower:
            return True
        if ssl_metadata.get("connected_ip") and ssl_metadata["connected_ip"].lower() in question_lower:
            return True
        if ssl_metadata.get("sni_name") and ssl_metadata["sni_name"].lower() in question_lower:
            return True
        
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

    elif "mobsf" in report_tool and "android" in report_tool:
        app_info = report_data.get("app_information", {})
        scan_metadata = report_data.get("scan_metadata", {})
        summary = report_data.get("summary", {})
        certificate_info = report_data.get("certificate_information", {})
        
        if app_info.get("App Name") and app_info["App Name"].lower() in question_lower: return True
        if app_info.get("Package Name") and app_info["Package Name"].lower() in question_lower: return True
        if scan_metadata.get("file_name") and scan_metadata["file_name"].lower() in question_lower: return True
        if scan_metadata.get("app_security_score") and (str(scan_metadata["app_security_score"]).split('/')[0] in question_lower or scan_metadata["app_security_score"].lower() in question_lower): return True
        if scan_metadata.get("grade") and scan_metadata["grade"].lower() in question_lower: return True
        if summary.get("total_issues") and str(summary["total_issues"]) in question_lower: return True
        for severity_type, count in summary.get("findings_severity", {}).items():
            if severity_type.lower() in question_lower and str(count) in question_lower: return True

        vulnerability_sections = [
            report_data.get("certificate_analysis_findings", []),
            report_data.get("manifest_analysis_findings", []),
            report_data.get("code_analysis_findings", [])
        ]
        for section in vulnerability_sections:
            for finding in section:
                if finding.get("title") and finding["title"].lower() in question_lower: return True
                if finding.get("issue") and finding["issue"].lower() in question_lower: return True
                if finding.get("severity") and finding["severity"].lower() in question_lower: return True
                if finding.get("description") and finding["description"].lower() in question_lower: return True

        for perm_entry in report_data.get("application_permissions", []):
            if perm_entry.get("permission") and perm_entry["permission"].lower() in question_lower: return True

        if certificate_info.get("X.509 Subject") and certificate_info["X.509 Subject"].lower() in question_lower: return True
        if certificate_info.get("md5_fingerprint") and certificate_info["md5_fingerprint"].lower() in question_lower: return True

        for apkid_finding in report_data.get("apkid_analysis", []):
            if apkid_finding.get("finding") and apkid_finding["finding"].lower() in question_lower: return True

        abused_perms = report_data.get("abused_permissions_summary", {}).get("Malware Permissions", {})
        if abused_perms.get("description") and abused_perms["description"].lower() in question_lower: return True
        
        mobsf_general_keywords = [
            "mobsf", "android report", "app info", "manifest", "permissions", 
            "abused permissions", "certificate", "signature", "sdk", "activity",
            "security score", "issues", "vulnerabilities", "findings", "apkid"
        ]
        if any(keyword in question_lower for keyword in mobsf_general_keywords): return True

    elif "mobsf" in report_tool and "ios" in report_tool:
        app_info = report_data.get("app_information", {})
        scan_metadata = report_data.get("scan_metadata", {})
        summary = report_data.get("summary", {})
        code_signature_info = report_data.get("code_signature_info", {}) 

        if app_info.get("App Name") and app_info["App Name"].lower() in question_lower: return True
        if app_info.get("Identifier") and app_info["Identifier"].lower() in question_lower: return True
        if scan_metadata.get("file_name") and scan_metadata["file_name"].lower() in question_lower: return True
        if scan_metadata.get("app_security_score") and (str(scan_metadata["app_security_score"]).split('/')[0] in question_lower or scan_metadata["app_security_score"].lower() in question_lower): return True
        if scan_metadata.get("grade") and scan_metadata["grade"].lower() in question_lower: return True
        if summary.get("total_issues") and str(summary["total_issues"]) in question_lower: return True
        for severity_type, count in summary.get("findings_severity", {}).items():
            if severity_type.lower() in question_lower and str(count) in question_lower: return True

        vulnerability_sections = [
            report_data.get("app_transport_security_findings", []),
            report_data.get("ipa_binary_code_analysis_findings", []),
            report_data.get("ipa_binary_analysis_findings", [])
        ]
        for section in vulnerability_sections:
            for finding in section:
                if finding.get("issue") and finding["issue"].lower() in question_lower: return True
                if finding.get("severity") and finding["severity"].lower() in question_lower: return True
                if finding.get("description") and finding["description"].lower() in question_lower: return True
                if finding.get("protection") and finding["protection"].lower() in question_lower: return True

        if code_signature_info:
            if code_signature_info.get("Team ID") and code_signature_info["Team ID"].lower() in question_lower: return True

        for country_data in report_data.get("ofac_sanctioned_countries", []):
            if country_data.get("domain") and country_data["domain"].lower() in question_lower: return True

        for domain_data in report_data.get("domain_malware_check", []):
            if domain_data.get("domain") and domain_data["domain"].lower() in question_lower: return True
            if domain_data.get("status") and domain_data["status"].lower() in question_lower: return True
        
        mobsf_general_ios_keywords = [
            "mobsf", "ios report", "app info", "app transport security", "ats",
            "ipa binary analysis", "code signing", "certificate", "provisioning profile",
            "security score", "issues", "vulnerabilities", "findings", "ofac", "malware domain",
            "binary protection", "objective-c", "swift"
        ]
        if any(keyword in question_lower for keyword in mobsf_general_ios_keywords): return True

    return False


@app.route('/')
def index():
    """Renders the main chat interface page."""
    # Ensure all session variables are cleared on fresh load
    session.clear()
    return render_template('index.html')

@app.route('/upload_report', methods=['POST'])
def upload_report():
    """Handles PDF file uploads, parses them, and generates an initial summary."""
    if 'pdf_file' not in request.files:
        return jsonify({'success': False, 'message': 'No file part'}), 400

    file = request.files['pdf_file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No selected file'}), 400

    if file and file.filename.lower().endswith('.pdf'):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Ensure old temporary files are cleaned up or overwritten if needed
        if os.path.exists(filepath):
            os.remove(filepath)
        file.save(filepath)

        # Clear previous session data for a new report
        if session.get('current_report_namespace'):
            try:
                delete_report_namespace(session['current_report_namespace'])
            except Exception as e:
                app.logger.warning(f"Failed to delete old namespace: {e}")
        session.clear() # Clear all session data

        try:
            report_type = detect_report_type_web(filepath)
            if report_type is None:
                os.remove(filepath)
                return jsonify({'success': False, 'message': 'Could not detect report type (Nmap, ZAP, SSLScan, MobSF Android, MobSF iOS).'}), 400

            parsed_data = None
            if report_type.lower() == 'nmap':
                parsed_data = process_nmap_report_file(filepath)
            elif report_type.lower() == 'zap':
                parsed_data = process_zap_report_file(filepath)
            elif report_type.lower() == 'sslscan':
                parsed_data = process_sslscan_report_file(filepath)
            elif report_type.lower() == 'mobsf_android':
                parsed_data = process_mobsf_android_report_file(filepath)
            elif report_type.lower() == 'mobsf_ios':
                parsed_data = process_mobsf_ios_report_file(filepath)

            if parsed_data:
                session['current_parsed_report'] = parsed_data
                session['current_report_type'] = report_type.lower()
                session['chat_history'] = []

                # Load report chunks and upsert to temporary Pinecone namespace
                embedding_model = get_embedding_model_instance()
                pinecone_index = get_pinecone_index_instance()

                if embedding_model and pinecone_index:
                    report_namespace = load_report_chunks_and_embeddings(parsed_data, report_type)
                    if report_namespace:
                        session['current_report_namespace'] = report_namespace
                        app.logger.info(f"Report data loaded into namespace: {report_namespace}")
                    else:
                        app.logger.warning("Failed to load report data into Pinecone namespace.")
                else:
                    app.logger.warning("RAG components (embedding model or Pinecone) not available. Proceeding without report RAG.")
                
                llm_instance = get_llm_instance()
                if llm_instance:
                    initial_summary = summarize_report_with_llm(llm_instance, parsed_data, report_type)
                    session['chat_history'].append({"role": "assistant", "content": initial_summary})
                    return jsonify({'success': True, 'summary': initial_summary, 'report_loaded': True})
                else:
                    return jsonify({'success': False, 'message': 'LLM not loaded. Cannot generate summary.'}), 500

            else:
                os.remove(filepath)
                return jsonify({'success': False, 'message': f'Failed to parse {report_type.upper()} report. No data returned.'}), 500

        except Exception as e:
            app.logger.error(f"Error processing report: {e}", exc_info=True)
            if os.path.exists(filepath):
                os.remove(filepath)
            return jsonify({'success': False, 'message': f'An error occurred: {e}'}), 500
    else:
        return jsonify({'success': False, 'message': 'Invalid file type. Please upload a PDF.'}), 400

@app.route('/chat', methods=['POST'])
def chat():
    """Handles user chat messages and returns AI responses."""
    user_question = request.json.get('message')
    if not user_question:
        return jsonify({'success': False, 'message': 'No message provided'}), 400

    llm_instance = get_llm_instance()
    if not llm_instance:
        return jsonify({'success': False, 'message': 'LLM is not initialized. Please restart the server or check logs.'}), 500

    chat_history = session.get('chat_history', [])
    current_parsed_report = session.get('current_parsed_report')
    current_report_type = session.get('current_report_type')
    current_report_namespace = session.get('current_report_namespace')

    chat_history.append({"role": "user", "content": user_question})

    # --- Chat History Management (Sliding Window) ---
    if len(chat_history) > config.CHAT_HISTORY_MAX_TURNS:
        app.logger.info(f"Chat history exceeding {config.CHAT_HISTORY_MAX_TURNS} turns. Summarizing older segments.")
        segment_to_summarize = chat_history[0 : len(chat_history) - config.CHAT_HISTORY_SUMMARIZE_THRESHOLD]
        
        if segment_to_summarize:
            summarized_segment_text = summarize_chat_history_segment(llm_instance, segment_to_summarize)
            new_chat_history = [{"role": "system", "content": f"Summary of previous conversation: {summarized_segment_text}"}]
            new_chat_history.extend(chat_history[len(chat_history) - config.CHAT_HISTORY_SUMMARIZE_THRESHOLD:])
            chat_history = new_chat_history
            session['chat_history'] = chat_history
            app.logger.info("Chat history summarized.")
        else:
            app.logger.info("No segment to summarize based on threshold.")

    llm_prompt_content = ""
    rag_context = ""

    if current_parsed_report and is_report_specific_question_web(user_question):
        app.logger.info("Determined as report-specific question - attempting INTERNAL RAG.")
        if current_report_namespace and get_embedding_model_instance() and get_pinecone_index_instance():
            rag_context = retrieve_internal_rag_context(user_question, current_report_namespace, top_k=config.DEFAULT_RAG_TOP_K)
            if rag_context:
                llm_prompt_content += f"Here is some relevant information from the current report:\n{rag_context}\n\n"
            else:
                llm_prompt_content += "No specific relevant information found in the current report for this query. "
                app.logger.info("No INTERNAL RAG context found for report-specific question.")
        else:
            llm_prompt_content += "Internal RAG components not available or report not loaded into Pinecone. Answering based on initial summary and general knowledge.\n"
            app.logger.warning("Internal RAG not available for report-specific question.")
        
        llm_prompt_content += f"The user is asking a question related to the previously provided {current_report_type.upper()} security report. Please refer to the report's content and your previous summary to answer.\n"
    else:
        app.logger.info("Determined as general cybersecurity question - attempting EXTERNAL RAG.")
        if get_embedding_model_instance() and get_pinecone_index_instance():
            rag_context = retrieve_rag_context(user_question, top_k=config.DEFAULT_RAG_TOP_K, namespace="owasp-cybersecurity-kb") 
            if rag_context:
                llm_prompt_content += f"Here is some relevant information from a cybersecurity knowledge base:\n{rag_context}\n\n"
            else:
                llm_prompt_content += "No specific relevant information found in the knowledge base for this query. "
                app.logger.info("No EXTERNAL RAG context found.")
        else:
            llm_prompt_content += "RAG components not loaded or initialized. Answering based on general knowledge and chat history.\n"
            app.logger.warning("RAG components not available for general question.")

    concatenated_prompt = ""
    for msg in chat_history:
        if msg["role"] == "user":
            concatenated_prompt += f"User: {msg['content']}\n"
        elif msg["role"] == "assistant":
            concatenated_prompt += f"Assistant: {msg['content']}\n"
        elif msg["role"] == "system":
            concatenated_prompt += f"System: {msg['content']}\n"
    
    final_llm_prompt = f"{llm_prompt_content}\n{concatenated_prompt}\nAssistant:"

    try:
        llm_response = llm_generate_response(llm_instance, final_llm_prompt, max_tokens=config.DEFAULT_MAX_TOKENS)
        
        chat_history.append({"role": "assistant", "content": llm_response})
        session['chat_history'] = chat_history # Update session after adding response

        return jsonify({'success': True, 'response': llm_response, 'chat_history': chat_history})

    except Exception as e:
        app.logger.error(f"Error generating LLM response: {e}", exc_info=True)
        if chat_history and chat_history[-1]["role"] == "user":
            chat_history.pop() # Remove user message if assistant failed
        session['chat_history'] = chat_history # Update session
        return jsonify({'success': False, 'message': f'An error occurred while generating response: {e}'}), 500

@app.route('/clear_chat', methods=['POST'])
def clear_chat():
    """Clears the current chat session, including deleting the Pinecone namespace."""
    if session.get('current_report_namespace'):
        try:
            delete_report_namespace(session['current_report_namespace'])
            app.logger.info(f"Deleted Pinecone namespace: {session['current_report_namespace']}")
        except Exception as e:
            app.logger.warning(f"Error deleting namespace during clear_chat: {e}")
    
    session.clear()
    return jsonify({'success': True, 'message': 'Chat and report context cleared.'})

if __name__ == '__main__':
    print("Starting Flask app...")
    # Initialize global LLM and RAG components on app start-up
    _init_global_llm_and_rag()
    # Disable Flask's default development server banner to prevent Windows error 6
    # This specifically addresses the OSError: [WinError 6] The handle is invalid.
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False) # Added use_reloader=False
