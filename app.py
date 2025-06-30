import os
import sys
import json
import logging
import uuid
import threading
import time
from typing import Dict, Any, List, Optional

# FastAPI imports
from fastapi import FastAPI, Request, File, UploadFile, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

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
    from chatbot_modules.nikto_parser import process_nikto_report_file
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

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI()

# Configuration for file uploads
UPLOAD_FOLDER = os.path.join(current_dir, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max file size

# Global state for LLM and RAG components (loaded once)
_llm_instance_global = None
_embedding_model_instance_global = None
_pinecone_index_instance_global = None

# A lock to prevent multiple threads from initializing LLM/RAG simultaneously
_init_lock = threading.Lock()

# In-memory session store (replace with Redis/DB for production)
_session_store: Dict[str, Dict[str, Any]] = {}

# --- Pydantic Models for Request Bodies ---
class ChatMessage(BaseModel):
    """Pydantic model for incoming chat messages."""
    message: str
    session_id: str

class ClearChatRequest(BaseModel):
    """Pydantic model for clearing a chat session."""
    session_id: str

def _init_global_llm_and_rag():
    """
    Initializes global LLM and RAG components if they haven't been already.
    This function uses a lock to ensure thread-safe initialization.
    """
    global _llm_instance_global, _embedding_model_instance_global, _pinecone_index_instance_global

    with _init_lock:
        if _llm_instance_global is None:
            logger.info("Initializing global LLM instance...")
            try:
                _llm_instance_global = load_model(
                    model_id=config.LLM_MODEL_ID,
                    model_basename=config.LLM_MODEL_BASENAME,
                    local_dir=config.LLM_MODEL_DIR
                )
                logger.info("Global LLM instance loaded.")
            except Exception as e:
                logger.error(f"Failed to load global LLM instance: {e}")
                _llm_instance_global = None
                # Consider raising an exception here if LLM is critical for app function
                return

        if _embedding_model_instance_global is None:
            logger.info("Initializing global embedding model...")
            try:
                _embedding_model_instance_global = load_embedding_model()
                logger.info("Global embedding model loaded.")
            except Exception as e:
                logger.error(f"Failed to load global embedding model: {e}")
                _embedding_model_instance_global = None

        if _pinecone_index_instance_global is None and _embedding_model_instance_global is not None:
            logger.info("Initializing global Pinecone index...")
            try:
                _pinecone_index_instance_global = initialize_pinecone_index()
                logger.info("Global Pinecone index initialized.")
            except Exception as e:
                logger.error(f"Failed to initialize global Pinecone index: {e}")
                _pinecone_index_instance_global = None

def get_llm_instance():
    """
    Returns the global LLM instance, initializing if necessary.
    Raises HTTPException if LLM instance cannot be loaded.
    """
    if _llm_instance_global is None:
        _init_global_llm_and_rag()
    if _llm_instance_global is None:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="LLM instance not available.")
    return _llm_instance_global

def get_embedding_model_instance():
    """
    Returns the global embedding model instance, initializing if necessary.
    """
    if _embedding_model_instance_global is None:
        _init_global_llm_and_rag()
    return _embedding_model_instance_global

def get_pinecone_index_instance():
    """
    Returns the global Pinecone index instance, initializing if necessary.
    """
    if _pinecone_index_instance_global is None:
        _init_global_llm_and_rag()
    return _pinecone_index_instance_global


@app.on_event("startup")
async def startup_event():
    """Initializes global resources when the FastAPI app starts."""
    logger.info("FastAPI app startup event - Initializing global LLM and RAG components.")
    _init_global_llm_and_rag()
    logger.info("Global resources initialization complete.")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleans up global resources when the FastAPI app shuts down."""
    global _llm_instance_global, _embedding_model_instance_global, _pinecone_index_instance_global

    logger.info("FastAPI app shutdown event - Cleaning up global resources...")
    
    # Close LLM model if it has a close method
    if _llm_instance_global is not None:
        try:
            if hasattr(_llm_instance_global, 'close') and callable(_llm_instance_global.close):
                _llm_instance_global.close()
                logger.info("Global LLM model closed.")
            _llm_instance_global = None
        except Exception as e:
            logger.error(f"Error during global LLM model closing: {e}")

    _embedding_model_instance_global = None
    _pinecone_index_instance_global = None
    logger.info("Global resources cleanup complete.")


def detect_report_type_web(pdf_path: str) -> Optional[str]:
    """
    Attempts to detect the type of the security report (Nmap, ZAP, SSLScan, MobSF Android, MobSF iOS, Nikto)
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

        nikto_keywords = ["detailsnikto", "nikto report", "nikto version:", "vulnerability id", "http server header", "cwe", "osvdb"]
        if any(keyword in lower_text for keyword in nikto_keywords):
            return "nikto"

        return None
    except Exception as e:
        logger.error(f"Error during report type detection: {e}")
        return None

def is_report_specific_question_web(question: str, report_data: Dict[str, Any]) -> bool:
    """
    Heuristically determines if a question is specific to the loaded Nmap/ZAP/SSLScan/MobSF/Nikto report.
    This check uses the provided report_data.
    """
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

    elif "nikto" in report_tool:
        host_details = report_data.get("host_details", {})
        scan_summary = report_data.get("scan_summary", {})

        # Check host details
        if host_details.get("hostname") and host_details["hostname"].lower() in question_lower:
            return True
        if host_details.get("ip") and host_details["ip"].lower() in question_lower:
            return True
        if host_details.get("port") and str(host_details["port"]) in question_lower:
            return True
        if host_details.get("http_server") and host_details["http_server"].lower() in question_lower:
            return True
        if host_details.get("site_link_name") and host_details["site_link_name"].lower() in question_lower:
            return True
        if host_details.get("site_link_ip") and host_details["site_link_ip"].lower() in question_lower:
            return True

        # Check scan summary details
        if scan_summary.get("software") and scan_summary["software"].lower() in question_lower:
            return True
        # Check for presence of CLI options generally, as details can be long
        if "cli options" in question_lower and scan_summary.get("cli_options"):
            return True
        
        # Check individual findings (descriptions, URIs, methods, references)
        for finding in report_data.get("findings", []):
            if finding.get("description") and finding["description"].lower() in question_lower:
                return True
            if finding.get("uri") and finding["uri"].lower() in question_lower:
                return True
            if finding.get("http_method") and finding["http_method"].lower() in question_lower:
                return True
            if finding.get("references"):
                if any(ref.lower() in question_lower for ref in finding["references"]):
                    return True

        # Broad keywords relevant to Nikto scans
        if "nikto" in question_lower or "web server" in question_lower or "header" in question_lower or \
           "vulnerability" in question_lower or "finding" in question_lower or "security" in question_lower or \
           "http" in question_lower or "site" in question_lower or "host" in question_lower or \
           "cdn" in question_lower or "request id" in question_lower or "varnish" in question_lower:
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

@app.post("/upload_report")
async def upload_report(file: UploadFile = File(...)):
    """
    Handles PDF file uploads, parses them, and generates an initial summary.
    Returns a session_id for subsequent interactions.
    """
    if not file.filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='No file provided.')
    
    if not file.filename.lower().endswith('.pdf'):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid file type. Please upload a PDF.')

    # FastAPI handles content length check automatically via server configuration
    # but a manual check can be added if needed before file read.
    # if file.size > MAX_CONTENT_LENGTH:
    #     raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=f'File too large. Max size is {MAX_CONTENT_LENGTH / (1024 * 1024)} MB.')

    filename = f"{uuid.uuid4()}_{file.filename}" # Use UUID to prevent name collisions
    filepath = os.path.join(UPLOAD_FOLDER, filename)

    try:
        # Save the uploaded file
        with open(filepath, "wb") as buffer:
            content = await file.read() # Asynchronously read file content
            buffer.write(content)
        
        session_id = str(uuid.uuid4())
        _session_store[session_id] = {
            'chat_history': [],
            'current_parsed_report': None,
            'current_report_type': None,
            'current_report_namespace': None
        }

        report_type = detect_report_type_web(filepath)
        if report_type is None:
            os.remove(filepath)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, 
                                detail='Could not detect report type (Nmap, ZAP, SSLScan, MobSF Android, MobSF iOS, Nikto).')

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
        elif report_type.lower() == 'nikto':
            parsed_data = process_nikto_report_file(filepath)

        if parsed_data:
            session_data = _session_store[session_id]
            session_data['current_parsed_report'] = parsed_data
            session_data['current_report_type'] = report_type.lower()
            session_data['chat_history'] = [] # Re-initialize chat history for new report

            # Load report chunks and upsert to temporary Pinecone namespace
            embedding_model = get_embedding_model_instance()
            pinecone_index = get_pinecone_index_instance()

            if embedding_model and pinecone_index:
                report_namespace = load_report_chunks_and_embeddings(parsed_data, report_type)
                if report_namespace:
                    session_data['current_report_namespace'] = report_namespace
                    logger.info(f"Report data loaded into namespace: {report_namespace} for session {session_id}")
                else:
                    logger.warning(f"Failed to load report data into Pinecone namespace for session {session_id}.")
            else:
                logger.warning("RAG components (embedding model or Pinecone) not available. Proceeding without report RAG.")
            
            llm_instance = get_llm_instance() # This will raise HTTPException if LLM is not loaded
            initial_summary = summarize_report_with_llm(llm_instance, parsed_data, report_type)
            session_data['chat_history'].append({"role": "assistant", "content": initial_summary})
            
            return JSONResponse(content={'success': True, 'summary': initial_summary, 'report_loaded': True, 'session_id': session_id})
        else:
            os.remove(filepath)
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
                                detail=f'Failed to parse {report_type.upper()} report. No data returned.')

    except HTTPException as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        raise e # Re-raise FastAPI HTTPExceptions
    except Exception as e:
        logger.error(f"Error processing report: {e}", exc_info=True)
        if os.path.exists(filepath):
            os.remove(filepath)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f'An error occurred: {e}')
    finally:
        # Clean up the temporary file after processing, regardless of success or failure
        if os.path.exists(filepath):
            os.remove(filepath)

@app.post("/chat")
async def chat(chat_message: ChatMessage):
    """Handles user chat messages and returns AI responses."""
    session_id = chat_message.session_id
    user_question = chat_message.message

    if session_id not in _session_store:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found. Please upload a report first or provide a valid session ID.")
    
    session_data = _session_store[session_id]

    llm_instance = get_llm_instance() # Will raise HTTPException if not loaded

    chat_history = session_data.get('chat_history', [])
    current_parsed_report = session_data.get('current_parsed_report')
    current_report_type = session_data.get('current_report_type')
    current_report_namespace = session_data.get('current_report_namespace')

    chat_history.append({"role": "user", "content": user_question})

    # --- Chat History Management (Sliding Window) ---
    if len(chat_history) > config.CHAT_HISTORY_MAX_TURNS:
        logger.info(f"Chat history exceeding {config.CHAT_HISTORY_MAX_TURNS} turns for session {session_id}. Summarizing older segments.")
        # Ensure we don't try to summarize an empty or too small segment
        segment_end_index = len(chat_history) - config.CHAT_HISTORY_SUMMARIZE_THRESHOLD
        segment_to_summarize = chat_history[0 : segment_end_index]
        
        if segment_to_summarize:
            summarized_segment_text = summarize_chat_history_segment(llm_instance, segment_to_summarize)
            new_chat_history = [{"role": "system", "content": f"Summary of previous conversation: {summarized_segment_text}"}]
            new_chat_history.extend(chat_history[segment_end_index:])
            chat_history = new_chat_history
            session_data['chat_history'] = chat_history
            logger.info(f"Chat history summarized for session {session_id}.")
        else:
            logger.info(f"No segment to summarize based on threshold for session {session_id}.")

    llm_prompt_content = ""
    rag_context = ""

    # Determine if the question is report-specific and apply internal RAG if applicable
    if current_parsed_report and is_report_specific_question_web(user_question, current_parsed_report):
        logger.info(f"Determined as report-specific question for session {session_id} - attempting INTERNAL RAG.")
        embedding_model = get_embedding_model_instance()
        pinecone_index = get_pinecone_index_instance()

        if current_report_namespace and embedding_model and pinecone_index:
            rag_context = retrieve_internal_rag_context(user_question, current_report_namespace, top_k=config.DEFAULT_RAG_TOP_K)
            if rag_context:
                llm_prompt_content += f"Here is some relevant information from the current report:\n{rag_context}\n\n"
            else:
                llm_prompt_content += "No specific relevant information found in the current report for this query. "
                logger.info(f"No INTERNAL RAG context found for report-specific question for session {session_id}.")
        else:
            llm_prompt_content += "Internal RAG components not available or report not loaded into Pinecone. Answering based on initial summary and general knowledge.\n"
            logger.warning(f"Internal RAG not available for report-specific question for session {session_id}.")
        
        llm_prompt_content += f"The user is asking a question related to the previously provided {current_report_type.upper()} security report. Please refer to the report's content and your previous summary to answer.\n"
    else:
        # If not report-specific, attempt external RAG
        logger.info(f"Determined as general cybersecurity question for session {session_id} - attempting EXTERNAL RAG.")
        embedding_model = get_embedding_model_instance()
        pinecone_index = get_pinecone_index_instance()

        if embedding_model and pinecone_index:
            rag_context = retrieve_rag_context(user_question, top_k=config.DEFAULT_RAG_TOP_K, namespace="owasp-cybersecurity-kb") 
            if rag_context:
                llm_prompt_content += f"Here is some relevant information from a cybersecurity knowledge base:\n{rag_context}\n\n"
            else:
                llm_prompt_content += "No specific relevant information found in the knowledge base for this query. "
                logger.info(f"No EXTERNAL RAG context found for session {session_id}.")
        else:
            llm_prompt_content += "RAG components not loaded or initialized. Answering based on general knowledge and chat history.\n"
            logger.warning(f"RAG components not available for general question for session {session_id}.")

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
        session_data['chat_history'] = chat_history # Update session data

        return JSONResponse(content={'success': True, 'response': llm_response, 'chat_history': chat_history})

    except Exception as e:
        logger.error(f"Error generating LLM response for session {session_id}: {e}", exc_info=True)
        # If LLM generation fails, remove the last user message from history to prevent bad state
        if chat_history and chat_history[-1]["role"] == "user":
            chat_history.pop() 
        session_data['chat_history'] = chat_history # Ensure session data is updated
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f'An error occurred while generating response: {e}')

@app.post("/clear_chat")
async def clear_chat(request_body: ClearChatRequest):
    """
    Clears the current chat session for a given session ID,
    including deleting the associated Pinecone namespace if it exists.
    """
    session_id = request_body.session_id

    if session_id not in _session_store:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found.")
    
    session_data = _session_store[session_id]

    if session_data.get('current_report_namespace'):
        try:
            delete_report_namespace(session_data['current_report_namespace'])
            logger.info(f"Deleted Pinecone namespace: {session_data['current_report_namespace']} for session {session_id}")
        except Exception as e:
            logger.warning(f"Error deleting namespace during clear_chat for session {session_id}: {e}")
    
    # Remove session data from the store
    del _session_store[session_id]
    logger.info(f"Chat and report context cleared for session {session_id}.")
    
    return JSONResponse(content={'success': True, 'message': 'Chat and report context cleared.'})

# To run this FastAPI application, save this code as, for example, `app.py`.
# Then, execute the following command in your terminal:
# uvicorn app:app --host 0.0.0.0 --port 5000 --reload
# The '--reload' flag is useful for development as it restarts the server on code changes.
# For production, remove '--reload' and ensure your environment is set up correctly.
