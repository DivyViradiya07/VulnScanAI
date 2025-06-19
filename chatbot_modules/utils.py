import os
import json
from sentence_transformers import SentenceTransformer, util
from pinecone import Pinecone, ServerlessSpec, PodSpec
from typing import Dict, Any, List, Optional, Union
import dotenv
import uuid
import sys
import re

# Load environment variables from a .env file (if present)
dotenv.load_dotenv()

# Add the project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Import configuration settings from the config module
from chatbot_modules.config import (
    RAG_EMBEDDING_MODEL_PATH,
    PINECONE_INDEX_NAME,
    PINECONE_EMBEDDING_DIMENSION,
    PINECONE_METRIC,
    PINECONE_CLOUD,
    PINECONE_REGION,
    DEFAULT_RAG_TOP_K,
    REPORT_SPECIFIC_KEYWORDS
)

# Pinecone API Key and Environment are still fetched from os.environ
# as recommended for sensitive information
PINECONE_API_KEY = os.environ.get("PINECONE_API_KEY")
PINECONE_ENVIRONMENT = os.environ.get("PINECONE_ENVIRONMENT")


# Global variables to store loaded RAG components
_embedding_model: Optional[SentenceTransformer] = None
_pinecone_index: Optional[Any] = None


def load_embedding_model() -> SentenceTransformer:
    """
    Loads the SentenceTransformer embedding model.
    This function ensures the model is loaded only once and cached.
    """
    global _embedding_model
    if _embedding_model is None:
        print(f"Loading embedding model from {RAG_EMBEDDING_MODEL_PATH}...")
        try:
            if not os.path.exists(RAG_EMBEDDING_MODEL_PATH):
                print(f"Warning: Embedding model path {RAG_EMBEDDING_MODEL_PATH} not found. Attempting to load default 'all-MiniLM-L6-v2'.")
                _embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
            else:
                _embedding_model = SentenceTransformer(RAG_EMBEDDING_MODEL_PATH)
            print("Embedding model loaded successfully.")
        except Exception as e:
            print(f"Error loading embedding model: {e}")
            raise RuntimeError(f"Could not load embedding model. Ensure it's downloaded and path is correct: {RAG_EMBEDDING_MODEL_PATH}") from e
    return _embedding_model

def initialize_pinecone_index() -> Any:
    """
    Initializes the Pinecone connection and returns the index.
    This function ensures Pinecone is initialized only once and cached.
    """
    global _pinecone_index
    if _pinecone_index is None:
        if not PINECONE_API_KEY or not PINECONE_ENVIRONMENT:
            raise ValueError("PINECONE_API_KEY and PINECONE_ENVIRONMENT must be set as environment variables.")

        print(f"Initializing Pinecone index '{PINECONE_INDEX_NAME}' in environment '{PINECONE_ENVIRONMENT}'...")
        try:
            pinecone_client = Pinecone(api_key=PINECONE_API_KEY, environment=PINECONE_ENVIRONMENT)
            
            if PINECONE_INDEX_NAME not in pinecone_client.list_indexes():
                print(f"Creating Pinecone index '{PINECONE_INDEX_NAME}'...")
                if PINECONE_CLOUD and PINECONE_REGION:
                     pinecone_client.create_index(
                        name=PINECONE_INDEX_NAME,
                        dimension=PINECONE_EMBEDDING_DIMENSION,
                        metric=PINECONE_METRIC,
                        spec=ServerlessSpec(
                            cloud=PINECONE_CLOUD, 
                            region=PINECONE_REGION
                        )
                    )
                else:
                    pinecone_client.create_index(
                        name=PINECONE_INDEX_NAME,
                        dimension=PINECONE_EMBEDDING_DIMENSION,
                        metric=PINECONE_METRIC,
                    )
                print(f"Index '{PINECONE_INDEX_NAME}' created.")
            else:
                print(f"Index '{PINECONE_INDEX_NAME}' already exists.")
            
            _pinecone_index = pinecone_client.Index(PINECONE_INDEX_NAME)
            print("Pinecone index initialized successfully.")
        except Exception as e:
            print(f"Error initializing Pinecone: {e}")
            raise RuntimeError("Could not initialize Pinecone. Check API key, environment, and network connectivity.") from e
    return _pinecone_index

def retrieve_rag_context(query: str, top_k: int = DEFAULT_RAG_TOP_K, namespace: str = "owasp-cybersecurity-kb") -> str:
    """
    Retrieves relevant context from the Pinecone knowledge base (external RAG).

    Args:
        query (str): The user's query.
        top_k (int): The number of top relevant results to retrieve.
        namespace (str): The Pinecone namespace to query (default is OWASP KB).

    Returns:
        str: A concatenated string of relevant context, or an empty string if none found.
    """
    embedding_model = load_embedding_model()
    pinecone_index = initialize_pinecone_index()

    try:
        query_embedding = embedding_model.encode(query).tolist()
        
        query_results = pinecone_index.query(
            vector=query_embedding,
            top_k=top_k,
            include_metadata=True,
            namespace=namespace
        )

        context_chunks = []
        for match in query_results.matches:
            if match.score > 0.7:
                context_chunks.append(match.metadata.get('text', ''))
        
        if context_chunks:
            return "\n---\n".join(context_chunks)
        else:
            return ""
    except Exception as e:
        print(f"Error retrieving RAG context from Pinecone: {e}")
        return ""

def _chunk_nmap_report(parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Chunks parsed Nmap data into smaller, meaningful segments for embedding.
    Each chunk will include metadata for better retrieval.
    """
    chunks = []
    
    scan_meta = parsed_data.get("scan_metadata", {})
    meta_text = (
        f"Nmap Scan Report for Target: {scan_meta.get('target', 'N/A')}. "
        f"Scan Initiated by: {scan_meta.get('scan_initiated_by', 'N/A')} "
        f"on {scan_meta.get('timestamp', 'N/A')} with Nmap version {scan_meta.get('nmap_version', 'N/A')}. "
        f"Scan Type: {scan_meta.get('scan_type', 'N/A')}. "
        f"Duration: {scan_meta.get('scan_duration', 'N/A')}."
    )
    chunks.append({"id_suffix": "meta", "content": meta_text, "metadata": scan_meta})

    for i, host in enumerate(parsed_data.get("hosts", [])):
        host_ip = host.get("ip_address", "N/A")
        host_hostname = host.get("hostname", "N/A")
        host_status = host.get("status", "N/A")
        
        host_summary = f"Host IP: {host_ip}, Hostname: {host_hostname}, Status: {host_status}."
        
        os_info = host.get("os_detection", {})
        if os_info:
            os_details = ", ".join([f"{k}: {v}" for k, v in os_info.items() if v])
            host_summary += f" OS Details: {os_details}."

        traceroute_info = host.get("traceroute", {})
        if traceroute_info and traceroute_info.get('hops'):
            num_hops = len(traceroute_info['hops'])
            host_summary += f" Traceroute shows {num_hops} hops."

        chunks.append({"id_suffix": f"host_{i}", "content": host_summary, "metadata": host})

        for j, port in enumerate(host.get("ports", [])):
            port_summary = (
                f"On host {host_ip} ({host_hostname}), Port {port.get('port_id')}/{port.get('protocol')} is {port.get('state')}. "
                f"Service: {port.get('service')}, Version: {port.get('version', 'N/A')}."
            )
            if port.get("script_output"):
                port_summary += f" Script output: {port.get('script_output')}"
            chunks.append({"id_suffix": f"host_{i}_port_{j}", "content": port_summary, "metadata": port})
            
    return chunks

def _chunk_zap_report(parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Chunks parsed ZAP data into smaller, meaningful segments for embedding.
    """
    chunks = []

    scan_meta = parsed_data.get("scan_metadata", {})
    summary = parsed_data.get("summary", {})
    meta_text = (
        f"ZAP Scan Report for Site: {scan_meta.get('site', 'N/A')}. "
        f"Generated at: {scan_meta.get('generated_at', 'N/A')} with ZAP version {scan_meta.get('zap_version', 'N/A')}. "
        f"Summary of risks: High: {summary.get('risk_counts', {}).get('High', 0)}, "
        f"Medium: {summary.get('risk_counts', {}).get('Medium', 0)}, "
        f"Low: {summary.get('risk_counts', {}).get('Low', 0)}, "
        f"Informational: {summary.get('risk_counts', {}).get('Informational', 0)}. "
        f"Total alerts: {summary.get('total_alerts', 0)}."
    )
    chunks.append({"id_suffix": "meta", "content": meta_text, "metadata": scan_meta})

    for i, vuln in enumerate(parsed_data.get("vulnerabilities", [])):
        vuln_name = vuln.get("name", "N/A")
        vuln_risk = vuln.get("risk", "N/A")
        vuln_cwe = vuln.get("cwe_id", "N/A")
        vuln_wasc = vuln.get("wasc_id", "N/A")
        
        vuln_summary = (
            f"Vulnerability: {vuln_name} (Risk: {vuln_risk}). "
            f"Description: {vuln.get('description', 'N/A')}. "
            f"CWE ID: {vuln_cwe}, WASC ID: {vuln_wasc}. "
            f"Solution: {vuln.get('solution', 'N/A')}."
        )
        
        urls_affected = []
        for url_info in vuln.get("urls", []):
            urls_affected.append(f"URL: {url_info.get('url')} (Method: {url_info.get('method')}, Parameter: {url_info.get('parameter', 'N/A')})")
        if urls_affected:
            vuln_summary += " Affected Instances:\n" + "\n".join(urls_affected)

        chunks.append({"id_suffix": f"vuln_{i}", "content": vuln_summary, "metadata": vuln})

    return chunks

def _chunk_sslscan_report(parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Chunks parsed SSLScan data into smaller, meaningful segments for embedding.
    """
    chunks = []

    scan_meta = parsed_data.get("scan_metadata", {})
    meta_text = (
        f"SSL/TLS Vulnerability Scan Report for Target: {scan_meta.get('target_host', 'N/A')}. "
        f"Connected to IP: {scan_meta.get('connected_ip', 'N/A')}. "
        f"Scan Initiated by: {scan_meta.get('scan_initiated_by', 'N/A')} on {scan_meta.get('timestamp', 'N/A')}. "
        f"OpenSSL Version: {scan_meta.get('openssl_version', 'N/A')}."
    )
    chunks.append({"id_suffix": "meta", "content": meta_text, "metadata": scan_meta})

    protocol_summary = "SSL/TLS Protocols:\n"
    for proto in parsed_data.get("protocols", []):
        protocol_summary += f"- {proto.get('name')}: {proto.get('status')}\n"
    chunks.append({"id_suffix": "protocols", "content": protocol_summary.strip(), "metadata": parsed_data.get("protocols", [])})

    security_features = parsed_data.get("security_features", {})
    if security_features:
        features_summary = "Security Features:\n"
        for key, value in security_features.items():
            features_summary += f"- {key.replace('_', ' ').title()}: {value}\n"
        chunks.append({"id_suffix": "security_features", "content": features_summary.strip(), "metadata": security_features})

    ciphers = parsed_data.get("supported_ciphers", [])
    if ciphers:
        cipher_texts = []
        for i, cipher in enumerate(ciphers):
            cipher_texts.append(
                f"Cipher: {cipher.get('name')} ({cipher.get('tls_version')} {cipher.get('bits')} bits). "
                f"Curve: {cipher.get('curve', 'N/A')}, DHE: {cipher.get('dhe', 'N/A')}."
            )
        for i in range(0, len(cipher_texts), 5):
            chunk_content = "Supported Ciphers:\n" + "\n".join(cipher_texts[i:i+5])
            chunks.append({"id_suffix": f"ciphers_{i//5}", "content": chunk_content, "metadata": ciphers[i:i+5]})

    cert_info = parsed_data.get("ssl_certificate", {})
    if cert_info:
        cert_summary = "SSL Certificate Details:\n"
        for key, value in cert_info.items():
            cert_summary += f"- {key.replace('_', ' ').title()}: {value}\n"
        chunks.append({"id_suffix": "certificate", "content": cert_summary.strip(), "metadata": cert_info})

    key_exchange_groups = parsed_data.get("key_exchange_groups", [])
    if key_exchange_groups:
        key_exchange_summary = "Key Exchange Groups:\n" + "\n".join([str(g) for g in key_exchange_groups])
        chunks.append({"id_suffix": "key_exchange", "content": key_exchange_summary.strip(), "metadata": key_exchange_groups})

    return chunks

def _chunk_raw_text(raw_text: str, chunk_size: int = 500, overlap: int = 50) -> List[Dict[str, Any]]:
    """
    Chunks raw text into smaller segments based on character length.
    This is a generic chunking method for unstructured text.
    """
    chunks = []
    text_length = len(raw_text)
    start_idx = 0
    chunk_num = 0

    while start_idx < text_length:
        end_idx = min(start_idx + chunk_size, text_length)
        chunk_content = raw_text[start_idx:end_idx]
        
        if end_idx < text_length:
            next_newline = raw_text.find('\n', end_idx - overlap, end_idx + 1)
            if next_newline != -1 and next_newline < text_length:
                end_idx = next_newline + 1
                chunk_content = raw_text[start_idx:end_idx]
            else:
                next_space = raw_text.rfind(' ', start_idx, end_idx)
                if next_space != -1 and next_space > start_idx:
                    end_idx = next_space
                    chunk_content = raw_text[start_idx:end_idx]

        chunks.append({
            "id_suffix": f"chunk_{chunk_num}", 
            "content": chunk_content.strip(), 
            "metadata": {"type": "raw_text_chunk", "chunk_index": chunk_num}
        })
        start_idx = end_idx - overlap if end_idx < text_length else end_idx
        chunk_num += 1
    return chunks


def load_report_chunks_and_embeddings(report_data: Union[Dict[str, Any], str], report_type: str) -> Optional[str]:
    """
    Loads parsed report data (or raw text for MobSF) into Pinecone.
    It chunks the data, generates embeddings, and upserts them into a new, unique namespace.

    Args:
        report_data (Union[Dict[str, Any], str]): The structured report data (for Nmap, ZAP, SSLScan)
                                                or raw text content (for MobSF).
        report_type (str): The type of the report ('nmap', 'zap', 'sslscan', 'mobsf').

    Returns:
        Optional[str]: The name of the unique Pinecone namespace where data was stored,
                       or None if an error occurred.
    """
    embedding_model = load_embedding_model()
    pinecone_index = initialize_pinecone_index()

    if not embedding_model or not pinecone_index:
        print("Embedding model or Pinecone index not initialized. Cannot load report chunks.")
        return None

    report_namespace = f"report-{report_type}-{uuid.uuid4()}"
    print(f"Using Pinecone namespace: {report_namespace}")

    try:
        chunks_to_embed = []
        if report_type == 'nmap':
            chunks_to_embed = _chunk_nmap_report(report_data)
        elif report_type == 'zap':
            chunks_to_embed = _chunk_zap_report(report_data)
        elif report_type == 'sslscan':
            chunks_to_embed = _chunk_sslscan_report(report_data)
        elif report_type == 'mobsf':
            if isinstance(report_data, str):
                chunks_to_embed = _chunk_mobsf_raw_text(report_data)
            else:
                print(f"Error: MobSF report_data expected to be string, got {type(report_data)}")
                return None
        else:
            print(f"Unknown report type: {report_type}. Cannot chunk data.")
            return None

        if not chunks_to_embed:
            print(f"No chunks generated for {report_type} report. Skipping embedding.")
            return None

        vectors_to_upsert = []
        for chunk in chunks_to_embed:
            content_text = chunk.get("content", "")
            if content_text:
                vector_id = f"{report_type}-{chunk.get('id_suffix')}"
                embedding = embedding_model.encode(content_text).tolist()
                
                chunk_metadata = chunk.get("metadata", {})
                chunk_metadata["text"] = content_text
                
                vectors_to_upsert.append({
                    "id": vector_id,
                    "values": embedding,
                    "metadata": chunk_metadata
                })

        if vectors_to_upsert:
            batch_size = 100 
            for i in range(0, len(vectors_to_upsert), batch_size):
                batch = vectors_to_upsert[i:i + batch_size]
                pinecone_index.upsert(vectors=batch, namespace=report_namespace)
            print(f"Successfully upserted {len(vectors_to_upsert)} vectors to Pinecone namespace '{report_namespace}'.")
            return report_namespace
        else:
            print("No vectors to upsert after embedding.")
            return None

    except Exception as e:
        print(f"Error loading report chunks and embeddings for {report_type}: {e}")
        import traceback
        traceback.print_exc()
        return None

def retrieve_internal_rag_context(query: str, report_namespace: str, top_k: int = DEFAULT_RAG_TOP_K) -> str:
    """
    Retrieves relevant context from the temporary Pinecone namespace for the current report (internal RAG).

    Args:
        query (str): The user's query.
        report_namespace (str): The specific Pinecone namespace for the current report.
        top_k (int): The number of top relevant results to retrieve.

    Returns:
        str: A concatenated string of relevant context, or an empty string if none found.
    """
    embedding_model = load_embedding_model()
    pinecone_index = initialize_pinecone_index()

    if not embedding_model or not pinecone_index:
        print("Embedding model or Pinecone index not initialized. Cannot retrieve internal RAG context.")
        return ""

    try:
        query_embedding = embedding_model.encode(query).tolist()
        
        query_results = pinecone_index.query(
            vector=query_embedding,
            top_k=top_k,
            include_metadata=True,
            namespace=report_namespace
        )

        context_chunks = []
        for match in query_results.matches:
            if match.score > 0.7: 
                context_chunks.append(match.metadata.get('text', '')) 
        
        if context_chunks:
            return "\n---\n".join(context_chunks)
        else:
            return ""
    except Exception as e:
        print(f"Error retrieving INTERNAL RAG context from Pinecone: {e}")
        return ""


def delete_report_namespace(report_namespace: str):
    """
    Deletes a specific namespace from the Pinecone index.
    """
    pinecone_index = initialize_pinecone_index()
    if pinecone_index:
        try:
            print(f"Deleting Pinecone namespace: {report_namespace}...")
            pinecone_index.delete(delete_all=True, namespace=report_namespace)
            print(f"Namespace '{report_namespace}' deleted successfully.")
        except Exception as e:
            print(f"Error deleting Pinecone namespace '{report_namespace}': {e}")
            import traceback
            traceback.print_exc()
    else:
        print("Pinecone index not initialized. Cannot delete namespace.")


def is_report_specific_question(question: str, report_data: Optional[Dict[str, Any]], report_type: Optional[str]) -> bool:
    """
    Heuristically determines if a question is specific to the loaded Nmap/ZAP/SSLScan/MobSF report.
    This check is performed only if a report is currently loaded.
    
    For MobSF reports, since report_data will be None, this relies solely on keywords.
    """
    # If no structured report data is loaded (which will be the case for MobSF)
    if report_data is None:
        question_lower = question.lower()
        if report_type == "mobsf":
            return any(keyword in question_lower for keyword in config.REPORT_SPECIFIC_KEYWORDS)
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

    return False

if __name__ == "__main__":
    dummy_nmap_data = {
        "scan_metadata": {
            "tool": "Nmap Scan Report", "scan_initiated_by": "Test User", "timestamp": "2023-10-27 10:00:00",
            "target": "example.com", "nmap_version": "7.92", "scan_type": "SYN Stealth Scan", "scan_duration": "10s"
        },
        "hosts": [
            {"ip_address": "192.168.1.1", "hostname": "host1.example.com", "status": "up",
             "os_detection": {"os_name": "Linux", "os_family": "Linux", "os_accuracy": "95%"},
             "ports": [
                 {"port_id": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "nginx 1.20.1", "script_output": "http-title: Welcome"},
                 {"port_id": 443, "protocol": "tcp", "state": "open", "service": "https", "version": "nginx 1.20.1", "script_output": "ssl-cert: self-signed"}
             ]},
            {"ip_address": "192.168.1.2", "hostname": "host2.example.com", "status": "up",
             "ports": [
                 {"port_id": 22, "protocol": "tcp", "state": "open", "service": "ssh"}
             ]}
        ]
    }

    dummy_zap_data = {
        "scan_metadata": {"tool": "Checkmarx ZAP Report", "site": "https://example.com", "generated_at": "2023-10-27"},
        "summary": {"risk_counts": {"High": 1, "Medium": 2, "Low": 0, "Informational": 3}, "total_alerts": 6},
        "vulnerabilities": [
            {"name": "SQL Injection", "risk": "High", "description": "SQL Injection vulnerability found.", "solution": "Use parameterized queries.", "urls": [{"url": "https://example.com/login", "method": "POST", "parameter": "username"}]},
            {"name": "Cross Site Scripting", "risk": "Medium", "description": "XSS vulnerability.", "solution": "Encode output.", "urls": [{"url": "https://example.com/search", "method": "GET", "parameter": "query"}]}
        ]
    }

    dummy_sslscan_data = {
        "scan_metadata": {"tool": "SSLScan Report", "target_host": "hackthissite.org", "connected_ip": "137.74.187.102"},
        "protocols": [
            {"name": "TLSv1.2", "status": "enabled"},
            {"name": "TLSv1.3", "status": "disabled"}
        ],
        "security_features": {
            "tls_fallback_scsv": "Server supports TLS Fallback SCSV",
            "heartbleed": "TLSv1.2 not vulnerable to heartbleed"
        },
        "supported_ciphers": [
            {"tls_version": "TLSv1.2", "bits": 256, "name": "ECDHE-RSA-AES256-GCM-SHA384", "curve": "P-256", "dhe": 256},
            {"tls_version": "TLSv1.2", "bits": 128, "name": "ECDHE-RSA-AES128-GCM-SHA256", "curve": "P-256", "dhe": 256}
        ],
        "ssl_certificate": {
            "subject": "CN=hackthissite.org", "issuer": "C=US, O=Let's Encrypt", "valid_from": "Apr 1 12:00:00 2024 GMT"
        }
    }

    dummy_mobsf_raw_text = """
    --- PAGE 1 ---
    MOBSF ANDROID STATIC ANALYSIS REPORT
    BitbarSampleApp (1.0)
    --- PAGE 2 ---
    File Name: bitbar-sample-app.apk
    Package Name: com.bitbar.testdroid
    Scan Date: April 19, 2025, 7:06 a.m.
    App Security Score: 32/100 (HIGH RISK)
    Grade: C
    --- PAGE 3 ---
    FINDINGS SEVERITY
    HIGH
    4
    MEDIUM
    0
    INFO
    1
    SECURE
    0
    FILE INFORMATION
    File Name: bitbar-sample-app.apk
    Size: 0.11MB
    MD5: 00cc5435151aa38a091781922c0390a4
    SHA1: 40e991508120d6f5d653a6755d8209df4d20289d
    SHA256: 3b4d462b8cce5f377a33417e1be7680717065f280a9f6e2f6af49325dbe89411
    APP INFORMATION
    App Name: BitbarSampleApp
    Package Name: com.bitbar.testdroid
    Main Activity: com.bitbar.testdroid. Bitbar SampleApplicationActivity
    Target SDK: 33
    Min SDK: 4
    Max SDK:
    Android Version Name: 1.0
    Android Version Code: 1
    --- PAGE 4 ---
    APP COMPONENTS
    Activities: 3
    Services: 0
    Receivers: 0
    Providers: 0
    Exported Activities: 2
    Exported Services: 0
    Exported Receivers: 0
    Exported Providers: 0
    CERTIFICATE INFORMATION
    Binary is signed
    v1 signature: True
    v2 signature: True
    X.509 Subject: CN=Android Debug, O=Android, C=US
    Signature Algorithm: rsassa_pkcs1v15
    Valid From: 2022-07-05 09:35:34+00:00
    Valid To: 2052-06-27 09:35:34+00:00
    Issuer: CN=Android Debug, O=Android, C=US
    APPLICATION PERMISSIONS
    "PERMISSION
    ","STATUS
    ","INFO
    ","DESCRIPTION
    "
    "android.permission.INTERNET
    ","normal
    ","full Internet access
    ","Allows an application to create network sockets.
    "
    --- PAGE 5 ---
    CODE ANALYSIS
    "NO
    ","ISSUE
    ","SEVERITY
    ","STANDARDS
    ","FILES
    "
    "1
    ","Debug configuration enabled. Production builds must not be debuggable.
    ","high
    ","CWE: CWE-919: Weaknesses in Mobile Applications
    ","com/bitbar/testdroid/BuildConfig.java
    "
    """

    if not os.environ.get("PINECONE_API_KEY"):
        print("Please set PINECONE_API_KEY environment variable to run RAG tests.")
        sys.exit(1)
    if not os.environ.get("PINECONE_ENVIRONMENT"):
        print("Please set PINECONE_ENVIRONMENT environment variable to run RAG tests.")
        sys.exit(1)

    print("--- Running RAG Utility Tests ---")

    report_namespace_nmap = None
    report_namespace_zap = None
    report_namespace_sslscan = None
    report_namespace_mobsf = None

    try:
        embedding_model_test = load_embedding_model()
        pinecone_index_test = initialize_pinecone_index()
        
        if not embedding_model_test or not pinecone_index_test:
            print("RAG components not loaded. Skipping tests that require Pinecone.")
            sys.exit(1)

        test_query_external = "What is SQL injection?"
        print(f"\nSearching for EXTERNAL RAG context for query: '{test_query_external}'")
        retrieved_context_external = retrieve_rag_context(test_query_external, namespace="owasp-cybersecurity-kb", top_k=2)
        if retrieved_context_external:
            print("\nRetrieved EXTERNAL RAG Context (OWASP KB):\n")
            print(retrieved_context_external)
        else:
            print("No EXTERNAL RAG context retrieved for general query.")
        
        print("\n" + "="*80 + "\n")

        print("Loading and upserting Nmap chunks to temporary namespace...")
        report_namespace_nmap = load_report_chunks_and_embeddings(dummy_nmap_data, "nmap")
        print(f"Nmap chunks upserted to namespace: {report_namespace_nmap}")

        if report_namespace_nmap:
            test_query_internal_nmap = "What services are running on host 192.168.1.1?"
            print(f"\nSearching for INTERNAL RAG context for query: '{test_query_internal_nmap}' (Nmap)")
            retrieved_context_internal_nmap = retrieve_internal_rag_context(test_query_internal_nmap, report_namespace_nmap, top_k=2)
            if retrieved_context_internal_nmap:
                print("\nRetrieved INTERNAL RAG Context (Nmap):\n")
                print(retrieved_context_internal_nmap)
            else:
                print("No INTERNAL RAG context retrieved for Nmap query.")

        print("\n" + "="*80 + "\n")

        print("Loading and upserting ZAP chunks to temporary namespace...")
        report_namespace_zap = load_report_chunks_and_embeddings(dummy_zap_data, "zap")
        print(f"ZAP chunks upserted to namespace: {report_namespace_zap}")

        if report_namespace_zap:
            test_query_internal_zap = "Details about the SQL Injection vulnerability."
            print(f"\nSearching for INTERNAL RAG context for query: '{test_query_internal_zap}' (ZAP)")
            retrieved_context_internal_zap = retrieve_internal_rag_context(test_query_internal_zap, report_namespace_zap, top_k=2)
            if retrieved_context_internal_zap:
                print("\nRetrieved INTERNAL RAG Context (ZAP):\n")
                print(retrieved_context_internal_zap)
            else:
                print("No INTERNAL RAG context retrieved for ZAP query.")
        
        print("\n" + "="*80 + "\n")

        print("Loading and upserting SSLScan chunks to temporary namespace...")
        report_namespace_sslscan = load_report_chunks_and_embeddings(dummy_sslscan_data, "sslscan")
        print(f"SSLScan chunks upserted to namespace: {report_namespace_sslscan}")

        if report_namespace_sslscan:
            test_query_internal_sslscan = "What are the supported TLS protocols and ciphers?"
            print(f"\nSearching for INTERNAL RAG context for query: '{test_query_internal_sslscan}' (SSLScan)")
            retrieved_context_internal_sslscan = retrieve_internal_rag_context(test_query_internal_sslscan, report_namespace_sslscan, top_k=2)
            if retrieved_context_internal_sslscan:
                print("\nRetrieved INTERNAL RAG Context (SSLScan):\n")
                print(retrieved_context_internal_sslscan)
            else:
                print("No INTERNAL RAG context retrieved for SSLScan query.")

        print("\n" + "="*80 + "\n")

        print("Loading and upserting MobSF raw text chunks to temporary namespace...")
        report_namespace_mobsf = load_report_chunks_and_embeddings(dummy_mobsf_raw_text, "mobsf")
        print(f"MobSF raw text chunks upserted to namespace: {report_namespace_mobsf}")

        if report_namespace_mobsf:
            test_query_internal_mobsf = "What is the app security score and grade?"
            print(f"\nSearching for INTERNAL RAG context for query: '{test_query_internal_mobsf}' (MobSF Raw)")
            retrieved_context_internal_mobsf = retrieve_internal_rag_context(test_query_internal_mobsf, report_namespace_mobsf, top_k=2)
            if retrieved_context_internal_mobsf:
                print("\nRetrieved INTERNAL RAG Context (MobSF Raw):\n")
                print(retrieved_context_internal_mobsf)
            else:
                print("No INTERNAL RAG context retrieved for MobSF raw query.")
        

    except Exception as e:
        print(f"An error occurred during INTERNAL RAG test: {e}")
        import traceback
        traceback.print_exc()
        print("Please ensure your SentenceTransformer model is valid and Pinecone is accessible.")
    finally:
        if report_namespace_nmap:
            delete_report_namespace(report_namespace_nmap)
        if report_namespace_zap:
            delete_report_namespace(report_namespace_zap)
        if report_namespace_sslscan:
            delete_report_namespace(report_namespace_sslscan)
        if report_namespace_mobsf:
            delete_report_namespace(report_namespace_mobsf)
