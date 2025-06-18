import os
import json
from sentence_transformers import SentenceTransformer, util # Added util for cosine similarity
from pinecone import Pinecone, ServerlessSpec, PodSpec
from typing import Dict, Any, List, Optional
import dotenv
import uuid # Added for generating unique namespace IDs
import sys

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
    DEFAULT_RAG_TOP_K
)

# Pinecone API Key and Environment are still fetched from os.environ
# as recommended for sensitive information
PINECONE_API_KEY = os.environ.get("PINECONE_API_KEY")
PINECONE_ENVIRONMENT = os.environ.get("PINECONE_ENVIRONMENT")


# Global variables to store loaded RAG components
_embedding_model: Optional[SentenceTransformer] = None
_pinecone_index: Optional[Any] = None # Using Any as Pinecone Index object type might vary


def load_embedding_model() -> SentenceTransformer:
    """
    Loads the fine-tuned SentenceTransformer model.
    Loads only once and caches the instance.
    """
    global _embedding_model
    if _embedding_model is None:
        print(f"Loading SentenceTransformer model from: {RAG_EMBEDDING_MODEL_PATH}")
        try:
            _embedding_model = SentenceTransformer(RAG_EMBEDDING_MODEL_PATH)
            print("SentenceTransformer model loaded successfully.")
        except Exception as e:
            print(f"Error loading SentenceTransformer model from {RAG_EMBEDDING_MODEL_PATH}: {e}")
            print("Please ensure the model path is correct and the model was saved properly (from S1-2_Model_Retraining.ipynb).")
            raise
    return _embedding_model

def initialize_pinecone_index() -> Any: # Returns a pinecone.Index object
    """
    Initializes the Pinecone connection and returns the index object.
    Initializes only once and caches the instance.
    """
    global _pinecone_index
    if _pinecone_index is None:
        print(f"Initializing Pinecone index: {PINECONE_INDEX_NAME}")
        if not PINECONE_API_KEY or not PINECONE_ENVIRONMENT:
            raise ValueError(
                "Pinecone API Key or Environment not set. "
                "Please set PINECONE_API_KEY and PINECONE_ENVIRONMENT "
                "environment variables."
            )
        try:
            pc = Pinecone(api_key=PINECONE_API_KEY, environment=PINECONE_ENVIRONMENT)
            
            # Check if index exists, if not, create it
            existing_indexes = [index_info.name for index_info in pc.list_indexes()]
            if PINECONE_INDEX_NAME not in existing_indexes:
                print(f"Pinecone index '{PINECONE_INDEX_NAME}' not found. Creating it...")
                
                # Determine spec based on your setup (Serverless vs PodSpec)
                # This should match how you created your index in S2_Embedding_Generation.ipynb
                if PINECONE_CLOUD and PINECONE_REGION: # Assuming Serverless if cloud/region are provided
                    spec = ServerlessSpec(cloud=PINECONE_CLOUD, region=PINECONE_REGION)
                else: # Fallback to PodSpec if specific cloud/region for Serverless are not set
                    spec = PodSpec(environment=PINECONE_ENVIRONMENT)

                pc.create_index(
                    name=PINECONE_INDEX_NAME,
                    dimension=PINECONE_EMBEDDING_DIMENSION,
                    metric=PINECONE_METRIC,
                    spec=spec
                )
                print(f"Pinecone index '{PINECONE_INDEX_NAME}' created.")
            
            _pinecone_index = pc.Index(PINECONE_INDEX_NAME)
            print("Pinecone index initialized successfully.")
        except Exception as e:
            print(f"Error initializing Pinecone index: {e}")
            raise
    return _pinecone_index

def retrieve_rag_context(query: str, top_k: int = DEFAULT_RAG_TOP_K, namespace: str = "owasp-cybersecurity-kb") -> str:
    """
    Generates an embedding for the query, queries Pinecone, and returns formatted context.

    Args:
        query (str): The user's question.
        top_k (int): The number of top relevant results to retrieve.
        namespace (str): The Pinecone namespace to query. (Kept hardcoded as it's a specific logical unit)

    Returns:
        str: Formatted retrieved context from the knowledge base, or an empty string if none found.
    """
    embedding_model = load_embedding_model()
    pinecone_index = initialize_pinecone_index()

    try:
        # Generate embedding for the query
        query_embedding = embedding_model.encode(query).tolist()

        # Query Pinecone
        response = pinecone_index.query(
            vector=query_embedding,
            top_k=top_k,
            include_metadata=True,
            namespace=namespace
        )

        context_parts = []
        for match in response.matches:
            metadata = match.metadata
            if metadata and "answer" in metadata:
                context_parts.append(f"Q: {metadata.get('question', 'N/A')}\nA: {metadata['answer']}")
            elif metadata and "text" in metadata: # Fallback if you stored general text
                context_parts.append(f"Context: {metadata['text']}")

        if context_parts:
            return "\n\nRelevant Information from Knowledge Base:\n" + "\n---\n".join(context_parts)
        else:
            return "" # No relevant context found

    except Exception as e:
        print(f"Error during RAG context retrieval: {e}")
        return f"Error retrieving context: {e}"


def _chunk_nmap_report(parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]: # Changed return type to include metadata
    """
    Extracts meaningful text chunks from parsed Nmap report data.
    Each chunk represents a specific finding or detail from the report,
    along with metadata.
    """
    chunks = []
    metadata = parsed_data.get("scan_metadata", {})
    
    # Chunk 1: Overall summary
    chunks.append({
        "text": f"Nmap Scan Summary: Target {metadata.get('target', 'N/A')}, Type {metadata.get('scan_type', 'N/A')}.",
        "id_suffix": "summary"
    })

    for i, host in enumerate(parsed_data.get("hosts", [])):
        host_ip = host.get('ip_address', 'N/A')
        host_hostname = host.get('hostname', 'N/A')
        host_info = f"Host {host_hostname} ({host_ip})"

        # Chunk for host status and OS
        chunks.append({
            "text": f"{host_info} status: {host.get('status', 'N/A')}. OS: {', '.join(host.get('os_detection', {}).get('os_guesses', ['N/A']))}.",
            "id_suffix": f"host_info_{host_ip}"
        })

        for port in host.get("ports", []):
            port_id = port.get('port_id')
            protocol = port.get('protocol')
            service = port.get('service')
            version = port.get('version', 'N/A')
            state = port.get('state')

            port_info_text = (
                f"{host_info} has port {port_id}/{protocol} "
                f"({service}, version: {version}) in state: {state}."
            )
            chunks.append({
                "text": port_info_text,
                "id_suffix": f"port_{host_ip}_{port_id}_{protocol}"
            })

            if port.get('script_outputs'):
                for script_name, script_output in port['script_outputs'].items():
                    # Limit script output length for chunking
                    script_chunk_text = f"{host_info} port {port_id}/{protocol} script output for {script_name}: {script_output[:300]}..."
                    chunks.append({
                        "text": script_chunk_text,
                        "id_suffix": f"script_{host_ip}_{port_id}_{script_name.replace(' ', '_')}"
                    })
    return chunks

def _chunk_zap_report(parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]: # Changed return type to include metadata
    """
    Extracts meaningful text chunks from parsed ZAP report data.
    Each chunk represents a specific vulnerability instance, along with metadata.
    """
    chunks = []
    metadata = parsed_data.get("scan_metadata", {})
    
    # Chunk 1: Overall summary
    chunks.append({
        "text": f"ZAP Scan Summary: Site {metadata.get('site', 'N/A')}, total alerts: {parsed_data.get('summary', {}).get('total_alerts', 0)}.",
        "id_suffix": "summary"
    })

    for i, vuln in enumerate(parsed_data.get("vulnerabilities", [])):
        vuln_name = vuln.get('name', 'N/A')
        vuln_risk = vuln.get('risk', 'N/A')
        vuln_desc = vuln.get('description', 'N/A')
        vuln_solution = vuln.get('solution', 'N/A')
        cwe_id = vuln.get('cwe_id', 'N/A')
        wasc_id = vuln.get('wasc_id', 'N/A')

        # Base chunk for the vulnerability
        base_vuln_chunk = {
            "text": (
                f"Vulnerability: {vuln_name} (Risk: {vuln_risk}). "
                f"Description: {vuln_desc[:500]}... " # Increased desc length for better context
                f"Solution: {vuln_solution[:500]}..." # Increased solution length
                f"CWE-ID: {cwe_id}, WASC-ID: {wasc_id}."
            ),
            "id_suffix": f"vuln_{vuln_name.replace(' ', '_')}_{i}"
        }
        chunks.append(base_vuln_chunk)

        # Add chunks for individual affected URLs/instances
        for j, instance in enumerate(vuln.get('urls', [])):
            instance_url = instance.get('url', 'N/A')
            instance_method = instance.get('method', 'N/A')
            instance_param = instance.get('parameter', 'N/A')
            instance_attack = instance.get('attack', 'N/A')
            instance_evidence = instance.get('evidence', 'N/A')

            instance_chunk_text = (
                f"Instance of '{vuln_name}' at URL: {instance_url}, "
                f"Method: {instance_method}, Parameter: {instance_param}, "
                f"Attack: {instance_attack[:200]}..., Evidence: {instance_evidence[:200]}..."
            )
            chunks.append({
                "text": instance_chunk_text,
                "id_suffix": f"instance_{vuln_name.replace(' ', '_')}_{j}"
            })
    return chunks

def _chunk_sslscan_report(parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extracts meaningful text chunks from parsed SSLScan report data.
    Each chunk represents a specific finding or detail from the report,
    along with metadata.
    """
    chunks = []
    metadata = parsed_data.get("scan_metadata", {})
    
    # Chunk 1: Overall summary
    chunks.append({
        "text": (f"SSLScan Summary: Target host {metadata.get('target_host', 'N/A')}, "
                 f"Connected IP {metadata.get('connected_ip', 'N/A')}. "
                 f"Scan performed at {metadata.get('timestamp', 'N/A')} "
                 f"with tool version {metadata.get('tool_version', 'N/A')} and OpenSSL {metadata.get('openssl_version', 'N/A')}."
                 ),
        "id_suffix": "sslscan_summary"
    })

    # Chunk 2: Protocols status
    protocols_text = "SSL/TLS Protocols: " + ", ".join([f"{p.get('name', 'N/A')} {p.get('status', 'N/A')}" for p in parsed_data.get('protocols', [])])
    chunks.append({
        "text": protocols_text,
        "id_suffix": "sslscan_protocols"
    })

    # Chunk 3: Security features
    security_features_text = "TLS Security Features: "
    features = []
    for feature, status in parsed_data.get('security_features', {}).items():
        if isinstance(status, list):
            features.append(f"{feature.replace('_', ' ').title()}: {', '.join(status)}")
        else:
            features.append(f"{feature.replace('_', ' ').title()}: {status}")
    security_features_text += ", ".join(features)
    chunks.append({
        "text": security_features_text,
        "id_suffix": "sslscan_security_features"
    })

    # Chunk 4: Supported Ciphers
    if parsed_data.get('supported_ciphers'):
        ciphers_text = "Supported Server Ciphers: " + "; ".join([
            f"{c.get('status', 'N/A')} {c.get('name', 'N/A')} ({c.get('bits', 'N/A')} bits, TLS {c.get('tls_version', 'N/A')})"
            for c in parsed_data['supported_ciphers']
        ])
        chunks.append({
            "text": ciphers_text,
            "id_suffix": "sslscan_ciphers"
        })

    # Chunk 5: Key Exchange Groups
    if parsed_data.get('key_exchange_groups'):
        kex_groups_text = "Server Key Exchange Groups: " + "; ".join([
            f"{g.get('name', 'N/A')} ({g.get('details', 'N/A')}, {g.get('bits', 'N/A')} bits, TLS {g.get('tls_version', 'N/A')})"
            for g in parsed_data['key_exchange_groups']
        ])
        chunks.append({
            "text": kex_groups_text,
            "id_suffix": "sslscan_kex_groups"
        })

    # Chunk 6: SSL Certificate Details
    certificate = parsed_data.get('ssl_certificate', {})
    if certificate:
        cert_details_text = (
            f"SSL Certificate: Subject '{certificate.get('subject', 'N/A')}', "
            f"Issuer '{certificate.get('issuer', 'N/A')}', "
            f"Signature Algorithm '{certificate.get('signature_algorithm', 'N/A')}', "
            f"RSA Key Strength {certificate.get('rsa_key_strength', 'N/A')} bits. "
            f"Valid from {certificate.get('not_valid_before', 'N/A')} to {certificate.get('not_valid_after', 'N/A')}. "
            f"Altnames: {', '.join(certificate.get('altnames', ['N/A']))}."
        )
        chunks.append({
            "text": cert_details_text,
            "id_suffix": "sslscan_certificate"
        })

    return chunks


def load_report_chunks_and_embeddings(parsed_report_data: Dict[str, Any], report_type: str) -> str:
    """
    Orchestrates the chunking and embedding process for a newly loaded report,
    and upserts them into a temporary Pinecone namespace unique to the session.
    Returns the generated namespace ID.
    """
    embedding_model = load_embedding_model() # Ensure model is loaded
    pinecone_index = initialize_pinecone_index() # Ensure index is initialized

    if report_type.lower() == "nmap":
        raw_chunks_with_metadata = _chunk_nmap_report(parsed_report_data)
    elif report_type.lower() == "zap":
        raw_chunks_with_metadata = _chunk_zap_report(parsed_report_data)
    elif report_type.lower() == "sslscan": # New condition for SSLScan
        raw_chunks_with_metadata = _chunk_sslscan_report(parsed_report_data)
    else:
        print(f"Warning: Unknown report type '{report_type}'. Cannot chunk report.")
        return ""

    if not raw_chunks_with_metadata:
        print(f"No chunks generated for the {report_type.upper()} report.")
        return ""

    print(f"Generated {len(raw_chunks_with_metadata)} chunks for the {report_type.upper()} report. Generating embeddings and upserting to Pinecone...")
    
    # Generate a unique namespace ID for this report session
    report_namespace = f"report-{uuid.uuid4()}"
    print(f"Using temporary Pinecone namespace: {report_namespace}")

    vectors_to_upsert = []
    # For batching if many chunks:
    batch_size = 100 

    for i, chunk_data in enumerate(raw_chunks_with_metadata):
        chunk_text = chunk_data["text"]
        # Generate embedding (removed .tolist() as convert_to_numpy=False returns list)
        chunk_embedding = embedding_model.encode(chunk_text, convert_to_numpy=False) # Fix: removed .tolist()
        
        # Create a unique ID for each vector within the namespace
        vector_id = f"{chunk_data.get('id_suffix', f'chunk-{i}')}"
        
        vectors_to_upsert.append({
            "id": vector_id,
            "values": chunk_embedding,
            "metadata": {"text": chunk_text, "report_type": report_type, "chunk_index": i}
        })

        if len(vectors_to_upsert) >= batch_size:
            pinecone_index.upsert(vectors=vectors_to_upsert, namespace=report_namespace)
            vectors_to_upsert = []
    
    # Upsert any remaining vectors
    if vectors_to_upsert:
        pinecone_index.upsert(vectors=vectors_to_upsert, namespace=report_namespace)

    print(f"Successfully upserted {len(raw_chunks_with_metadata)} embeddings to Pinecone namespace: {report_namespace}")
    
    return report_namespace # Return the namespace ID for later retrieval


def retrieve_internal_rag_context(query: str, report_namespace: str, top_k: int = 3) -> str:
    """
    Retrieves the most relevant text chunks from the temporary Pinecone namespace
    for the current report, based on the user's query.

    Args:
        query (str): The user's question.
        report_namespace (str): The unique Pinecone namespace for the current report.
        top_k (int): The number of top relevant results to retrieve.

    Returns:
        str: Formatted relevant context from the report, or an empty string if none found.
    """
    if not report_namespace:
        return "" # No report namespace provided

    embedding_model = load_embedding_model()
    pinecone_index = initialize_pinecone_index()

    try:
        query_embedding = embedding_model.encode(query).tolist() # query_embedding should still be a list

        # Query the specific report namespace
        response = pinecone_index.query(
            vector=query_embedding,
            top_k=top_k,
            include_metadata=True,
            namespace=report_namespace # Query the specific report namespace
        )

        context_parts = []
        for match in response.matches:
            # You can set a minimum similarity threshold if desired
            # if match["similarity"] > 0.5: # Example threshold
            metadata = match.metadata
            if metadata and "text" in metadata:
                context_parts.append(metadata["text"])
        
        if context_parts:
            return "\n\nRelevant Information from Current Report:\n" + "\n---\n".join(context_parts)
        else:
            return "" # No relevant context found

    except Exception as e:
        print(f"Error during internal RAG context retrieval: {e}")
        return f"Error retrieving report context: {e}"

def delete_report_namespace(report_namespace: str):
    """
    Deletes a specific Pinecone namespace used for a report session.
    Call this when a new report is loaded or the application exits.
    """
    if not report_namespace:
        return

    pinecone_index = initialize_pinecone_index()
    try:
        print(f"Deleting Pinecone namespace: {report_namespace}...")
        pinecone_index.delete(delete_all=True, namespace=report_namespace)
        print(f"Namespace '{report_namespace}' deleted successfully.")
    except Exception as e:
        print(f"Error deleting Pinecone namespace '{report_namespace}': {e}")
        # import traceback
        # traceback.print_exc() # For debugging, if needed

# Example usage (for testing chatbot_utils.py directly)
if __name__ == "__main__":
    print("--- Testing chatbot_utils.py directly ---")
    print("Ensure PINECONE_API_KEY and PINECONE_ENVIRONMENT are set as environment variables.")
    print("Also ensure RAG_EMBEDDING_MODEL_PATH in config.py points to your fine-tuned model.")
    
    # --- Test General RAG Retrieval (External Knowledge) ---
    try:
        model = load_embedding_model() # Ensure model is loaded for general RAG
        # Pinecone index will be initialized if retrieve_rag_context is called
        
        test_query_external = "What is SQL injection?"
        print(f"\nSearching for EXTERNAL RAG context for query: '{test_query_external}'")
        retrieved_context_external = retrieve_rag_context(test_query_external)
        
        if retrieved_context_external:
            print("\nRetrieved EXTERNAL RAG Context:")
            print(retrieved_context_external)
        else:
            print("No EXTERNAL RAG context retrieved.")

    except Exception as e:
        print(f"An error occurred during EXTERNAL RAG test: {e}")
        import traceback
        traceback.print_exc()
        print("Please ensure your external RAG setup is correct (Pinecone API, Environment, Index, and Model Path).")

    print("\n" + "="*50 + "\n")

    # --- Test Internal RAG Retrieval (Report-Specific Knowledge in Temporary Namespace) ---
    # Dummy Nmap parsed data for testing internal RAG
    dummy_nmap_data = {
        "scan_metadata": {
            "scan_initiated_by": "User", "timestamp": "Fri Jun 18 10:00:00 2025 IST",
            "target": "example.com (192.168.1.1)", "nmap_version": "7.92",
            "scan_type": "Port Scan", "scan_duration": "10.5 seconds"
        },
        "hosts": [
            {
                "ip_address": "192.168.1.1", "hostname": "example.com", "status": "up", "latency": "0.002s",
                "os_detection": {"os_guesses": ["Linux 3.10 - 4.11"], "device_type": ["general purpose"]},
                "ports": [
                    {"port_id": 22, "protocol": "tcp", "state": "open", "service": "ssh",
                     "version": "OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)",
                     "script_outputs": {"ssh-hostkey": "2048 SHA256:abcd... (RSA). Weak algorithms detected."}
                    },
                    {"port_id": 80, "protocol": "tcp", "state": "open", "service": "http",
                     "version": "Apache httpd 2.4.29 ((Ubuntu))",
                     "script_outputs": {"http-title": "Apache2 Ubuntu Default Page", "http-security-headers": "Missing X-Frame-Options"}
                    }
                ]
            }
        ]
    }

    # Dummy ZAP parsed data for testing internal RAG
    dummy_zap_data = {
        "scan_metadata": {
            "tool": "Checkmarx ZAP Report", "report_id": "12345-abcde", "generated_at": "2025-06-18T10:05:00",
            "site": "http://testphp.vulnweb.com", "zap_version": "2.10.0"
        },
        "summary": {
            "risk_counts": {"High": 1, "Medium": 2, "Low": 3, "Informational": 5, "False Positives": 0},
            "total_alerts": 11
        },
        "vulnerabilities": [
            {
                "name": "SQL Injection", "risk": "High",
                "description": "SQL Injection vulnerability found in parameter 'id' on products page. Highly critical due to data exposure.",
                "urls": [{"url": "http://testphp.vulnweb.com/listproducts.php?cat=1", "method": "GET", "parameter": "id", "attack": "id=1'%20OR%201=1--", "evidence": "Error message with SQL syntax"}],
                "solution": "Use parameterized queries or prepared statements to prevent SQL injection. Validate and sanitize all user input."
            },
            {
                "name": "Cross Site Scripting (XSS)", "risk": "Medium",
                "description": "Reflected XSS vulnerability identified on search page. Allows attacker to inject malicious scripts.",
                "urls": [{"url": "http://testphp.vulnweb.com/search.php?test=1", "method": "GET", "parameter": "test", "attack": "<script>alert(1)</script>", "evidence": "Reflected script in response"}],
                "solution": "Implement proper input validation and output encoding for all user-supplied data to prevent XSS."
            }
        ]
    }

    # Dummy SSLScan parsed data for testing internal RAG (new)
    dummy_sslscan_data = {
        "scan_metadata": {
            "tool": "SSLScan Report",
            "initiated_by": "Maaz",
            "timestamp": "2025-04-19 12:29:21",
            "target_host": "hackthissite.org",
            "tool_version": "2.1.5",
            "openssl_version": "3.4.0",
            "connected_ip": "137.74.187.102",
            "tested_server": "hackthissite.org",
            "tested_port": 443,
            "sni_name": "hackthissite.org"
        },
        "protocols": [
            {"name": "SSLv2", "status": "disabled"},
            {"name": "SSLv3", "status": "disabled"},
            {"name": "TLSv1.0", "status": "disabled"},
            {"name": "TLSv1.1", "status": "disabled"},
            {"name": "TLSv1.2", "status": "enabled"},
            {"name": "TLSv1.3", "status": "disabled"}
        ],
        "security_features": {
            "tls_fallback_scsv": "Server supports TLS Fallback SCSV",
            "tls_renegotiation": "Session renegotiation not supported",
            "tls_compression": "Compression disabled",
            "heartbleed": ["TLSv1.2 not vulnerable to heartbleed"]
        },
        "supported_ciphers": [
            {"status": "Preferred", "tls_version": "TLSv1.2", "bits": 256, "name": "ECDHE-RSA-AES256-GCM-SHA384", "curve": "P-256", "dhe_bits": 256},
            {"status": "Accepted", "tls_version": "TLSv1.2", "bits": 128, "name": "ECDHE-RSA-AES128-GCM-SHA256", "curve": "P-256", "dhe_bits": 256}
        ],
        "key_exchange_groups": [
            {"tls_version": "TLSv1.2", "bits": 128, "name": "secp256r1", "details": "NIST P-256"}
        ],
        "ssl_certificate": {
            "signature_algorithm": "sha256WithRSAEncryption",
            "rsa_key_strength": 4096,
            "subject": "hackthisjogneh42n5o7gbzrewxee3vyu6ex37ukyvdw6jm66npakiyd.onion",
            "altnames": ["DNS: hackthissite.org", "DNS:www.hackthissite.org"],
            "issuer": "HARICA DV TLS RSA",
            "not_valid_before": "Mar 25 04:43:22 2025 GMT",
            "not_valid_after": "Mar 25 04:43:22 2026 GMT"
        }
    }


    report_namespace_nmap = None
    report_namespace_zap = None
    report_namespace_sslscan = None # New variable for SSLScan namespace

    try:
        # Load and upsert Nmap chunks
        print("\nLoading and upserting Nmap chunks to temporary namespace...")
        report_namespace_nmap = load_report_chunks_and_embeddings(dummy_nmap_data, "nmap")
        print(f"Nmap chunks upserted to namespace: {report_namespace_nmap}")

        # Test internal RAG with Nmap data
        if report_namespace_nmap:
            test_query_internal_nmap = "Tell me about the SSH service on 192.168.1.1."
            print(f"\nSearching for INTERNAL RAG context for query: '{test_query_internal_nmap}' (Nmap)")
            retrieved_context_internal_nmap = retrieve_internal_rag_context(test_query_internal_nmap, report_namespace_nmap, top_k=2)
            if retrieved_context_internal_nmap:
                print("\nRetrieved INTERNAL RAG Context (Nmap):")
                print(retrieved_context_internal_nmap)
            else:
                print("No INTERNAL RAG context retrieved for Nmap query.")

        # Load and upsert ZAP chunks
        print("\nLoading and upserting ZAP chunks to temporary namespace...")
        report_namespace_zap = load_report_chunks_and_embeddings(dummy_zap_data, "zap")
        print(f"ZAP chunks upserted to namespace: {report_namespace_zap}")

        # Test internal RAG with ZAP data
        if report_namespace_zap:
            test_query_internal_zap = "Details about the SQL Injection vulnerability."
            print(f"\nSearching for INTERNAL RAG context for query: '{test_query_internal_zap}' (ZAP)")
            retrieved_context_internal_zap = retrieve_internal_rag_context(test_query_internal_zap, report_namespace_zap, top_k=2)
            if retrieved_context_internal_zap:
                print("\nRetrieved INTERNAL RAG Context (ZAP):")
                print(retrieved_context_internal_zap)
            else:
                print("No INTERNAL RAG context retrieved for ZAP query.")
        
        # Load and upsert SSLScan chunks (new test block)
        print("\nLoading and upserting SSLScan chunks to temporary namespace...")
        report_namespace_sslscan = load_report_chunks_and_embeddings(dummy_sslscan_data, "sslscan")
        print(f"SSLScan chunks upserted to namespace: {report_namespace_sslscan}")

        # Test internal RAG with SSLScan data
        if report_namespace_sslscan:
            test_query_internal_sslscan = "What are the supported TLS protocols and ciphers?"
            print(f"\nSearching for INTERNAL RAG context for query: '{test_query_internal_sslscan}' (SSLScan)")
            retrieved_context_internal_sslscan = retrieve_internal_rag_context(test_query_internal_sslscan, report_namespace_sslscan, top_k=2)
            if retrieved_context_internal_sslscan:
                print("\nRetrieved INTERNAL RAG Context (SSLScan):")
                print(retrieved_context_internal_sslscan)
            else:
                print("No INTERNAL RAG context retrieved for SSLScan query.")


    except Exception as e:
        print(f"An error occurred during INTERNAL RAG test: {e}")
        import traceback
        traceback.print_exc()
        print("Please ensure your SentenceTransformer model is valid and Pinecone is accessible.")
    finally:
        # Clean up temporary namespaces after testing
        if report_namespace_nmap:
            delete_report_namespace(report_namespace_nmap)
        if report_namespace_zap:
            delete_report_namespace(report_namespace_zap)
        if report_namespace_sslscan: # New cleanup
            delete_report_namespace(report_namespace_sslscan)
