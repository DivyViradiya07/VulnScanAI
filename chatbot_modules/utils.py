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


def _chunk_nmap_report(parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extracts meaningful text chunks from parsed Nmap report data.
    Each chunk represents a specific finding or detail from the report,
    along with metadata.
    """
    chunks = []
    metadata = parsed_data.get("scan_metadata", {})
    
    # Chunk 1: Overall scan metadata (more detailed)
    scan_summary_text = (
        f"Nmap Scan Summary: Target {metadata.get('target', 'N/A')}, "
        f"Scan Type: {metadata.get('scan_type', 'N/A')}, "
        f"Nmap Version: {metadata.get('nmap_version', 'N/A')}. "
        f"Scan started at {metadata.get('scan_start_time', 'N/A')} "
        f"and completed in {metadata.get('scan_duration', 'N/A')}."
    )
    chunks.append({
        "text": scan_summary_text,
        "id_suffix": "nmap_scan_summary"
    })

    for i, host in enumerate(parsed_data.get("hosts", [])):
        host_ip = host.get('ip_address', 'N/A')
        host_hostname = host.get('hostname', 'N/A')
        
        # Host Status Chunk
        chunks.append({
            "text": f"Host {host_hostname} ({host_ip}) status: {host.get('status', 'N/A')}.",
            "id_suffix": f"nmap_host_status_{host_ip}"
        })

        # Host Details Chunk
        host_details_text = f"Host {host_hostname} ({host_ip}) details:"
        details = []
        if host.get('mac_address') and host['mac_address'] != 'N/A':
            details.append(f"MAC Address: {host['mac_address']}")
        if host.get('network_distance'):
            details.append(f"Network Distance: {host['network_distance']} hops")
        if host.get('latency') and host['latency'] != 'N/A':
            details.append(f"Latency: {host['latency']}")
        if host.get('rdns') and host['rdns'] != 'N/A':
            details.append(f"Reverse DNS: {host['rdns']}")
        if host.get('other_addresses'):
            details.append(f"Other Addresses: {', '.join(host['other_addresses'])}")
        
        if details:
            host_details_text += " " + ", ".join(details) + "."
            chunks.append({
                "text": host_details_text,
                "id_suffix": f"nmap_host_details_{host_ip}"
            })

        # OS Detection Chunks (more granular)
        os_detection = host.get('os_detection', {})
        if os_detection.get('os_guesses'):
            chunks.append({
                "text": f"Host {host_hostname} ({host_ip}) OS guesses: {', '.join(os_detection['os_guesses'])}.",
                "id_suffix": f"nmap_os_guesses_{host_ip}"
            })
        if os_detection.get('aggressive_os_guesses'):
            chunks.append({
                "text": f"Host {host_hostname} ({host_ip}) Aggressive OS guesses: {', '.join(os_detection['aggressive_os_guesses'])}.",
                "id_suffix": f"nmap_aggressive_os_guesses_{host_ip}"
            })
        if os_detection.get('device_type'):
            chunks.append({
                "text": f"Host {host_hostname} ({host_ip}) Device Type: {', '.join(os_detection['device_type'])}.",
                "id_suffix": f"nmap_device_type_{host_ip}"
            })
        if os_detection.get('os_cpe'):
            chunks.append({
                "text": f"Host {host_hostname} ({host_ip}) OS CPE: {', '.join(os_detection['os_cpe'])}.",
                "id_suffix": f"nmap_os_cpe_{host_ip}"
            })
        if os_detection.get('no_exact_match_reason'):
             chunks.append({
                "text": f"Host {host_hostname} ({host_ip}) OS detection reason for no exact match: {os_detection.get('no_exact_match_reason')}.",
                "id_suffix": f"nmap_no_exact_os_match_reason_{host_ip}"
            })


        for j, port in enumerate(host.get("ports", [])):
            port_id = port.get('port_id')
            protocol = port.get('protocol')
            service = port.get('service')
            version = port.get('version', 'N/A')
            state = port.get('state')

            # Individual Port Information Chunk
            port_info_text = (
                f"Host {host_hostname} ({host_ip}) has port {port_id}/{protocol} "
                f"in state '{state}'. Service: '{service}'"
            )
            if version and version != 'N/A':
                port_info_text += f", Version: '{version}'."
            else:
                port_info_text += "."

            chunks.append({
                "text": port_info_text,
                "id_suffix": f"nmap_port_info_{host_ip}_{port_id}_{protocol}"
            })

            # Script Outputs for each port (can be many, so iterate)
            if port.get('script_outputs'):
                for script_name, script_output in port['script_outputs'].items():
                    # Limit script output length for chunking, indicate truncation
                    script_chunk_text = (
                        f"Script output for Host {host_hostname} ({host_ip}) "
                        f"on port {port_id}/{protocol} (script: {script_name}): "
                        f"{script_output[:500]}{'...' if len(script_output) > 500 else ''}"
                    )
                    chunks.append({
                        "text": script_chunk_text,
                        "id_suffix": f"nmap_script_output_{host_ip}_{port_id}_{script_name.replace(' ', '_')}"
                    })
        
        # Traceroute Chunks (per hop)
        if host.get('traceroute'):
            for k, hop in enumerate(host['traceroute']):
                hop_text = (
                    f"Traceroute for Host {host_hostname} ({host_ip}): "
                    f"Hop {hop.get('hop', 'N/A')}: Address '{hop.get('address', 'N/A')}' "
                    f"with RTT '{hop.get('rtt', 'N/A')}'."
                )
                chunks.append({
                    "text": hop_text,
                    "id_suffix": f"nmap_traceroute_{host_ip}_hop_{k}"
                })
                
    return chunks

def _chunk_zap_report(parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extracts meaningful text chunks from parsed ZAP report data, with increased granularity.
    Each chunk represents a specific vulnerability instance, along with metadata.
    """
    chunks = []
    metadata = parsed_data.get("scan_metadata", {})
    
    # Chunk 1: Overall scan metadata (more detailed)
    scan_summary_text = (
        f"ZAP Scan Summary: Site {metadata.get('site', 'N/A')}, "
        f"Report ID: {metadata.get('report_id', 'N/A')}, "
        f"Generated At: {metadata.get('generated_at', 'N/A')}, "
        f"ZAP Version: {metadata.get('zap_version', 'N/A')}. "
        f"Total alerts: {parsed_data.get('summary', {}).get('total_alerts', 0)}."
    )
    chunks.append({
        "text": scan_summary_text,
        "id_suffix": "zap_scan_metadata_summary"
    })

    # Chunk 2: Alerts by Risk Counts
    risk_counts = parsed_data.get('summary', {}).get('risk_counts', {})
    if risk_counts:
        risk_summary_text = "ZAP Alert Counts by Risk Level: "
        risk_details = []
        for risk_level, count in risk_counts.items():
            risk_details.append(f"{risk_level}: {count}")
        if risk_details:
            risk_summary_text += ", ".join(risk_details) + "."
            chunks.append({
                "text": risk_summary_text,
                "id_suffix": "zap_risk_counts_summary"
            })

    # Chunk 3 (and subsequent): Alerts by Name Summary
    alerts_by_name = parsed_data.get('summary', {}).get('alerts_by_name', [])
    for alert_sum in alerts_by_name:
        alert_name = alert_sum.get('name', 'N/A')
        alert_risk = alert_sum.get('risk_level', 'N/A')
        alert_instances = alert_sum.get('instances_count', 0)
        chunks.append({
            "text": f"Alert Summary: '{alert_name}' has a risk level of '{alert_risk}' with {alert_instances} instances.",
            "id_suffix": f"zap_alert_name_summary_{alert_name.replace(' ', '_')}"
        })

    for i, vuln in enumerate(parsed_data.get("vulnerabilities", [])):
        vuln_name = vuln.get('name', 'N/A')
        vuln_risk = vuln.get('risk', 'N/A')
        vuln_desc = vuln.get('description', 'N/A')
        vuln_solution = vuln.get('solution', 'N/A')
        cwe_id = vuln.get('cwe_id', 'N/A')
        wasc_id = vuln.get('wasc_id', 'N/A')
        plugin_id = vuln.get('plugin_id', 'N/A')

        # Chunk 4: Core Vulnerability Identification (more concise)
        core_vuln_chunk = {
            "text": (
                f"Vulnerability ID: {vuln.get('id', 'N/A')}, Name: '{vuln_name}' (Risk: {vuln_risk}). "
                f"CWE-ID: {cwe_id}, WASC-ID: {wasc_id}, Plugin ID: {plugin_id}."
            ),
            "id_suffix": f"zap_vuln_core_info_{vuln_name.replace(' ', '_')}_{i}"
        }
        chunks.append(core_vuln_chunk)

        # Chunk 5: Vulnerability Description (separate chunk for detailed text)
        if vuln_desc and vuln_desc != 'N/A':
            chunks.append({
                "text": f"Description for '{vuln_name}': {vuln_desc}",
                "id_suffix": f"zap_vuln_description_{vuln_name.replace(' ', '_')}_{i}"
            })

        # Chunk 6: Vulnerability Solution (separate chunk for detailed text)
        if vuln_solution and vuln_solution != 'N/A':
            chunks.append({
                "text": f"Solution for '{vuln_name}': {vuln_solution}",
                "id_suffix": f"zap_vuln_solution_{vuln_name.replace(' ', '_')}_{i}"
            })
        
        # Chunk 7: Vulnerability References (separate chunk for each reference or a list)
        if vuln.get('references'):
            references_text = f"References for '{vuln_name}': " + ", ".join(vuln['references']) + "."
            chunks.append({
                "text": references_text,
                "id_suffix": f"zap_vuln_references_{vuln_name.replace(' ', '_')}_{i}"
            })


        # Chunk 8 (and subsequent for each instance): Individual Affected URLs/Instances
        for j, instance in enumerate(vuln.get('urls', [])):
            instance_url = instance.get('url', 'N/A')
            instance_method = instance.get('method', 'N/A')
            instance_param = instance.get('parameter', 'N/A')
            instance_attack = instance.get('attack', 'N/A')
            instance_evidence = instance.get('evidence', 'N/A')
            instance_severity = instance.get('severity', 'N/A') # Often the same as vuln_risk but good to include if varied
            instance_confidence = instance.get('confidence', 'N/A')
            instance_other = instance.get('other', 'N/A')
            instance_alert_ref = instance.get('alertRef', 'N/A')

            instance_chunk_text = (
                f"Instance {j+1} of '{vuln_name}' (Risk: {instance_severity}, Confidence: {instance_confidence}) "
                f"at URL: {instance_url}, Method: {instance_method}, Parameter: {instance_param}. "
                f"Attack: {instance_attack[:500]}{'...' if len(instance_attack) > 500 else ''}, "
                f"Evidence: {instance_evidence[:500]}{'...' if len(instance_evidence) > 500 else ''}. "
                f"Other Info: {instance_other[:200]}{'...' if len(instance_other) > 200 else ''}, "
                f"Alert Ref: {instance_alert_ref}."
            )
            chunks.append({
                "text": instance_chunk_text,
                "id_suffix": f"zap_vuln_instance_{vuln_name.replace(' ', '_')}_{i}_{j}"
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

def _chunk_mobsf_android_report(parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extracts relevant information from a parsed MobSF Android report and
    structures it into smaller, meaningful text chunks for RAG.
    """
    chunks = []
    
    # --- Scan Metadata ---
    scan_metadata = parsed_data.get("scan_metadata", {})
    chunks.append({
        "text": (
            f"MobSF Scan Report ID: {scan_metadata.get('report_id', 'N/A')}. "
            f"Tool Version: {scan_metadata.get('mobsf_version', 'N/A')}. "
            f"Scan Date: {scan_metadata.get('scan_date', 'N/A')}."
        ),
        "id_suffix": "mobsf_scan_metadata"
    })
    chunks.append({
        "text": (
            f"MobSF App Security Score: {scan_metadata.get('app_security_score', 'N/A')}. "
            f"Grade: {scan_metadata.get('grade', 'N/A')}."
        ),
        "id_suffix": "mobsf_security_score"
    })
    chunks.append({
        "text": (
            f"MobSF Scanned File Name: {scan_metadata.get('file_name', 'N/A')}. "
            f"Package Name: {scan_metadata.get('package_name', 'N/A')}."
        ),
        "id_suffix": "mobsf_file_package_name"
    })

    # --- Summary of Findings ---
    summary = parsed_data.get("summary", {})
    chunks.append({
        "text": f"MobSF Overall Total Issues: {summary.get('total_issues', 0)}.",
        "id_suffix": "mobsf_total_issues"
    })
    findings_severity = summary.get("findings_severity", {})
    if findings_severity:
        for severity, count in findings_severity.items():
            chunks.append({
                "text": f"MobSF Issues by Severity: {severity} - {count}.",
                "id_suffix": f"mobsf_issues_severity_{severity.lower()}"
            })

    # --- File Information ---
    file_info = parsed_data.get("file_information", {})
    if file_info:
        chunks.append({
            "text": (
                f"MobSF File Information: Name - {file_info.get('File Name', 'N/A')}, "
                f"Size - {file_info.get('Size', 'N/A')}."
            ),
            "id_suffix": "mobsf_file_general_info"
        })
        chunks.append({
            "text": (
                f"MobSF File Hashes: MD5 - {file_info.get('MD5', 'N/A')}, "
                f"SHA1 - {file_info.get('SHA1', 'N/A')}, "
                f"SHA256 - {file_info.get('SHA256', 'N/A')}."
            ),
            "id_suffix": "mobsf_file_hashes"
        })

    # --- App Information ---
    app_info = parsed_data.get("app_information", {})
    if app_info:
        chunks.append({
            "text": (
                f"MobSF App Details: App Name - {app_info.get('App Name', 'N/A')}, "
                f"Package Name - {app_info.get('Package Name', 'N/A')}."
            ),
            "id_suffix": "mobsf_app_basic_info"
        })
        chunks.append({
            "text": (
                f"MobSF SDK Information: Target SDK - {app_info.get('Target SDK', 'N/A')}, "
                f"Min SDK - {app_info.get('Min SDK', 'N/A')}."
            ),
            "id_suffix": "mobsf_app_sdk_info"
        })
        if app_info.get('Android Version Name') != 'Android Version Name:': # Check for actual content
             chunks.append({
                "text": f"MobSF Android Version Name: {app_info.get('Android Version Name', 'N/A')}.",
                "id_suffix": "mobsf_android_version_name"
            })
        if app_info.get('Android Version Code'):
            chunks.append({
                "text": f"MobSF Android Version Code: {app_info.get('Android Version Code', 'N/A')}.",
                "id_suffix": "mobsf_android_version_code"
            })

    # --- App Components ---
    app_components = parsed_data.get("app_components", {})
    if app_components:
        for comp_type, count in app_components.items():
            chunks.append({
                "text": f"MobSF App Components: {comp_type.replace('_', ' ').title()} - {count}.",
                "id_suffix": f"mobsf_app_component_{comp_type.lower().replace(' ', '_')}"
            })

    # --- Certificate Information ---
    certificate_info = parsed_data.get("certificate_information", {})
    if certificate_info:
        chunks.append({
            "text": f"MobSF Certificate: Binary is signed: {certificate_info.get('Binary is signed', 'N/A')}. "
                    f"Found Unique Certificates: {certificate_info.get('Found Unique Certificates', 'N/A')}.",
            "id_suffix": "mobsf_cert_signing_status"
        })
        chunks.append({
            "text": (
                f"MobSF Certificate Signature Versions: v1={certificate_info.get('v1 signature', 'N/A')}, "
                f"v2={certificate_info.get('v2 signature', 'N/A')}, "
                f"v3={certificate_info.get('v3 signature', 'N/A')}, "
                f"v4={certificate_info.get('v4 signature', 'N/A')}."
            ),
            "id_suffix": "mobsf_cert_signature_versions"
        })
        chunks.append({
            "text": (
                f"MobSF Certificate Subject: '{certificate_info.get('X.509 Subject', 'N/A')}'. "
                f"Issuer: '{certificate_info.get('Issuer', 'N/A')}'."
            ),
            "id_suffix": "mobsf_cert_subject_issuer"
        })
        chunks.append({
            "text": (
                f"MobSF Certificate Algorithm Details: Signature Algorithm - '{certificate_info.get('Signature Algorithm', 'N/A')}', "
                f"Hash Algorithm - '{certificate_info.get('Hash Algorithm', 'N/A')}', "
                f"PublicKey Algorithm - '{certificate_info.get('PublicKey Algorithm', 'N/A')}', "
                f"Bit Size - {certificate_info.get('Bit Size', 'N/A')}."
            ),
            "id_suffix": "mobsf_cert_algo_details"
        })
        chunks.append({
            "text": (
                f"MobSF Certificate Validity: From {certificate_info.get('Valid From', 'N/A')} "
                f"To {certificate_info.get('Valid To', 'N/A')}."
            ),
            "id_suffix": "mobsf_cert_validity"
        })
        chunks.append({
            "text": (
                f"MobSF Certificate Fingerprints: MD5 - {certificate_info.get('md5_fingerprint', 'N/A')}, "
                f"SHA1 - {certificate_info.get('sha1_fingerprint', 'N/A')}, "
                f"SHA256 - {certificate_info.get('sha256_fingerprint', 'N/A')}, "
                f"SHA512 - {certificate_info.get('sha512_fingerprint', 'N/A')}."
            ),
            "id_suffix": "mobsf_cert_fingerprints"
        })
        if certificate_info.get('Fingerprint'): # This seems to be another SHA256 or similar, add if unique
            chunks.append({
                "text": f"MobSF Certificate Generic Fingerprint: {certificate_info.get('Fingerprint', 'N/A')}.",
                "id_suffix": "mobsf_cert_generic_fingerprint"
            })


    # --- Application Permissions ---
    application_permissions = parsed_data.get("application_permissions", [])
    for i, perm_data in enumerate(application_permissions):
        chunks.append({
            "text": (
                f"MobSF Application Permission: '{perm_data.get('permission', 'N/A')}', "
                f"Status: '{perm_data.get('status', 'N/A')}', "
                f"Info: '{perm_data.get('info', 'N/A')}', "
                f"Description: '{perm_data.get('description', 'N/A')}'."
            ),
            "id_suffix": f"mobsf_app_permission_{i}"
        })

    # --- APKiD Analysis ---
    apkid_analysis = parsed_data.get("apkid_analysis", [])
    for i, apkid_data in enumerate(apkid_analysis):
        chunks.append({
            "text": (
                f"MobSF APKiD Analysis: Finding - '{apkid_data.get('finding', 'N/A')}', "
                f"Details - '{apkid_data.get('details', 'N/A')}'."
            ),
            "id_suffix": f"mobsf_apkid_analysis_{i}"
        })

    # --- Network Security Findings ---
    network_security_findings = parsed_data.get("network_security_findings", [])
    for i, net_finding in enumerate(network_security_findings):
        # Assuming network_security_findings have 'title', 'severity', 'description'
        chunks.append({
            "text": (
                f"MobSF Network Security Finding: Title - '{net_finding.get('title', 'N/A')}', "
                f"Severity - '{net_finding.get('severity', 'N/A')}', "
                f"Description - '{net_finding.get('description', 'N/A')}'."
            ),
            "id_suffix": f"mobsf_net_security_finding_{i}"
        })

    # --- Certificate Analysis Findings ---
    certificate_analysis_findings = parsed_data.get("certificate_analysis_findings", [])
    for i, cert_finding in enumerate(certificate_analysis_findings):
        chunks.append({
            "text": (
                f"MobSF Certificate Analysis Finding: Title - '{cert_finding.get('title', 'N/A')}', "
                f"Severity - '{cert_finding.get('severity', 'N/A')}', "
                f"Description - '{cert_finding.get('description', 'N/A')}'."
            ),
            "id_suffix": f"mobsf_cert_analysis_finding_{i}"
        })

    # --- Manifest Analysis Findings ---
    manifest_analysis_findings = parsed_data.get("manifest_analysis_findings", [])
    for i, manifest_finding in enumerate(manifest_analysis_findings):
        chunks.append({
            "text": (
                f"MobSF Manifest Analysis Finding {manifest_finding.get('number', 'N/A')}: "
                f"Issue - '{manifest_finding.get('issue', 'N/A')}', "
                f"Severity - '{manifest_finding.get('severity', 'N/A')}', "
                f"Description - '{manifest_finding.get('description', 'N/A')}'."
            ),
            "id_suffix": f"mobsf_manifest_analysis_finding_{i}"
        })

    # --- Code Analysis Findings ---
    code_analysis_findings = parsed_data.get("code_analysis_findings", [])
    for i, code_finding in enumerate(code_analysis_findings):
        chunks.append({
            "text": (
                f"MobSF Code Analysis Finding {code_finding.get('number', 'N/A')}: "
                f"Issue - '{code_finding.get('issue', 'N/A')}', "
                f"Severity - '{code_finding.get('severity', 'N/A')}', "
                f"Standards - '{code_finding.get('standards', 'N/A')}', "
                f"Files - '{code_finding.get('files', 'N/A')}'."
            ),
            "id_suffix": f"mobsf_code_analysis_finding_{i}"
        })
        
    # --- NIAP Analysis (if data exists) ---
    niap_analysis = parsed_data.get("niap_analysis", [])
    for i, niap_finding in enumerate(niap_analysis):
        # Assuming NIAP findings also have structure like title/description
        chunks.append({
            "text": (
                f"MobSF NIAP Analysis Finding: {json.dumps(niap_finding)}" # Dump as JSON if structure unknown
            ),
            "id_suffix": f"mobsf_niap_finding_{i}"
        })

    # --- Abused Permissions Summary (Malware Permissions) ---
    abused_permissions_summary = parsed_data.get("abused_permissions_summary", {})
    malware_perms_section = abused_permissions_summary.get("Malware Permissions", {})
    if malware_perms_section.get("matches"):
        chunks.append({
            "text": (
                f"MobSF Abused Permissions - Malware: Matches '{malware_perms_section.get('matches', 'N/A')}'. "
                f"Permissions: {', '.join(malware_perms_section.get('permissions', []))}."
            ),
            "id_suffix": "mobsf_abused_perms_malware_list"
        })
        chunks.append({
            "text": (
                f"MobSF Abused Permissions - Malware Description: "
                f"{malware_perms_section.get('description', 'N/A')}."
            ),
            "id_suffix": "mobsf_abused_perms_malware_desc"
        })
    
    # --- Abused Permissions Summary (Other Common Permissions) ---
    other_common_perms_section = abused_permissions_summary.get("Other Common Permissions", {})
    if other_common_perms_section.get("matches") and other_common_perms_section.get("permissions"):
        chunks.append({
            "text": (
                f"MobSF Abused Permissions - Other Common: Matches '{other_common_perms_section.get('matches', 'N/A')}'. "
                f"Permissions: {', '.join(other_common_perms_section.get('permissions', []))}."
            ),
            "id_suffix": "mobsf_abused_perms_other_list"
        })
        chunks.append({
            "text": (
                f"MobSF Abused Permissions - Other Common Description: "
                f"{other_common_perms_section.get('description', 'N/A')}."
            ),
            "id_suffix": "mobsf_abused_perms_other_desc"
        })

    # --- Scan Logs ---
    scan_logs = parsed_data.get("scan_logs", [])
    for i, log_entry in enumerate(scan_logs):
        log_text = (
            f"MobSF Scan Log Entry {i+1}: "
            f"Timestamp - {log_entry.get('timestamp', 'N/A')}, "
            f"Event - '{log_entry.get('event', 'N/A')}', "
            f"Error/Status - '{log_entry.get('error', 'N/A')}'."
        )
        # Filter out less informative or repetitive log entries if needed,
        # but for max chunks, include all.
        chunks.append({
            "text": log_text,
            "id_suffix": f"mobsf_scan_log_{i}"
        })

    # --- File Metadata ---
    file_metadata = parsed_data.get("file_metadata", {})
    if file_metadata:
        chunks.append({
            "text": (
                f"MobSF File Metadata: Filename - '{file_metadata.get('filename', 'N/A')}', "
                f"Size - {file_metadata.get('file_size', 'N/A')} bytes, "
                f"Last Modified - {file_metadata.get('last_modified', 'N/A')}."
            ),
            "id_suffix": "mobsf_file_metadata"
        })

    return chunks

def _chunk_mobsf_ios_report(parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extracts relevant information from a parsed MobSF iOS report and
    structures it into smaller, meaningful text chunks for RAG.
    """
    chunks = []
    
    # --- Scan Metadata ---
    scan_metadata = parsed_data.get("scan_metadata", {})
    chunks.append({
        "text": (
            f"MobSF Scan Report ID: {scan_metadata.get('report_id', 'N/A')}. "
            f"Tool Version: {scan_metadata.get('mobsf_version', 'N/A')}. "
            f"Scan Date: {scan_metadata.get('scan_date', 'N/A')}."
        ),
        "id_suffix": "mobsf_scan_metadata"
    })
    chunks.append({
        "text": (
            f"MobSF App Security Score: {scan_metadata.get('app_security_score', 'N/A')}. "
            f"Grade: {scan_metadata.get('grade', 'N/A')}."
        ),
        "id_suffix": "mobsf_security_score"
    })
    chunks.append({
        "text": (
            f"MobSF Scanned File Name: {scan_metadata.get('file_name', 'N/A')}. "
            f"App Identifier: {scan_metadata.get('identifier', 'N/A')}." # Changed from package_name
        ),
        "id_suffix": "mobsf_file_identifier_name" # Changed suffix
    })

    # --- Summary of Findings ---
    summary = parsed_data.get("summary", {})
    chunks.append({
        "text": f"MobSF Overall Total Issues: {summary.get('total_issues', 0)}.",
        "id_suffix": "mobsf_total_issues"
    })
    findings_severity = summary.get("findings_severity", {})
    if findings_severity:
        for severity, count in findings_severity.items():
            chunks.append({
                "text": f"MobSF Issues by Severity: {severity} - {count}.",
                "id_suffix": f"mobsf_issues_severity_{severity.lower()}"
            })

    # --- File Information ---
    file_info = parsed_data.get("file_information", {})
    if file_info:
        chunks.append({
            "text": (
                f"MobSF File Information: Name - {file_info.get('File Name', 'N/A')}, "
                f"Size - {file_info.get('Size', 'N/A')}."
            ),
            "id_suffix": "mobsf_file_general_info"
        })
        chunks.append({
            "text": (
                f"MobSF File Hashes: MD5 - {file_info.get('MD5', 'N/A')}, "
                f"SHA1 - {file_info.get('SHA1', 'N/A')}, "
                f"SHA256 - {file_info.get('SHA256', 'N/A')}."
            ),
            "id_suffix": "mobsf_file_hashes"
        })

    # --- App Information (iOS Specific) ---
    app_info = parsed_data.get("app_information", {})
    if app_info:
        chunks.append({
            "text": (
                f"MobSF iOS App Details: App Name - {app_info.get('App Name', 'N/A')}, "
                f"Identifier - {app_info.get('Identifier', 'N/A')}, "
                f"App Type - {app_info.get('App Type', 'N/A')}."
            ),
            "id_suffix": "mobsf_ios_app_basic_info"
        })
        chunks.append({
            "text": (
                f"MobSF iOS Version Info: Version - {app_info.get('Version', 'N/A')}, "
                f"Build - {app_info.get('Build', 'N/A')}, "
                f"SDK Name - {app_info.get('SDK Name', 'N/A')}."
            ),
            "id_suffix": "mobsf_ios_app_version_sdk"
        })
        chunks.append({
            "text": (
                f"MobSF iOS Platform Compatibility: Platform Version - {app_info.get('Platform Version', 'N/A')}, "
                f"Min OS Version - {app_info.get('Min OS Version', 'N/A')}, "
                f"Supported Platforms - {', '.join(app_info.get('Supported Platforms', ['N/A']))}."
            ),
            "id_suffix": "mobsf_ios_app_platform_compat"
        })

    # --- Binary Information (iOS Specific) ---
    binary_info = parsed_data.get("binary_information", {})
    if binary_info:
        chunks.append({
            "text": (
                f"MobSF Binary Information: Architecture - {binary_info.get('Arch', 'N/A')}, "
                f"Sub Architecture - {binary_info.get('Sub Arch', 'N/A')}, "
                f"Bit - {binary_info.get('Bit', 'N/A')}, "
                f"Endian - {binary_info.get('Endian', 'N/A')}."
            ),
            "id_suffix": "mobsf_binary_info"
        })

    # --- App Transport Security Findings (iOS Specific) ---
    ats_findings = parsed_data.get("app_transport_security_findings", [])
    for i, finding in enumerate(ats_findings):
        chunks.append({
            "text": (
                f"MobSF App Transport Security Finding {i+1}: "
                f"Issue - '{finding.get('issue', 'N/A')}', "
                f"Severity - '{finding.get('severity', 'N/A')}', "
                f"Description - '{finding.get('description', 'N/A')}'."
            ),
            "id_suffix": f"mobsf_ats_finding_{i}"
        })

    # --- IPA Binary Code Analysis Findings (iOS Specific) ---
    ipa_binary_code_analysis_findings = parsed_data.get("ipa_binary_code_analysis_findings", [])
    for i, finding in enumerate(ipa_binary_code_analysis_findings):
        standards_text = ""
        if 'standards' in finding and isinstance(finding['standards'], dict):
            standards = finding['standards']
            standards_list = [f"{k}: {v}" for k, v in standards.items() if v]
            if standards_list:
                standards_text = f" Standards: {'; '.join(standards_list)}."

        chunks.append({
            "text": (
                f"MobSF IPA Binary Code Analysis Finding {finding.get('number', i+1)}: "
                f"Issue - '{finding.get('issue', 'N/A')}', "
                f"Severity - '{finding.get('severity', 'N/A')}', "
                f"Description - '{finding.get('description', 'N/A')}'.{standards_text}"
            ),
            "id_suffix": f"mobsf_ipa_code_analysis_finding_{i}"
        })

    # --- IPA Binary Analysis Findings (iOS Specific - Protections) ---
    ipa_binary_analysis_findings = parsed_data.get("ipa_binary_analysis_findings", [])
    for i, finding in enumerate(ipa_binary_analysis_findings):
        chunks.append({
            "text": (
                f"MobSF IPA Binary Protection Finding {i+1}: "
                f"Protection - '{finding.get('protection', 'N/A')}', "
                f"Status - '{finding.get('status', 'N/A')}', "
                f"Severity - '{finding.get('severity', 'N/A')}', "
                f"Description - '{finding.get('description', 'N/A')}'."
            ),
            "id_suffix": f"mobsf_ipa_binary_protection_finding_{i}"
        })

    # --- OFAC Sanctioned Countries ---
    ofac_sanctioned_countries = parsed_data.get("ofacsanctioned_countries", [])
    for i, country_data in enumerate(ofac_sanctioned_countries):
        chunks.append({
            "text": (
                f"MobSF OFAC Sanctioned Country Check {i+1}: "
                f"Domain - '{country_data.get('domain', 'N/A')}', "
                f"Country/Region - '{country_data.get('country_region', 'N/A')}'."
            ),
            "id_suffix": f"mobsf_ofac_country_{i}"
        })
        
    # --- Domain Malware Check ---
    domain_malware_check = parsed_data.get("domain_malware_check", [])
    for i, domain_data in enumerate(domain_malware_check):
        geolocation_info = ""
        if 'geolocation' in domain_data and isinstance(domain_data['geolocation'], dict):
            geo = domain_data['geolocation']
            geo_parts = []
            if geo.get('IP'): geo_parts.append(f"IP: {geo['IP']}")
            if geo.get('Country'): geo_parts.append(f"Country: {geo['Country']}")
            if geo.get('Region'): geo_parts.append(f"Region: {geo['Region']}")
            if geo.get('City'): geo_parts.append(f"City: {geo['City']}")
            if geo.get('Latitude'): geo_parts.append(f"Latitude: {geo['Latitude']}")
            if geo.get('Longitude'): geo_joining_word = " and " if geo_parts else ""
            if geo.get('Longitude'): geo_parts.append(f"Longitude: {geo['Longitude']}")
            if geo_parts:
                geolocation_info = f" Geolocation: {'; '.join(geo_parts)}."

        chunks.append({
            "text": (
                f"MobSF Domain Malware Check {i+1}: "
                f"Domain - '{domain_data.get('domain', 'N/A')}', "
                f"Status - '{domain_data.get('status', 'N/A')}'.{geolocation_info}"
            ),
            "id_suffix": f"mobsf_domain_malware_check_{i}"
        })

    # --- Scan Logs ---
    scan_logs = parsed_data.get("scan_logs", [])
    # Limit scan logs to a reasonable number if they can be very verbose
    for i, log_entry in enumerate(scan_logs[-10:]): # Take last 10 entries for brevity
        chunks.append({
            "text": (
                f"MobSF Scan Log Entry {i+1}: "
                f"Timestamp - '{log_entry.get('timestamp', 'N/A')}', "
                f"Event - '{log_entry.get('event', 'N/A')}', "
                f"Error/Status - '{log_entry.get('error', 'N/A')}'."
            ),
            "id_suffix": f"mobsf_scan_log_{i}"
        })

    # --- File Metadata ---
    file_metadata = parsed_data.get("file_metadata", {})
    if file_metadata:
        chunks.append({
            "text": (
                f"MobSF File Metadata: Filename - '{file_metadata.get('filename', 'N/A')}', "
                f"Size - {file_metadata.get('file_size', 'N/A')} bytes, "
                f"Last Modified - {file_metadata.get('last_modified', 'N/A')}."
            ),
            "id_suffix": "mobsf_file_metadata"
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
    elif report_type.lower() == "mobsf_android": # New condition for Mobsf Android
        raw_chunks_with_metadata = _chunk_mobsf_android_report(parsed_report_data)
    elif report_type.lower() == "mobsf_ios": # New condition for Mobsf iOS
        raw_chunks_with_metadata = _chunk_mobsf_ios_report(parsed_report_data)
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
    report_namespace_mobsf_android = None # New variable for Mobsf Android namespace

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

        # Load and upsert Mobsf Android chunks (new test block)
        print("\nLoading and upserting Mobsf Android chunks to temporary namespace...")
        report_namespace_mobsf_android = load_report_chunks_and_embeddings(dummy_mobsf_android_data, "mobsf_android")
        print(f"Mobsf Android chunks upserted to namespace: {report_namespace_mobsf_android}")

        # Test internal RAG with Mobsf Android data
        if report_namespace_mobsf_android:
            test_query_internal_mobsf_android = "What are the abused permissions and their descriptions?"
            print(f"\nSearching for INTERNAL RAG context for query: '{test_query_internal_mobsf_android}' (Mobsf Android)")
            retrieved_context_internal_mobsf_android = retrieve_internal_rag_context(test_query_internal_mobsf_android, report_namespace_mobsf_android, top_k=2)
            if retrieved_context_internal_mobsf_android:
                print("\nRetrieved INTERNAL RAG Context (Mobsf Android):")
                print(retrieved_context_internal_mobsf_android)
            else:
                print("No INTERNAL RAG context retrieved for Mobsf Android query.")

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
        if report_namespace_mobsf_android: # New cleanup
            delete_report_namespace(report_namespace_mobsf_android)