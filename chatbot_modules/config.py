import os

# Define the base directory for the project.
# This assumes config.py is in chatbot_modules, and project root is one level up.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# --- LLM Model Configuration ---
LLM_MODEL_ID = "TheBloke/OpenHermes-2.5-Mistral-7B-GGUF"
LLM_MODEL_BASENAME = "openhermes-2.5-mistral-7b.Q4_K_M.gguf"
# Path to store the downloaded GGUF model, relative to PROJECT_ROOT
LLM_MODEL_DIR = os.path.join(PROJECT_ROOT, "pretrained_language_model")

# --- RAG (Retrieval Augmented Generation) Configuration ---
# Path to your fine-tuned SentenceTransformer model, relative to PROJECT_ROOT
# This should match the save path from S1-2_Model_Retraining.ipynb
RAG_EMBEDDING_MODEL_PATH = os.path.join(PROJECT_ROOT, "fine_tuned_owasp_model_advanced")

# Pinecone Configuration
PINECONE_INDEX_NAME = "owasp-qa"
# You MUST set PINECONE_API_KEY and PINECONE_ENVIRONMENT as system environment variables.
# Example: PINECONE_API_KEY = os.environ.get("PINECONE_API_KEY")
# Example: PINECONE_ENVIRONMENT = os.environ.get("PINECONE_ENVIRONMENT") # e.g., "gcp-starter" or your specific environment
# These are retrieved in chatbot_utils.py
PINECONE_EMBEDDING_DIMENSION = 768 # Dimension of your SentenceTransformer embeddings (e.g., for all-mpnet-base-v2)
PINECONE_METRIC = "cosine" # Metric used in Pinecone index (e.g., "cosine")
PINECONE_CLOUD = "aws" # Your Pinecone cloud provider (e.g., "aws", "gcp", "azure")
PINECONE_REGION = "us-east-1" # Your Pinecone region

# --- Chatbot Settings ---
DEFAULT_MAX_TOKENS = 500 # Max tokens for LLM responses
DEFAULT_RAG_TOP_K = 3 # Number of top results to retrieve from Pinecone

# --- Heuristic Keywords for Report-Specific Questions ---
# These keywords help determine if a question is about the uploaded report.
# Refined from previous version to avoid overly generic terms.
REPORT_SPECIFIC_KEYWORDS = [
    "report", "scan", "host", "ip", "port", "vulnerability", "alert", "cve",
    "solution", "remediation", "finding", "risk", "instance", "site", "version",
    "mac address", "os detection", "service", "script", "traceroute", "references", "reference",
    "url", "urls",
    # Specific actions/requests that apply to a *given* report
    "this report", "the report", "current report", "this scan", "the scan"
]

