import os
from dotenv import load_dotenv

load_dotenv() # Load environment variables from .env file

# Base directory for the project
PROJECT_ROOT_DIR = os.path.abspath(os.path.dirname(__file__))

# --- Configuration for Local LLM ---
LLM_MODEL_ID = "TheBloke/OpenHermes-2.5-Mistral-7B-GGUF"
LLM_MODEL_BASENAME = "openhermes-2.5-mistral-7b.Q4_K_M.gguf"
LLM_LOCAL_DIR = os.path.join(PROJECT_ROOT_DIR, "pretrained_language_model")

# --- Configuration for Semantic Search Model and Pinecone ---
SEMANTIC_MODEL_PATH = os.path.join(PROJECT_ROOT_DIR, "fine_tuned_owasp_model_advanced")
PINECONE_INDEX_NAME = "owasp-qa"
UNIFIED_PINECONE_NAMESPACE = "owasp-cybersecurity-kb"
EMBEDDING_DIM = 768 # Standard for 'all-mpnet-base-v2'

PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")
PINECONE_ENVIRONMENT = os.getenv("PINECONE_ENVIRONMENT", "us-east-1")

# Chat History
MAX_CHAT_HISTORY_TURNS = 5

# Documents directory
DOCUMENTS_DIR = os.path.join(PROJECT_ROOT_DIR, "documents")