import os
import json
from sentence_transformers import SentenceTransformer
from pinecone import Pinecone, ServerlessSpec, PodSpec
from typing import Dict, Any, List, Optional
import dotenv

dotenv.load_dotenv()

# --- Configuration for RAG Components ---
# This path should point to the directory where your fine-tuned SentenceTransformer model is saved.
# This is typically the output path from S1-2_Model_Retraining.ipynb
# Example: r'D:\OWASP_BERT\fine_tuned_owasp_model_advanced'
MODEL_PATH = r"D:\VulnScanAI_Chatbot\fine_tuned_owasp_model_advanced"

# Pinecone configuration
PINECONE_INDEX_NAME = "owasp-qa"
# Ensure your Pinecone environment and API key are set as environment variables
# For local development, you might set them in your shell or use a .env file (not included here for simplicity)
PINECONE_API_KEY = os.environ.get("PINECONE_API_KEY")
PINECONE_ENVIRONMENT = os.environ.get("PINECONE_ENVIRONMENT") # e.g., "gcp-starter" or your specific environment


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
        print(f"Loading SentenceTransformer model from: {MODEL_PATH}")
        try:
            _embedding_model = SentenceTransformer(MODEL_PATH)
            print("SentenceTransformer model loaded successfully.")
        except Exception as e:
            print(f"Error loading SentenceTransformer model from {MODEL_PATH}: {e}")
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
            
            # Check if index exists, if not, create it (assuming a serverless setup here)
            existing_indexes = [index.name for index in pc.list_indexes()]
            if PINECONE_INDEX_NAME not in existing_indexes:
                print(f"Pinecone index '{PINECONE_INDEX_NAME}' not found. Creating it...")
                # You need to know the dimension of your embeddings (e.g., 768 for all-mpnet-base-v2)
                # and the metric (cosine). This should match your S2_Embedding_Generation.ipynb.
                # For serverless:
                pc.create_index(
                    name=PINECONE_INDEX_NAME,
                    dimension=load_embedding_model().get_sentence_embedding_dimension(), # Dynamically get dimension
                    metric="cosine",
                    spec=ServerlessSpec(cloud="aws", region="us-east-1") # Adjust cloud/region as per your Pinecone setup
                )
                # For pod-based:
                # pc.create_index(
                #     name=PINECONE_INDEX_NAME,
                #     dimension=load_embedding_model().get_sentence_embedding_dimension(),
                #     metric="cosine",
                #     spec=PodSpec(environment=PINECONE_ENVIRONMENT)
                # )
                print(f"Pinecone index '{PINECONE_INDEX_NAME}' created.")
            
            _pinecone_index = pc.Index(PINECONE_INDEX_NAME)
            print("Pinecone index initialized successfully.")
        except Exception as e:
            print(f"Error initializing Pinecone index: {e}")
            raise
    return _pinecone_index

def retrieve_rag_context(query: str, top_k: int = 3, namespace: str = "owasp-cybersecurity-kb") -> str:
    """
    Generates an embedding for the query, queries Pinecone, and returns formatted context.

    Args:
        query (str): The user's question.
        top_k (int): The number of top relevant results to retrieve.
        namespace (str): The Pinecone namespace to query.

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
            # You can adjust how you format the retrieved context.
            # Here, we're taking the 'answer' from the metadata.
            # Make sure 'answer' (and 'question') are stored in metadata in S2_Embedding_Generation.ipynb
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

# Example usage (for testing chatbot_utils.py directly)
if __name__ == "__main__":
    print("--- Testing chatbot_utils.py directly ---")
    print("Ensure PINECONE_API_KEY and PINECONE_ENVIRONMENT are set as environment variables.")
    print(f"Attempting to load model from: {MODEL_PATH}")

    # You might want to set dummy env vars for testing if not already set system-wide
    # os.environ["PINECONE_API_KEY"] = "YOUR_API_KEY"
    # os.environ["PINECONE_ENVIRONMENT"] = "YOUR_ENVIRONMENT"

    try:
        # Test loading components
        model = load_embedding_model()
        index = initialize_pinecone_index()
        
        # Test retrieval
        test_query = "What is SQL injection?"
        print(f"\nSearching for RAG context for query: '{test_query}'")
        retrieved_context = retrieve_rag_context(test_query)
        
        if retrieved_context:
            print("\nRetrieved RAG Context:")
            print(retrieved_context)
        else:
            print("No RAG context retrieved.")

        test_query_2 = "How to prevent XSS?"
        print(f"\nSearching for RAG context for query: '{test_query_2}'")
        retrieved_context_2 = retrieve_rag_context(test_query_2)
        if retrieved_context_2:
            print("\nRetrieved RAG Context:")
            print(retrieved_context_2)
        else:
            print("No RAG context retrieved for second query.")

    except Exception as e:
        print(f"An error occurred during direct chatbot_utils test: {e}")
        print("Please ensure you have a valid SentenceTransformer model at the specified MODEL_PATH,")
        print("and that your Pinecone API Key/Environment variables are correctly configured,")
        print("and the Pinecone index exists with data populated.")
