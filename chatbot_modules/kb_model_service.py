import os
from typing import Dict, Any, Optional, List
from sentence_transformers import SentenceTransformer
from pinecone import Pinecone, ServerlessSpec
import config

class KnowledgeBaseService:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(KnowledgeBaseService, cls).__new__(cls)
            cls._instance.semantic_model = None
            cls._instance.pinecone_index = None
            cls._instance._load_semantic_model()
            cls._instance._initialize_pinecone_client()
        return cls._instance

    def _load_semantic_model(self):
        if self.semantic_model is None:
            print(f"Attempting to load Semantic Model from {config.SEMANTIC_MODEL_PATH}...")
            try:
                self.semantic_model = SentenceTransformer(config.SEMANTIC_MODEL_PATH)
                print("Semantic Model loaded successfully.")
            except Exception as e:
                print(f"Failed to load Semantic Model: {e}")
                self.semantic_model = None

    def _initialize_pinecone_client(self):
        if self.pinecone_index is None:
            if not config.PINECONE_API_KEY:
                print("Error: PINECONE_API_KEY not found. Cannot initialize Pinecone.")
                return

            print(f"Attempting to initialize Pinecone client and connect to index '{config.PINECONE_INDEX_NAME}'...")
            try:
                pc = Pinecone(api_key=config.PINECONE_API_KEY)

                if config.PINECONE_INDEX_NAME not in [index.name for index in pc.list_indexes()]:
                    print(f"Creating new Pinecone index: {config.PINECONE_INDEX_NAME} in region {config.PINECONE_ENVIRONMENT}")
                    pc.create_index(
                        name=config.PINECONE_INDEX_NAME,
                        dimension=config.EMBEDDING_DIM,
                        metric="cosine",
                        spec=ServerlessSpec(cloud='aws', region=config.PINECONE_ENVIRONMENT)
                    )
                    print(f"Index '{config.PINECONE_INDEX_NAME}' created.")

                self.pinecone_index = pc.Index(config.PINECONE_INDEX_NAME)
                print(f"Connected to Pinecone index: {config.PINECONE_INDEX_NAME}")
            except Exception as e:
                print(f"Failed to initialize Pinecone: {e}")
                self.pinecone_index = None

    def is_loaded(self) -> bool:
        return self.semantic_model is not None and self.pinecone_index is not None

    def retrieve_from_pinecone(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        if not self.is_loaded():
            print("Semantic model or Pinecone not loaded. Cannot perform retrieval.")
            return []

        try:
            query_embedding = self.semantic_model.encode(query, convert_to_tensor=True).cpu().numpy().tolist()

            query_params = {
                'vector': query_embedding,
                'top_k': top_k,
                'include_metadata': True,
                'namespace': config.UNIFIED_PINECONE_NAMESPACE
            }

            search_results = self.pinecone_index.query(**query_params)
            retrieved_data = []

            for match in search_results.matches:
                question_text = match.metadata.get('question', 'N/A')
                answer_text = match.metadata.get('answer', 'N/A')

                if question_text == 'N/A' or answer_text == 'N/A' or not question_text.strip() or not answer_text.strip():
                    continue

                retrieved_data.append({
                    'score': match.score,
                    'question': question_text,
                    'answer': answer_text,
                    'source_file': match.metadata.get('source_file', 'Pinecone-KB'),
                    'top_level_category': match.metadata.get('top_level_category', 'N/A'),
                    'type': match.metadata.get('type', 'N/A'),
                    'intent': match.metadata.get('intent', 'N/A'),
                    'related_topics': match.metadata.get('related_topics', 'N/A')
                })
            return retrieved_data
        except Exception as e:
            print(f"Error during Pinecone retrieval: {e}")
            return []