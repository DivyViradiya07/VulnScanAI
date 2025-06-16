import os
from typing import Dict, Any, Optional
from chatbot_modules.local_llm import load_model, generate_response
import config

class LLMService:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(LLMService, cls).__new__(cls)
            cls._instance.llm_instance = None
            cls._instance._load_llm()
        return cls._instance

    def _load_llm(self):
        if self.llm_instance is None:
            print(f"Attempting to load Local LLM from {config.LLM_LOCAL_DIR}...")
            try:
                self.llm_instance = load_model(config.LLM_MODEL_ID, config.LLM_MODEL_BASENAME, config.LLM_LOCAL_DIR)
                print("Local LLM successfully initialized.")
            except Exception as e:
                print(f"Failed to load Local LLM: {e}")
                self.llm_instance = None

    def get_llm_instance(self):
        return self.llm_instance

    def is_loaded(self) -> bool:
        return self.llm_instance is not None

    def generate_response(self, prompt: str, max_tokens: int = 500) -> str:
        if not self.is_loaded():
            return "Error: Language model not loaded."
        try:
            return generate_response(self.llm_instance, prompt, max_tokens)
        except Exception as e:
            print(f"Error generating LLM response: {e}")
            return f"Sorry, I encountered an error while generating a response: {str(e)}"

    def cleanup(self):
        if self.llm_instance:
            try:
                if hasattr(self.llm_instance, 'close') and callable(getattr(self.llm_instance, 'close')):
                    self.llm_instance.close()
                self.llm_instance = None
                print("LLM instance cleaned up.")
            except Exception as e:
                print(f"Error during LLM cleanup: {e}")