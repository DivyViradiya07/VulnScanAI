import os
from huggingface_hub import hf_hub_download
from llama_cpp import Llama

def load_model(model_id: str, model_basename: str, local_dir: str = "models") -> Llama:
    """
    Loads a local GGUF language model, downloading it if not present.
    Args:
        model_id (str): The Hugging Face model ID (e.g., "TheBloke/OpenHermes-2.5-Mistral-7B-GGUF").
        model_basename (str): The specific GGUF filename (e.g., "openhermes-2.5-mistral-7b-dpo.Q4_K_M.gguf").
        local_dir (str): Directory to store the downloaded model.
    Returns:
        Llama: An instance of the loaded language model.
    """
    # Ensure the local_dir exists 
    if not os.path.exists(local_dir):
        os.makedirs(local_dir)

    model_path = os.path.join(local_dir, model_basename)

    # Check if the GGUF model file exists in local_dir 
    if not os.path.exists(model_path):
        print(f"Model not found at {model_path}. Downloading from Hugging Face...")
        # Use hf_hub_download to download it 
        hf_hub_download(
            repo_id=model_id,
            filename=model_basename,
            local_dir=local_dir,
            force_download=False # Set to True to re-download even if exists
        )
        print("Download complete.")
    else:
        print(f"Model found locally at {model_path}.")

    # Initialize and return a llama_cpp.Llama instance 
    # Adjust n_ctx and n_gpu_layers as needed for your system
    model = Llama(
        model_path=model_path,
        n_ctx=4096,      # Context window size 
        n_gpu_layers=-1, # Offload all layers to GPU if available. Set to 0 for CPU only. 
        verbose=False    # Set to True for more loading details
    )
    print("Language model loaded successfully.")
    return model

def generate_response(model_instance: Llama, prompt: str, max_tokens: int = 500) -> str:
    """
    Generates a response from the language model instance.
    Formats the prompt correctly for your chosen model (e.g., Mistral's <s>[INST]...[/INST]) 
    and calls model_instance.create_chat_completion or model_instance() for inference.
    Args:
        model_instance (Llama): The loaded model instance.
        prompt (str): The input prompt for the model.
        max_tokens (int): The maximum number of tokens to generate in the response.
    Returns:
        str: The generated response from the model.
    """
    response = model_instance.create_chat_completion(
        messages=[
            {"role": "user", "content": prompt}
        ],
        max_tokens=max_tokens,
        temperature=0.7, # A common default, can be tuned
        stop=["</s>"] # Common stop token, can be expanded
    )
    # Extract the response content from the completion object
    return response["choices"][0]["message"]["content"]

if __name__ == "__main__":
    # --- Example Usage (for testing) ---
    # Define the model to download and load.
    # This uses the same model_id and filename as in the S3_Model_Download.ipynb
    MODEL_ID = "TheBloke/OpenHermes-2.5-Mistral-7B-GGUF"
    MODEL_BASENAME = "openhermes-2.5-mistral-7b.Q4_K_M.gguf"
    MODEL_DIR = r"D:\VulnScanAI\pretrained_language_model"

    print("--- Testing Model Loading ---")
    try:
        # Load the model
        model = load_model(MODEL_ID, MODEL_BASENAME, MODEL_DIR)

        # Test generating a response
        test_prompt = "What is the capital of France?"
        print(f"\n--- Testing Model Response for prompt: '{test_prompt}' ---")
        generated_text = generate_response(model, test_prompt, max_tokens=50)
        print(f"Generated Response: {generated_text}")

        test_prompt_2 = "Explain what an Nmap SYN scan is in one sentence."
        print(f"\n--- Testing Model Response for prompt: '{test_prompt_2}' ---")
        generated_text_2 = generate_response(model, test_prompt_2, max_tokens=50)
        print(f"Generated Response: {generated_text_2}")

    except Exception as e:
        print(f"An error occurred during model testing: {e}")