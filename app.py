import sys
import os

# Add the current directory and its subdirectories to Python path
# This helps with importing modules correctly
project_root_dir = os.path.abspath(os.path.dirname(__file__))
if project_root_dir not in sys.path:
    sys.path.insert(0, project_root_dir)

# Ensure 'chatbot_modules' is accessible, assuming it's a sibling directory or in PATH
# If chatbot_modules is a package, its __init__.py will handle imports.
# If it's just a directory with scripts, ensure it's on the Python path.
# For simplicity here, we assume it's set up to be importable directly
# or resides in a location already covered by sys.path or PYTHONPATH.
try:
    # Attempt a dummy import to check if the path setup is correct for chatbot_modules
    import chatbot_modules.pdf_extractor
    import chatbot_modules.nmap_parser
    import chatbot_modules.zap_parser
    import chatbot_modules.local_llm
except ImportError as e:
    print(f"Critical Error: Could not import core chatbot_modules. Please ensure they are correctly installed and accessible.")
    print(f"Python path: {sys.path}")
    print(f"Error: {e}")
    sys.exit(1)


from cli.cli_interface import CLIInterface
from services.llm_service import LLMService # Import to ensure it's initialized
from services.kb_service import KnowledgeBaseService # Import to ensure it's initialized

def main():
    try:
        print("Initializing application components...")
        # Initialize services to ensure models and connections are loaded once at startup
        llm_service = LLMService()
        kb_service = KnowledgeBaseService()

        if not llm_service.is_loaded():
            print("Cannot start application without the local LLM. Please check configuration and model files.")
            return 1

        if not kb_service.is_loaded():
            print("Warning: Semantic search (Pinecone) components could not be fully loaded. "
                  "General cybersecurity questions might not be as effective, but report analysis will still work.")

        cli = CLIInterface()
        cli.run()
        return 0
    except KeyboardInterrupt:
        print("\nReceived keyboard interrupt. Exiting...")
        return 0
    except Exception as e:
        print(f"An unhandled error occurred: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        # Cleanup can be handled within CLIInterface's run method or explicitly here if needed
        # For singleton services, their cleanup methods can be called if needed.
        # llm_service.cleanup() # This would be called by CLIInterface.run() already on exit.
        pass

if __name__ == "__main__":
    sys.exit(main())