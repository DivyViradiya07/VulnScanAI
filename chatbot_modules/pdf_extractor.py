import PyPDF2
import os

def extract_text_from_pdf(pdf_path: str) -> str:
    """
    Extracts all readable text from a PDF document.

    Args:
        pdf_path (str): The path to the PDF file.

    Returns:
        str: The extracted text from the PDF.

    Raises:
        FileNotFoundError: If the PDF file does not exist.
        PyPDF2.errors.PdfReadError: If the PDF file is corrupted or unreadable.
        Exception: For other unexpected errors during extraction.
    """
    if not os.path.exists(pdf_path):
        raise FileNotFoundError(f"The PDF file was not found: {pdf_path}")

    extracted_text = ""
    try:
        with open(pdf_path, 'rb') as file:
            reader = PyPDF2.PdfReader(file)
            # Iterate through its pages 
            for page_num in range(len(reader.pages)):
                page = reader.pages[page_num]
                text = page.extract_text()
                if text:
                    extracted_text += text + "\n" # Add a newline for readability between pages
    except PyPDF2.errors.PdfReadError as e:
        # Include robust error handling for unreadable PDFs or extraction issues 
        raise PyPDF2.errors.PdfReadError(f"Error reading PDF file {pdf_path}: {e}. It might be corrupted or encrypted.")
    except Exception as e:
        # Include robust error handling for unreadable PDFs or extraction issues 
        raise Exception(f"An unexpected error occurred during PDF extraction from {pdf_path}: {e}")

    return extracted_text

if __name__ == "__main__":
    # --- Example Usage (for testing) ---
    # Create a dummy PDF for testing (if you don't have one)
    # You would typically have a PDF file to test with.
    # For demonstration, let's assume 'dummy_report.pdf' exists in a 'reports' folder
    # Or you can quickly create a simple text file and convert it to PDF manually for testing.

    # Example of how you would test it:
    # 1. Create a 'reports' directory in your nmap_llm_analyzer folder
    # 2. Place a sample PDF (e.g., a simple text document saved as PDF) inside it.
    # 3. Update the pdf_test_path below.

    dummy_pdf_path = r"D:\VulnScanAI_Chatbot\documents\Zap\1_zap_20250419_125059.pdf" # Make sure this path is correct for your test file

    # To create a dummy PDF for quick testing, you can use online converters
    # or simple text editors to save as PDF.
    # If you don't have a PDF, this part will raise FileNotFoundError as expected.

    print(f"Attempting to extract text from: {dummy_pdf_path}")
    try:
        # Create a dummy reports directory for example if it doesn't exist
        if not os.path.exists("reports"):
            os.makedirs("reports")
            print("Created 'reports' directory. Please place a dummy PDF inside it for testing.")

        extracted_content = extract_text_from_pdf(dummy_pdf_path)
        print("\n--- Extracted Text ---")
        print(extracted_content) # Print first 500 chars to avoid flooding console
        print("\n--- End of Extracted Text (showing first 500 characters) ---")
    except FileNotFoundError as e:
        print(f"Error: {e}. Please ensure '{dummy_pdf_path}' exists for testing.")
    except PyPDF2.errors.PdfReadError as e:
        print(f"PDF Read Error: {e}")
    except Exception as e:
        print(f"General Error: {e}")