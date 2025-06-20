# VulnScanAI - Security Report Analysis Chatbot

VulnScanAI is an intelligent chatbot designed to analyze security reports (Nmap, ZAP, SSLScan, MobSF) and provide interactive insights using a local LLM (OpenHermes 2.5 Mistral 7B) with RAG (Retrieval-Augmented Generation) capabilities.

## Features

- **Multiple Report Formats**: Supports PDF, TXT
- **Security Tools Integration**: Works with Nmap, ZAP, SSLScan, and MobSF reports
- **Local LLM**: Uses OpenHermes 2.5 Mistral 7B for privacy-focused analysis
- **RAG Implementation**: Enhanced responses using Retrieval-Augmented Generation
- **Interactive Chat**: Natural language interface for querying report details
- **Comprehensive Analysis**: Identifies vulnerabilities, suggests remediations, and provides contextual insights

## Prerequisites

- Python 3.8+
- Git
- [Pinecone](https://www.pinecone.io/) account (for vector storage)
- Sufficient disk space for the language model (~4-8GB)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/VulnScanAI_Chatbot.git
   cd VulnScanAI_Chatbot
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   .\venv\Scripts\activate  # Windows
   # OR
   source venv/bin/activate  # Linux/Mac
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   Note: If requirements.txt doesn't exist, install the following packages:
   ```bash
   pip install langchain sentence-transformers pinecone-client python-dotenv pypdf2 python-multipart fastapi uvicorn
   ```

4. Set up environment variables:
   Create a `.env` file in the project root with the following content:
   ```
   PINECONE_API_KEY=your_pinecone_api_key
   PINECONE_ENVIRONMENT=your_pinecone_environment
   ```

## Usage

1. **Run the application**:
   ```bash
   python app.py  #For now CLI interface.
   ```

2. **Upload a security report** when prompted. Supported formats:
   - Nmap reports (.xml, .nmap, .txt)
   - ZAP reports (.json, .xml, .html)
   - SSLScan reports (.xml, .json, .txt)
   - MobSF reports (Android/iOS) (.json, .txt)

3. **Interact with the chatbot** by asking questions about the report:
   - "What are the critical vulnerabilities found?"
   - "List all open ports"
   - "Suggest remediations for the vulnerabilities"
   - "What services are running on port 443?"

## Project Structure

```
VulnScanAI_Chatbot/
├── .env                    # Environment variables
├── app.py                  # Main application entry point
├── chatbot_modules/        # Core functionality modules
│   ├── config.py          # Configuration settings
│   ├── local_llm.py       # LLM model loading and inference
│   ├── nmap_parser.py     # Nmap report parsing
│   ├── zap_parser.py      # ZAP report parsing
│   ├── ssl_parser.py      # SSLScan report parsing
│   ├── mobsf_*.py         # MobSF report parsing (Android/iOS)
│   ├── pdf_extractor.py   # Text extraction from PDFs
│   ├── summarizer.py      # Report and chat summarization
│   └── utils.py           # Utility functions
├── Data/                  # Processed data storage
├── documents/             # Uploaded report storage
├── fine_tuned_owasp_model_advanced/  # Fine-tuned embedding model
├── notebooks/             # Jupyter notebooks for development
└── pretrained_language_model/  # Local LLM model storage
```

## Configuration

Modify `chatbot_modules/config.py` to adjust:
- LLM model settings
- RAG parameters
- Chat history settings
- Report-specific keywords

## Troubleshooting

1. **Model Download Issues**:
   - Ensure you have sufficient disk space (~8GB for the model)
   - Check your internet connection
   - Verify write permissions in the target directory

2. **Pinecone Connection Issues**:
   - Verify your API key and environment variables
   - Check your internet connection
   - Ensure your Pinecone index exists and is accessible

3. **Report Parsing Errors**:
   - Verify the report format is supported
   - Check for any corruption in the report file
   - Ensure the file is not password protected

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
