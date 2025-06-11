# VulnScanAI Chatbot

VulnScanAI is an advanced security analysis chatbot designed to help security professionals and developers understand and analyze vulnerability scan reports. It combines local language models with semantic search to provide intelligent, context-aware responses about security findings, particularly focusing on port scanning results, OWASP Top 10 vulnerabilities, and CVE analysis.

## 🌟 Features

- **Report Analysis**: Analyze Nmap,Zap, MobSF, and Nikto scan reports
- **Comprehensive Knowledge Base**: 
  - Port scanning techniques and analysis
  - OWASP Top 10 (2021) vulnerability details
  - Processed CVE data (2020-2025)
- **Local Processing**: Option to use local language models for privacy
- **Semantic Search**: Advanced search across security knowledge base
- **Interactive CLI**: User-friendly command-line interface
- **Report Generation**: Detailed analysis and summary of security findings

## 📁 Project Structure

```
VulnScanAI/
├── Data/                         # Security data and reports
│   ├── QA_Pairs/                 # Structured Q&A pairs
│   │   ├── OWASP_Top10_QA/       # OWASP Top 10 questions and answers
│   │   ├── PORT_Scanning_QA/     # Port scanning related Q&A
│   │   └── Processed_CVEs/       # Processed CVE data (2020-2025)
│   └── reports/                  # Example scan reports
│       ├── mobsf/                # MobSF mobile app scan reports
│       ├── nikto/                # Nikto web server scan reports
│       └── nmap/                 # Nmap network scan reports
├── chatbot_modules/              # Core functionality modules
│   ├── local_llm.py             # Local language model integration
│   ├── nmap_parser.py           # Nmap report parsing utilities
│   └── pdf_extractor.py         # PDF text extraction tools
├── notebooks/                    # Jupyter notebooks for development
│   ├── S1-2_Model_Retraining.ipynb
│   ├── S1_Semantic_Search.ipynb
│   ├── S2_Embedding_Generation.ipynb
│   └── S3_Model_Download.ipynb
├── pretrained_language_model/    # Local model storage
├── fine_tuned_owasp_model_advanced/  # Fine-tuned security model
├── .env                         # Environment configuration
├── .gitignore
└── app.py                      # Main application entry point
```

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- pip (Python package manager)
- Git

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/DivyViradiya07/VulnScanAI.git
   cd VulnScanAI
   ```

2. Create and activate a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: .\venv\Scripts\activate
   ```

3. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up environment variables:
   - Copy `.env.example` to `.env`
   - Update the environment variables as needed

### Usage

1. Start the VulnScanAI CLI:
   ```bash
   python app.py
   ```

2. Follow the on-screen menu to:
   - Upload and analyze scan reports
   - Query the knowledge base
   - Get detailed vulnerability information
   - Generate security reports

## 🤖 Knowledge Base

The system includes a comprehensive knowledge base covering:

- **Port Scanning**: Techniques, analysis, and security implications
- **OWASP Top 10**: Detailed information about the most critical web application security risks
- **CVE Database**: Processed CVE data from 2020-2025
- **Security Best Practices**: Prevention and mitigation strategies

## 🔧 Development

### Setting Up Development Environment

1. Install development dependencies:
   ```bash
   pip install -r requirements-dev.txt
   ```

2. Install pre-commit hooks:
   ```bash
   pre-commit install
   ```

### Running Tests

```bash
pytest tests/
```

## 📚 Documentation

For detailed documentation, please refer to the [docs](docs/) directory.

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📧 Contact

For any questions or feedback, please open an issue or contact the maintainers.
