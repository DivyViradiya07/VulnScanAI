import os
import sys
from core.report_analyzer import ReportAnalyzer
import config

class CLIInterface:
    def __init__(self):
        self.analyzer = ReportAnalyzer()

    def print_header(self):
        print("\n" + "=" * 70)
        print("      Nmap/ZAP Report Analyzer & Cybersecurity Assistant")
        print("=" * 70)

    def print_section(self, title):
        print(f"\n{' ' + title + ' ':-^70}")

    def print_help(self):
        self.print_section("HELP")
        print("  Commands:")
        print("  - new report : Load a different security report (Nmap or ZAP)")
        print("  - help       : Show this help message")
        print("  - exit       : Exit the application")
        print("\n  Ask questions about the loaded report or general cybersecurity topics.")

    def run(self):
        self.print_header()
        print("\nWelcome! Upload a security report (Nmap or ZAP PDF) to begin analysis.")
        print("Type 'help' for commands or 'exit' to quit.\n")

        while True:
            try:
                user_input = input("\n[?] Enter PDF path or command: ").strip()

                if user_input.lower() == 'exit':
                    print("\n[+] Thank you for using Report Analyzer. Goodbye!")
                    break

                if user_input.lower() == 'help':
                    self.print_help()
                    continue

                if not user_input:
                    print("[!] Please enter a valid command, PDF path, or a question.")
                    continue

                if user_input.lower() == 'new report' or user_input.lower().endswith('.pdf') or os.path.exists(user_input):
                    pdf_file_path_input = ""
                    if user_input.lower() == 'new report':
                        print("\n[+] Initiating new report upload...")
                        self.analyzer.clear_report_data()
                        self.analyzer.clear_chat_history()
                        pdf_file_path_input = input("\n[?] Enter PDF report path: ").strip()
                    else:
                        pdf_file_path_input = user_input

                    if os.path.isabs(pdf_file_path_input):
                        pdf_file_path = pdf_file_path_input
                    else:
                        pdf_file_path = os.path.join(config.DOCUMENTS_DIR, pdf_file_path_input)

                    if not os.path.isfile(pdf_file_path):
                        print(f"Error: No file found at '{pdf_file_path}'. Please check the path and try again.")
                        continue
                    if not pdf_file_path.lower().endswith('.pdf'):
                        print(f"Error: '{pdf_file_path}' is not a PDF file. Please provide a PDF.")
                        continue

                    print(f"Loading and analyzing report: {os.path.basename(pdf_file_path)}")
                    summary = self.analyzer.load_report(pdf_file_path)

                    if summary:
                        self.print_section("REPORT SUMMARY")
                        print(summary)
                        self.analyzer.add_to_chat_history("model", summary)
                        self.print_section("INTERACTIVE ANALYSIS")
                        print("Report loaded. You can now ask questions about this report or general cybersecurity topics.")
                        print("Type 'new report' to analyze a different scan or 'exit' to quit.\n")
                    else:
                        print("\n[!] Failed to process the report. Please check the file and try again.")
                    continue

                if self.analyzer.current_loaded_report_data is None:
                    print("[!] No security report is currently loaded. Please load a report first (e.g., enter its PDF path).")
                    continue

                user_question = user_input
                self.analyzer.add_to_chat_history("user", user_question)

                print("\n[+] Analyzing your question...")
                answer = self.analyzer.answer_query(user_question)

                self.print_section("ANALYSIS RESULTS")
                print(answer)
                self.analyzer.add_to_chat_history("model", answer)

            except KeyboardInterrupt:
                print("\n[!] Operation cancelled. Type 'exit' to quit or enter a file path/command.")
            except Exception as e:
                print(f"\n[!] An error occurred: {str(e)}")
                import traceback
                traceback.print_exc()

        self.analyzer.llm_service.cleanup() # Ensure LLM is closed on exit