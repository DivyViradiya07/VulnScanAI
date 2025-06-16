import json
from typing import Dict, Any, List, Optional
from services.llm_service import LLMService
from services.kb_service import KnowledgeBaseService
from utils import report_parser, query_enhancer
import config

class ReportAnalyzer:
    def __init__(self):
        self.llm_service = LLMService()
        self.kb_service = KnowledgeBaseService()
        self.current_loaded_report_data: Optional[Dict[str, Any]] = None
        self.chat_history: List[Dict[str, str]] = []

    def load_report(self, pdf_path: str) -> Optional[str]:
        """
        Loads and processes a security scan PDF report, then generates an initial summary.
        """
        parsed_data = report_parser.parse_report_content(pdf_path)
        if not parsed_data:
            return None

        self.current_loaded_report_data = parsed_data
        print(f"{parsed_data['report_type'].upper()} report parsing complete.")

        if not self.llm_service.is_loaded():
            print("LLM is not loaded. Cannot generate summary.")
            return None

        report_json_str = json.dumps(self.current_loaded_report_data, indent=2)

        prompt_intro = "You are a highly skilled cybersecurity analyst. "
        prompt_focus = ""
        prompt_ending = (
            "Highlight key findings, potential vulnerabilities, and immediate remediation steps. "
            "Only respond with the summary and recommendations in markdown format.\n"
            f"\n{parsed_data['report_type'].upper()} Report Data:\n"
            f"```json\n{report_json_str}\n```\n\n"
            "Please provide your summary and recommendations:"
        )

        if parsed_data['report_type'] == 'nmap':
            prompt_intro += "Your task is to provide explanation of the provided Nmap scan report data (in JSON format) "
            prompt_focus = "Focus on critical information from open ports, service versions, and OS detection."
        elif parsed_data['report_type'] == 'zap':
            prompt_intro += "Your task is to provide explanation of the provided ZAP vulnerability scan report data (in JSON format) "
            prompt_focus = "Focus on critical alerts, risk levels, and specific vulnerabilities identified by ZAP."

        prompt = prompt_intro + prompt_focus + prompt_ending

        print("--- Generating summary with LLM ---")
        print("[+] LLM is generating summary... Please wait.")
        summary = self.llm_service.generate_response(prompt, max_tokens=1000)
        print("[+] LLM summary generated.")

        if not summary or summary.strip() == '':
            return None
        return summary

    def _get_nmap_context(self, user_query_lower: str) -> List[str]:
        """Extracts and formats relevant Nmap context snippets."""
        context_snippets = []
        nmap_metadata_info = self.current_loaded_report_data.get('scan_metadata')

        if nmap_metadata_info:
            metadata_summary = (
                f"Scan Type: {nmap_metadata_info.get('scan_type', 'N/A')}\n"
                f"Initiated By: {nmap_metadata_info.get('scan_initiated_by', 'N/A')}\n"
                f"Timestamp: {nmap_metadata_info.get('timestamp', 'N/A')}\n"
                f"Target: {nmap_metadata_info.get('target', 'N/A')} (IP: {nmap_metadata_info.get('target_ip', 'N/A')})\n"
                f"Nmap Version: {nmap_metadata_info.get('nmap_version', 'N/A')}\n"
                f"Duration: {nmap_metadata_info.get('scan_duration', 'N/A')}"
            )
            context_snippets.append("--- Nmap Scan Report Snippets (General Overview) ---\n" + metadata_summary)

        if self.current_loaded_report_data.get('hosts'):
            context_snippets.append("\n--- Nmap Scan Report Snippets (Host Details) ---")
            for host in self.current_loaded_report_data['hosts']:
                host_info = []
                host_identifier = host.get('hostname', host.get('ip_address', 'Unknown Host'))
                host_info.append(f"Host: {host_identifier} (IP: {host.get('ip_address', 'N/A')})")

                if host.get('ports'):
                    ports_info = []
                    for port in host['ports']:
                        port_info = f"  Port: {port.get('port_id', 'N/A')}/{port.get('protocol', 'N/A')}, " \
                                  f"State: {port.get('state', 'N/A')}, " \
                                  f"Service: {port.get('service', 'N/A')}, " \
                                  f"Version: {port.get('version', 'N/A')}"
                        ports_info.append(port_info)
                        if port.get('script_outputs'):
                            for script_name, script_output in port['script_outputs'].items():
                                script_truncated = script_output.splitlines()[0][:150] + "..." if script_output.splitlines() and len(script_output.splitlines()[0]) > 150 else script_output
                                ports_info.append(f"    Script ({script_name}): {script_truncated}")

                    if ports_info:
                        host_info.append("Open/Filtered Ports:")
                        host_info.extend(ports_info)

                if host.get('os_detection'):
                    os_info = []
                    if host['os_detection'].get('device_type'):
                        os_info.append(f"  Device Type: {', '.join(host['os_detection']['device_type'])}")
                    if host['os_detection'].get('os_guesses'):
                        os_info.append(f"  OS Guesses: {', '.join(host['os_detection']['os_guesses'])}")
                    if host['os_detection'].get('aggressive_os_guesses'):
                        os_info.append(f"  Aggressive OS Guesses: {', '.join(host['os_detection']['aggressive_os_guesses'])}")
                    if os_info:
                        host_info.append("OS Detection:")
                        host_info.extend(os_info)

                if host.get('traceroute'):
                    trace_info = [f"  Hop {h.get('hop', 'N/A')}: {h.get('rtt', 'N/A')} to {h.get('address', 'N/A')}"
                                for h in host.get('traceroute', [])]
                    if trace_info:
                        host_info.append("Traceroute:")
                        host_info.extend(trace_info)

                if host.get('latency'):
                    host_info.append(f"Latency: {host['latency']}")
                if host.get('rdns'):
                    host_info.append(f"rDNS Record: {host['rdns']}")
                if host.get('mac_address'):
                    host_info.append(f"MAC Address: {host['mac_address']}")

                context_snippets.append("\n".join(host_info))
        return context_snippets

    def _get_zap_context(self, user_query_lower: str) -> List[str]:
        """Extracts and formats relevant ZAP context snippets."""
        context_snippets = []
        zap_metadata = self.current_loaded_report_data.get('scan_metadata', {})
        if zap_metadata:
            metadata_summary = (
                f"Scan Type: {zap_metadata.get('scan_type', 'N/A')}\n"
                f"Generated: {zap_metadata.get('generated', 'N/A')}\n"
                f"Generated By: {zap_metadata.get('generated_by', 'N/A')}\n"
                f"Site: {zap_metadata.get('site', 'N/A')}"
            )
            context_snippets.append("--- ZAP Scan Report Snippets (General Overview) ---\n" + metadata_summary)

        if self.current_loaded_report_data.get('alerts'):
            context_snippets.append("\n--- ZAP Scan Report Snippets (Security Alerts) ---")

            stats = self.current_loaded_report_data.get('statistics', {})
            if stats:
                stats_summary = [
                    f"Total Alerts: {stats.get('total_alerts', 'N/A')}",
                    f"High Risk: {stats.get('high', 'N/A')}",
                    f"Medium Risk: {stats.get('medium', 'N/A')}",
                    f"Low Risk: {stats.get('low', 'N/A')}",
                    f"Informational: {stats.get('informational', 'N/A')}"
                ]
                context_snippets.append("\n".join(stats_summary))

            for alert in self.current_loaded_report_data['alerts']:
                alert_info = [
                    f"\nAlert: {alert.get('name', 'N/A')}",
                    f"Risk: {alert.get('risk', 'N/A')}",
                    f"Confidence: {alert.get('confidence', 'N/A')}",
                    f"URL: {alert.get('url', 'N/A')}",
                    f"Description: {alert.get('description', 'N/A')}",
                ]
                if alert.get('solution'):
                    alert_info.append(f"Solution: {alert.get('solution')}")
                if alert.get('reference'):
                    alert_info.append(f"Reference: {alert.get('reference')}")
                context_snippets.append("\n".join(alert_info))
        return context_snippets

    def answer_query(self, user_query: str) -> str:
        """
        Answers a user query by combining relevant information from the loaded report
        and the Pinecone knowledge base, then uses the LLM to synthesize the response.
        """
        if not self.llm_service.is_loaded():
            return "Sorry, the main language model is not loaded. Please try again later."

        all_context_snippets = []
        user_query_lower = user_query.lower()

        # Attempt to answer directly from Loaded Report data first (if relevant)
        direct_answer = self._get_direct_report_answer(user_query, user_query_lower)
        if direct_answer:
            return direct_answer

        # Extract broader Report context (if relevant)
        if self.current_loaded_report_data:
            loaded_report_type = self.current_loaded_report_data.get('report_type', 'none')
            if loaded_report_type == 'nmap':
                is_general_cyber_q = query_enhancer.is_general_cybersecurity_question(user_query)
                nmap_question_category = query_enhancer.categorize_nmap_report_question(user_query)
                is_nmap_context_needed = (nmap_question_category != "not_nmap_specific") or \
                                        (is_general_cyber_q and any(term in user_query_lower for term in ["port", "host", "ip address", "service", "report"]))
                if is_nmap_context_needed:
                    all_context_snippets.extend(self._get_nmap_context(user_query_lower))
            elif loaded_report_type == 'zap':
                all_context_snippets.extend(self._get_zap_context(user_query_lower))

        # Always retrieve relevant information from Pinecone
        print("Attempting to retrieve information from Pinecone knowledge base.")
        expanded_user_queries = query_enhancer.expand_query(user_query)

        all_pinecone_results = []
        for query_variant in expanded_user_queries:
            is_mitigation_query = any(k in query_variant.lower() for k in ["how to", "prevent", "mitigate", "close", "secure", "fix", "remediation", "solution"])
            is_port_scanning_related_pinecone = any(k in query_variant.lower() for k in ["port", "scan", "tcp", "udp", "syn", "stealth", "firewall", "vulnerability"])

            pinecone_top_k = 7 if is_mitigation_query or is_port_scanning_related_pinecone else 5
            results_for_variant = self.kb_service.retrieve_from_pinecone(query_variant, top_k=pinecone_top_k)
            all_pinecone_results.extend(results_for_variant)

        unique_pinecone_results = []
        seen_qa_pairs = set()
        for res in all_pinecone_results:
            qa_hash = (res.get('question', ''), res.get('answer', ''))
            if qa_hash not in seen_qa_pairs:
                unique_pinecone_results.append(res)
                seen_qa_pairs.add(qa_hash)

        unique_pinecone_results.sort(key=lambda x: x['score'], reverse=True)
        pinecone_results = unique_pinecone_results[:7]

        if pinecone_results:
            pinecone_context_items = []
            for item in pinecone_results:
                if item.get('question') and item.get('answer') and \
                   item.get('question').strip() != 'N/A' and item.get('answer').strip() != 'N/A':
                    pinecone_context_items.append(
                        f"Question: {item['question']}\n"
                        f"Answer: {item['answer']}\n"
                        f"Source File: {item['source_file']} (Category: {item['top_level_category']})"
                    )
                    if item.get('related_topics') != 'N/A' and item.get('related_topics'):
                        pinecone_context_items[-1] += f" | Related Topics: {item['related_topics']}"

            if pinecone_context_items:
                all_context_snippets.append("\n--- Cybersecurity Knowledge Base Snippets (Pinecone) ---")
                all_context_snippets.extend(pinecone_context_items)
                print(f"Pinecone KB snippets retrieved. Total size: {len('\n'.join(pinecone_context_items))} characters.")
            else:
                print("No *usable* Pinecone KB snippets retrieved for this query.")
        else:
            print("No relevant Pinecone KB snippets retrieved for this query.")

        context_for_llm = "\n\n".join(all_context_snippets)
        formatted_history_str = self._format_chat_history(self.chat_history)
        if formatted_history_str:
            formatted_history_str = "\n\nPrevious Conversation:\n" + formatted_history_str + "\n"

        system_instruction = (
            "You are a highly skilled cybersecurity analyst and an expert in security reports and general cybersecurity. "
            "Your primary goal is to provide accurate, concise, and actionable answers to user queries. "
            "Always respond in markdown format. "
            "You have access to information from the following sources:\n"
            "1. A structured security scan report (if provided in '--- [Report Type] Scan Report Snippets ---' section).\n"
            "2. A unified cybersecurity knowledge base (if provided in '--- Cybersecurity Knowledge Base Snippets (Pinecone) ---' section).\n\n"
            "Synthesize information from *all provided contexts* to answer the user's question comprehensively. "
            "Prioritize factual data directly from the loaded report when explicitly asked about specific report details. "
            "If the question is general cybersecurity knowledge or asks for 'how to', 'prevent', 'mitigate', 'close', 'secure', or 'fix', "
            "leverage the cybersecurity knowledge base snippets to provide detailed, actionable steps and recommendations. "
            "Do not fabricate information. If information is not explicitly available in *any* provided context (Report or Pinecone), "
            "then provide a concise answer based on your general cybersecurity knowledge. Clearly state if the answer is based on general knowledge and not from the provided context."
        )

        user_prompt_content = f"User Query: {user_query}\n\n"

        if context_for_llm:
            user_prompt_content = f"Here is the relevant context:\n```\n{context_for_llm}\n```\n\n" + user_prompt_content
        else:
            user_prompt_content = "No specific context found from the loaded report or external knowledge base for your query. Please answer based on your general cybersecurity knowledge.\n" + user_prompt_content

        full_prompt = f"<s>[INST] {system_instruction}"
        if formatted_history_str:
            full_prompt += f"\n{formatted_history_str}"
        full_prompt += f"\n\n{user_prompt_content} [/INST]"

        print("\n--- Full Prompt Sent to LLM ---")
        print(full_prompt)
        print("--------------------------------\n")

        print("[+] LLM is generating response... Please wait.")
        answer = self.llm_service.generate_response(full_prompt, max_tokens=1500)
        print("[+] LLM response generated.")

        if not answer or answer.strip() == '':
            print("[!] LLM returned an empty or whitespace-only response. Providing a generic fallback.")
            return "I'm sorry, I couldn't generate a response for your query at this moment. There might have been an issue with the language model or the query format."

        return answer

    def _get_direct_report_answer(self, user_query: str, user_query_lower: str) -> Optional[str]:
        """Attempts to find a direct answer within the loaded report data."""
        if not self.current_loaded_report_data:
            return None

        loaded_report_type = self.current_loaded_report_data.get('report_type')

        if loaded_report_type == 'nmap':
            nmap_metadata_info = self.current_loaded_report_data.get('scan_metadata')
            direct_nmap_metadata_map = {}
            if nmap_metadata_info:
                direct_nmap_metadata_map = {
                    "target ip address": nmap_metadata_info.get('target_ip'),
                    "target": nmap_metadata_info.get('target'),
                    "scan type": nmap_metadata_info.get('scan_type'),
                    "initiated by": nmap_metadata_info.get('scan_initiated_by'),
                    "timestamp": nmap_metadata_info.get('timestamp'),
                    "nmap version": nmap_metadata_info.get('nmap_version'),
                    "duration": nmap_metadata_info.get('scan_duration'),
                }
                if self.current_loaded_report_data.get('hosts'):
                    primary_host = self.current_loaded_report_data['hosts'][0]
                    direct_nmap_metadata_map["rdns record"] = primary_host.get('rdns')
                    direct_nmap_metadata_map["mac address"] = primary_host.get('mac_address')
                    direct_nmap_metadata_map["latency"] = primary_host.get('latency')

            for phrase, value in direct_nmap_metadata_map.items():
                if value and isinstance(value, str) and value.strip() != 'N/A' and phrase in user_query_lower:
                    direct_answer_text = f"The Nmap report states the {phrase} is: {value}."
                    print(f"--- Direct Nmap Answer Found for '{phrase}' ---")
                    concise_system_prompt = "You are a helpful assistant. Provide the factual answer directly based on the provided Nmap snippet. Do not add extra commentary. If the snippet doesn't contain the direct answer, state so concisely."
                    concise_user_prompt = f"Nmap Snippet: {direct_answer_text}\n\nUser Question: {user_query}"
                    concise_full_prompt = f"<s>[INST] {concise_system_prompt}\n\n{concise_user_prompt} [/INST]"
                    try:
                        final_answer = self.llm_service.generate_response(concise_full_prompt, max_tokens=100)
                        if final_answer and final_answer.strip() != '' and "cannot answer" not in final_answer.lower():
                            return final_answer
                    except Exception as e:
                        print(f"Error generating direct Nmap answer: {e}")
                    return "" # Indicate that a direct answer was attempted but LLM didn't return useful info

        elif loaded_report_type == 'zap':
            zap_alerts = self.current_loaded_report_data.get('alerts', [])
            zap_metadata = self.current_loaded_report_data.get('site', {}) or {}

            # Metadata direct answers
            metadata_terms = [
                "site", "target", "scanned", "host", "url", "domain", "address", "endpoint",
                "generated", "created", "scan date", "scan time", "report date", "timestamp",
                "version", "zap version", "zap release", "zap build", "scanner version",
                "policy", "scan policy", "context", "scan context", "scope", "included", "excluded",
                "scan type", "scan mode", "spider", "ajax spider", "active scan", "passive scan",
                "authentication", "logged in", "login", "auth", "session", "user", "credentials",
                "zap", "report", "alerts", "high" , "medium", "low", "informational", "csp", "clickjacking",
                "hsts", "CWE", "wasc", "attack", "plugin id"
            ]

            if any(term in user_query_lower for term in metadata_terms):
                site_info = []
                if 'name' in zap_metadata:
                    site_info.append(f"- Site: {zap_metadata['name']}")
                if 'host' in zap_metadata:
                    site_info.append(f"- Host: {zap_metadata['host']}")
                if 'port' in zap_metadata:
                    site_info.append(f"- Port: {zap_metadata['port']}")
                if 'generated' in self.current_loaded_report_data:
                    site_info.append(f"- Report generated: {self.current_loaded_report_data['generated']}")
                if 'version' in self.current_loaded_report_data:
                    site_info.append(f"- ZAP version: {self.current_loaded_report_data['version']}")
                if site_info:
                    return "ZAP Scan Information:\n" + "\n".join(site_info)

            # Alert statistics
            if any(term in user_query_lower for term in ["total alerts", "number of alerts", "how many alerts"]):
                alert_count = len(zap_alerts)
                return f"Total number of alerts found: {alert_count}"
            elif any(term in user_query_lower for term in ["high-risk", "high risk"]) and "how many" in user_query_lower:
                high_count = sum(1 for a in zap_alerts if a.get('risk') == 'High')
                return f"Number of high-risk alerts: {high_count}"
            elif any(term in user_query_lower for term in ["medium-risk", "medium risk"]) and "how many" in user_query_lower:
                med_count = sum(1 for a in zap_alerts if a.get('risk') == 'Medium')
                return f"Number of medium-risk alerts: {med_count}"
            elif any(term in user_query_lower for term in ["low-risk", "low risk"]) and "how many" in user_query_lower:
                low_count = sum(1 for a in zap_alerts if a.get('risk') == 'Low')
                return f"Number of low-risk alerts: {low_count}"
            elif any(term in user_query_lower for term in ["informational", "info alerts"]) and "how many" in user_query_lower:
                info_count = sum(1 for a in zap_alerts if a.get('risk') == 'Informational')
                return f"Number of informational alerts: {info_count}"

            # Specific alert types
            alert_handlers = [
                {
                    'terms': ["content security policy", "csp"],
                    'name_contains': 'content security policy',
                    'description': 'Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks.',
                    'solution': 'Ensure that your web application sets a Content-Security-Policy header with appropriate directives.',
                    'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'
                },
                {
                    'terms': ["clickjacking", "x-frame-options", "x frame"],
                    'name_contains': 'clickjacking',
                    'description': 'Clickjacking is a malicious technique of tricking a user into clicking something different from what the user perceives.',
                    'solution': 'Set the X-Frame-Options header to "DENY" or "SAMEORIGIN" to prevent clickjacking attacks.',
                    'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'
                },
                {
                    'terms': ["hsts", "strict transport security", "http strict transport security"],
                    'name_contains': 'strict transport security',
                    'description': 'HTTP Strict Transport Security (HSTS) ensures browsers only connect to your server over HTTPS.',
                    'solution': 'Set the Strict-Transport-Security header with an appropriate max-age and includeSubDomains directive.',
                    'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'
                },
                {
                    'terms': ["x-content-type-options", "mime sniffing"],
                    'name_contains': 'x-content-type-options',
                    'description': 'MIME sniffing can cause security issues when browsers interpret files as a different MIME type than declared.',
                    'solution': 'Set the X-Content-Type-Options header to "nosniff" to prevent MIME type sniffing.',
                    'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options'
                },
                {
                    'terms': ["x-xss-protection", "xss protection"],
                    'name_contains': 'x-xss-protection',
                    'description': 'X-XSS-Protection is a feature that can help prevent some types of Cross-Site Scripting (XSS) attacks.',
                    'solution': 'For modern browsers, consider using Content-Security-Policy instead. For legacy support, set X-XSS-Protection: 1; mode=block.',
                    'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection'
                }
            ]

            for handler in alert_handlers:
                if any(term in user_query_lower for term in handler['terms']):
                    matching_alerts = [a for a in zap_alerts if handler['name_contains'] in a.get('name', '').lower()]
                    if matching_alerts:
                        alert = matching_alerts[0]
                        alert_info = [
                            f"## {alert.get('name', 'Alert')}",
                            f"**Risk Level:** {alert.get('risk', 'N/A')}",
                            f"**Instances Found:** {len(matching_alerts)}",
                            f"\n**Description:**\n{alert.get('description', handler.get('description', 'No description available.'))}",
                            f"\n**Solution:**\n{alert.get('solution', handler.get('solution', 'No specific solution provided.'))}",
                            f"\n**Affected URLs:**\n- " + "\n- ".join(set(a.get('url', 'N/A') for a in matching_alerts)),
                            f"\n**References:**\n{alert.get('reference', handler.get('reference', 'No references provided.'))}"
                        ]
                        if 'cweid' in alert and alert['cweid'] not in ['0', '']:
                            alert_info.append(f"\n**CWE ID:** CWE-{alert['cweid']}")
                        if 'wascid' in alert and alert['wascid'] not in ['0', '']:
                            alert_info.append(f"**WASC ID:** WASC-{alert['wascid']}")
                        return "\n".join(alert_info)

            # Generic alert information
            if any(term in user_query_lower for term in ["alerts", "vulnerabilities", "issues", "risks"]):
                if zap_alerts:
                    risk_levels = {}
                    for alert in zap_alerts:
                        risk = alert.get('risk', 'Unknown')
                        if risk not in risk_levels:
                            risk_levels[risk] = []
                        risk_levels[risk].append(alert)

                    alert_summary = ["ZAP Scan Alert Summary:"]
                    for risk, alerts in sorted(risk_levels.items(), key=lambda x: x[0], reverse=True):
                        alert_summary.append(f"\n{risk.upper()} RISK ({len(alerts)} alerts):")
                        for alert in alerts:
                            alert_summary.append(f"- {alert.get('name', 'Unnamed Alert')}")
                            alert_summary.append(f"  URL: {alert.get('url', 'N/A')}")
                    return "\n".join(alert_summary)
        return None

    def _format_chat_history(self, history: List[Dict[str, str]]) -> str:
        """Formats the chat history for inclusion in the LLM prompt."""
        formatted_history = []
        for turn in history:
            content_preview = turn['content'][:200] + "..." if len(turn['content']) > 200 else turn['content']
            formatted_history.append(f"{turn['role'].capitalize()}: {content_preview}")
        return "\n".join(formatted_history)

    def add_to_chat_history(self, role: str, content: str):
        self.chat_history.append({"role": role, "content": content})
        if len(self.chat_history) > config.MAX_CHAT_HISTORY_TURNS * 2:
            self.chat_history = self.chat_history[-(config.MAX_CHAT_HISTORY_TURNS * 2):]

    def clear_chat_history(self):
        self.chat_history.clear()

    def clear_report_data(self):
        self.current_loaded_report_data = None