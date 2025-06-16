from typing import List
from collections import Counter
import re

def extract_keywords(text: str) -> List[str]:
    """Extract important keywords from text for query expansion."""
    stopwords = {"a", "an", "the", "and", "or", "but", "if", "then", "else", "when",
                "at", "by", "for", "with", "about", "against", "between", "into",
                "through", "during", "before", "after", "above", "below", "to", "from",
                "up", "down", "in", "out", "on", "off", "over", "under", "again",
                "further", "then", "once", "here", "there", "all", "any", "both",
                "each", "few", "more", "most", "other", "some", "such", "no", "nor",
                "not", "only", "own", "same", "so", "than", "too", "very", "can",
                "will", "just", "should", "now", "what", "which", "how", "where", "is", "are"}

    security_terms = {"vulnerability", "exploit", "cve", "attack", "threat", "risk",
                     "compromise", "security", "breach", "patch", "fix", "update",
                     "mitigation", "remediation", "severity", "impact", "unauthorized",
                     "access", "disclosure", "injection", "overflow", "credentials",
                     "port", "scan", "tcp", "udp", "http", "https", "ssh", "smtp", "dns", "firewall", "os"}

    stopwords = stopwords - security_terms

    words = text.lower().split()
    important_words = [word for word in words if word not in stopwords and len(word) > 2]

    word_counts = Counter(important_words)
    keywords = [word for word, count in word_counts.most_common(7)]

    all_keywords = list(set(important_words + keywords))

    print(f"Extracted keywords: {all_keywords}")
    return all_keywords

def expand_query(question: str) -> List[str]:
    """Generate multiple query variations to improve retrieval."""
    print(f"Expanding query: '{question}'")
    keywords = extract_keywords(question)

    queries = [question]

    if keywords:
        keyword_query = " ".join(keywords)
        if keyword_query != question.lower() and keyword_query not in queries:
            queries.append(keyword_query)

    question_lower = question.lower()
    question_words = ["what is", "what are", "how to", "how do", "explain", "tell me about"]
    for q_word in question_words:
        if question_lower.startswith(q_word):
            clean_q = question_lower.replace(q_word, "", 1).strip()
            if clean_q and clean_q not in queries:
                queries.append(clean_q)

    if len(keywords) >= 2:
        for i in range(len(keywords)):
            for j in range(i+1, len(keywords)):
                bigram = f"{keywords[i]} {keywords[j]}"
                if bigram not in queries and len(bigram.split()) <= 3:
                    queries.append(bigram)

    if any(term in question_lower for term in ["vulnerability", "security", "risk", "threat", "hack"]):
        if "high" in question_lower or "critical" in question_lower:
            queries.append("high severity vulnerability security risk")
        if "remediation" in question_lower or "solution" in question_lower or "fix" in question_lower:
            queries.append("vulnerability remediation solution fix best practices")

    unique_queries = []
    seen_queries = set()
    for q in queries:
        if q not in seen_queries:
            unique_queries.append(q)
            seen_queries.add(q)

    print(f"Expanded queries: {unique_queries}")
    return unique_queries

def is_general_cybersecurity_question(question: str) -> bool:
    """Check if the user is asking a general cybersecurity question not specific to a loaded report."""
    question_lower = question.lower()

    cybersecurity_keywords = [
        "cybersecurity", "security best practices", "security policy", "cyber attack",
        "phishing", "ransomware", "malware", "zero day", "firewall", "encryption",
        "security framework", "compliance", "security standard", "penetration testing",
        "security awareness", "data breach", "incident response", "security controls",
        "authentication", "authorization", "zero trust", "security posture", "threat actor",
        "social engineering", "mfa", "2fa", "access control", "security audit", "ddos", "dos",
        "vpn", "cloud security", "iot security", "secure coding", "devsecops", "threat intelligence",
        "sql injection", "xss", "cross-site scripting", "fin scan", "xmas scan", "tcp", "udp"
    ]

    nmap_report_specific_terms = [
        "nmap", "scan", "report", "host", "ip address", "port", "service", "os detection",
        "traceroute", "latency", "mac address", "open port", "filtered port", "closed port",
        "script output", "version detection", "aggressive scan", "syn scan", "udp scan",
        "on the report", "in this report", "from this scan"
    ]

    contains_cyber_keywords = any(keyword in question_lower for keyword in cybersecurity_keywords)
    contains_nmap_keywords = any(term in question_lower for term in nmap_report_specific_terms)

    if contains_cyber_keywords:
        if any(re.search(pattern, question_lower) for pattern in [
            r"what is (a|an|the)?\s*(phishing|ransomware|malware|sql injection|xss|ddos|firewall|encryption|vpn|mfa|zero trust|social engineering|fin scan|xmas scan|tcp|udp)",
            r"(explain|tell me about)\s*(phishing|ransomware|malware|sql injection|xss|ddos|firewall|encryption|vpn|mfa|zero trust|social engineering|fin scan|xmas scan|tcp|udp)"
        ]):
            return True

        if not contains_nmap_keywords:
            return True

    return False

def categorize_nmap_report_question(question: str) -> str:
    """
    Categorizes Nmap-report specific questions to guide context extraction and LLM response.
    Returns a specific category or "not_nmap_specific" if it's primarily general.
    """
    question_lower = question.lower()

    if "summary" in question_lower or "overview" in question_lower or "explain the report" in question_lower or "tell me about this report" in question_lower:
        return "report_summary"
    if "open ports" in question_lower or "which ports are open" in question_lower or ("ports" in question_lower and "open" in question_lower):
        return "open_ports"
    if "closed ports" in question_lower or "filtered ports" in question_lower:
        return "closed_filtered_ports"
    if "services" in question_lower or "what services" in question_lower:
        return "services_info"
    if "os" in question_lower or "operating system" in question_lower or "device type" in question_lower:
        return "os_info"
    if "vulnerability" in question_lower or "vulnerabilities" in question_lower or "security issues" in question_lower:
        return "vulnerability_info"
    if "how to fix" in question_lower or "remediation" in question_lower or "mitigate" in question_lower or "prevent" in question_lower or "secure" in question_lower:
        return "remediation_advice"
    if "target" in question_lower or "ip address" in question_lower or "hostname" in question_lower:
        return "target_info"
    if "scan type" in question_lower or "initiated" in question_lower or "timestamp" in question_lower or "duration" in question_lower or "nmap version" in question_lower:
        return "scan_metadata"
    if "traceroute" in question_lower or "hops" in question_lower:
        return "traceroute_info"
    if "latency" in question_lower or "speed" in question_lower:
        return "latency_info"
    if "mac address" in question_lower:
        return "mac_info"

    nmap_general_terms = ["nmap", "scan", "report", "host", "this report"]
    if any(term in question_lower for term in nmap_general_terms):
        return "general_nmap"

    return "not_nmap_specific"