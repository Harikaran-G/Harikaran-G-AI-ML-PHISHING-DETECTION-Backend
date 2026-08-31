from typing import Dict, Any, List

# Embedded MITRE ATT&CK Knowledge Base
MITRE_ATTACK_KNOWLEDGE = {
    "FILE-001": {
        "techniqueId": "T1036.007",
        "techniqueName": "Masquerading: Double Extension",
        "tactic": "Defense Evasion",
        "description": "Adversaries may disguise executables with multiple file extensions to mislead victims and bypass security filters.",
    },
    "FILE-002": {
        "techniqueId": "T1027.002",
        "techniqueName": "Obfuscated Files or Information: Software Packing",
        "tactic": "Defense Evasion",
        "description": "Adversaries pack or encrypt file payloads to elevate byte entropy and evade signature-based detection.",
    },
    "FILE-005": {
        "techniqueId": "T1071.001",
        "techniqueName": "Application Layer Protocol: Direct IP C2",
        "tactic": "Command and Control",
        "description": "Hardcoded external IP communications allow binaries to bypass domain resolution logging.",
    },
    "FILE-007": {
        "techniqueId": "T1059.001",
        "techniqueName": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "description": "PowerShell command execution enables in-memory shellcode loading and fileless downloader behavior.",
    },
    "URL-SSRF-01": {
        "techniqueId": "T1190",
        "techniqueName": "Exploit Public-Facing Application: Server-Side Request Forgery",
        "tactic": "Initial Access",
        "description": "Targeting loopback or RFC 1918 subnets attempts to pivot into internal cloud metadata or local microservices.",
    },
    "URL-USERINFO-01": {
        "techniqueId": "T1566.002",
        "techniqueName": "Phishing: Spearphishing Link (Userinfo Deception)",
        "tactic": "Initial Access",
        "description": "Adversaries embed brand names or lure text in the URL authority userinfo (@ delimiter) to mislead victims about the destination domain.",
    },
    "URL-USERINFO-BRAND": {
        "techniqueId": "T1036.005",
        "techniqueName": "Masquerading: Match Legitimate Name or Location",
        "tactic": "Defense Evasion",
        "description": "Deceptive userinfo strings mimic trusted corporate domains and promotional login portals.",
    },
    "URL-SUBDOMAIN-ANOMALY": {
        "techniqueId": "T1583.001",
        "techniqueName": "Acquire Infrastructure: Domains & Dynamic Subdomains",
        "tactic": "Resource Development",
        "description": "Automated, high-entropy, or disposable subdomain generation facilitates short-lived phishing landing pages.",
    },
    "URL-INFRA-TUNNEL": {
        "techniqueId": "T1572",
        "techniqueName": "Protocol Tunneling / Reverse Port Forwarding",
        "tactic": "Command and Control & Defense Evasion",
        "description": "Ephemeral reverse tunneling platforms (e.g. Cloudflare Quick Tunnels, Ngrok) bypass traditional perimeter reputation filters.",
    },
    "URL-004": {
        "techniqueId": "T1566.002",
        "techniqueName": "Phishing: Spearphishing Link (IDN Homograph)",
        "tactic": "Initial Access",
        "description": "Punycode spoofing masks fraudulent domains under visually identical legitimate brand names.",
    },
    "APK-001": {
        "techniqueId": "T1437.001",
        "techniqueName": "Application Impersonation / Overlay Injection",
        "tactic": "Credential Access & Defense Evasion",
        "description": "Combining screen overlay permissions with SMS or Accessibility interception enables credential harvesting and OTP theft.",
    },
}

def retrieve_mitre_context(indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    RAG retrieval: Maps detected indicators to authoritative MITRE ATT&CK techniques.
    """
    tactics = []
    seen = set()
    for ind in indicators:
        rule_id = ind.get("id", "")
        if rule_id in MITRE_ATTACK_KNOWLEDGE and rule_id not in seen:
            seen.add(rule_id)
            tactics.append({
                "ruleId": rule_id,
                "indicatorName": ind.get("name", ""),
                **MITRE_ATTACK_KNOWLEDGE[rule_id]
            })
    return tactics
