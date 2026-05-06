"""
MITRE ATT&CK Framework mappings for alert correlation and display.
Contains tactics, techniques, and recommended analyst actions.
"""

MITRE_TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
    "TA0042": "Resource Development",
    "TA0043": "Reconnaissance",
}

MITRE_TECHNIQUES = {
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "TA0002",
        "tactic_name": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands.",
        "sub_techniques": {
            "T1059.001": "PowerShell",
            "T1059.003": "Windows Command Shell",
            "T1059.004": "Unix Shell",
            "T1059.006": "Python",
        },
        "severity": "high",
        "recommended_action": "Review command history, check parent process, isolate if confirmed malicious.",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "TA0006",
        "tactic_name": "Credential Access",
        "description": "Adversaries may use brute force techniques to gain access to accounts.",
        "sub_techniques": {
            "T1110.001": "Password Guessing",
            "T1110.002": "Password Cracking",
            "T1110.003": "Password Spraying",
            "T1110.004": "Credential Stuffing",
        },
        "severity": "high",
        "recommended_action": "Block source IP, force password reset on targeted accounts, review for compromised credentials.",
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "TA0005",
        "tactic_name": "Defense Evasion",
        "description": "Adversaries may attempt to make a payload difficult to discover or analyze.",
        "sub_techniques": {
            "T1027.001": "Binary Padding",
            "T1027.005": "Indicator Removal from Tools",
            "T1027.010": "Command Obfuscation",
        },
        "severity": "high",
        "recommended_action": "Decode and analyze the obfuscated content, check for known malware signatures.",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "TA0001",
        "tactic_name": "Initial Access",
        "description": "Adversaries may obtain and abuse credentials of existing accounts.",
        "sub_techniques": {
            "T1078.001": "Default Accounts",
            "T1078.002": "Domain Accounts",
            "T1078.003": "Local Accounts",
            "T1078.004": "Cloud Accounts",
        },
        "severity": "medium",
        "recommended_action": "Verify account legitimacy, check login geo-location, review session activity.",
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "TA0001",
        "tactic_name": "Initial Access",
        "description": "Adversaries may send phishing messages to gain access to systems.",
        "sub_techniques": {
            "T1566.001": "Spearphishing Attachment",
            "T1566.002": "Spearphishing Link",
            "T1566.003": "Spearphishing via Service",
        },
        "severity": "high",
        "recommended_action": "Quarantine email, scan attachments, notify affected users, check for credential compromise.",
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "TA0011",
        "tactic_name": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols.",
        "sub_techniques": {
            "T1071.001": "Web Protocols",
            "T1071.004": "DNS",
        },
        "severity": "critical",
        "recommended_action": "Block C2 domains/IPs, isolate affected hosts, conduct memory forensics.",
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "TA0003",
        "tactic_name": "Persistence",
        "description": "Adversaries may abuse task scheduling to execute malicious code.",
        "sub_techniques": {
            "T1053.003": "Cron",
            "T1053.005": "Scheduled Task",
        },
        "severity": "medium",
        "recommended_action": "Review scheduled tasks/cron jobs, check for unauthorized entries.",
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "TA0007",
        "tactic_name": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts.",
        "sub_techniques": {},
        "severity": "medium",
        "recommended_action": "Identify scanning source, check for lateral movement, isolate if internal.",
    },
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "TA0004",
        "tactic_name": "Privilege Escalation",
        "description": "Adversaries may circumvent mechanisms designed to control elevated privileges.",
        "sub_techniques": {
            "T1548.001": "Setuid and Setgid",
            "T1548.002": "Bypass User Account Control",
            "T1548.003": "Sudo and Sudo Caching",
        },
        "severity": "high",
        "recommended_action": "Review privilege escalation chain, audit sudoers/UAC config, check for persistence.",
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "TA0008",
        "tactic_name": "Lateral Movement",
        "description": "Adversaries may use valid accounts to log into a service for lateral movement.",
        "sub_techniques": {
            "T1021.001": "Remote Desktop Protocol",
            "T1021.002": "SMB/Windows Admin Shares",
            "T1021.004": "SSH",
        },
        "severity": "high",
        "recommended_action": "Verify authorized access, check source credentials, review lateral movement path.",
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "TA0010",
        "tactic_name": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating it over a different protocol than C2.",
        "sub_techniques": {
            "T1048.001": "Exfiltration Over Symmetric Encrypted Non-C2 Protocol",
            "T1048.002": "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
            "T1048.003": "Exfiltration Over Unencrypted Non-C2 Protocol",
        },
        "severity": "critical",
        "recommended_action": "Block exfiltration channel, preserve evidence, assess data exposure, notify stakeholders.",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "TA0001",
        "tactic_name": "Initial Access",
        "description": "Adversaries may attempt to exploit vulnerabilities in internet-facing applications.",
        "sub_techniques": {},
        "severity": "critical",
        "recommended_action": "Patch vulnerability, review web logs, check for webshells, isolate affected server.",
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "TA0006",
        "tactic_name": "Credential Access",
        "description": "Adversaries may attempt to dump credentials for lateral movement.",
        "sub_techniques": {
            "T1003.001": "LSASS Memory",
            "T1003.002": "Security Account Manager",
            "T1003.003": "NTDS",
        },
        "severity": "critical",
        "recommended_action": "Isolate host immediately, force enterprise-wide password reset, investigate lateral movement.",
    },
    "T1543": {
        "name": "Create or Modify System Process",
        "tactic": "TA0003",
        "tactic_name": "Persistence",
        "description": "Adversaries may create or modify system-level processes for persistence.",
        "sub_techniques": {
            "T1543.003": "Windows Service",
        },
        "severity": "high",
        "recommended_action": "Review new services, check service binary paths, verify digital signatures.",
    },
    "T1595": {
        "name": "Active Scanning",
        "tactic": "TA0043",
        "tactic_name": "Reconnaissance",
        "description": "Adversaries may execute active reconnaissance scans to gather information.",
        "sub_techniques": {
            "T1595.001": "Scanning IP Blocks",
            "T1595.002": "Vulnerability Scanning",
        },
        "severity": "low",
        "recommended_action": "Monitor scanning activity, update firewall rules, assess exposed attack surface.",
    },
}


def get_technique(technique_id: str) -> dict | None:
    """Look up a MITRE ATT&CK technique by ID."""
    base_id = technique_id.split(".")[0]
    return MITRE_TECHNIQUES.get(base_id)


def get_tactic_name(tactic_id: str) -> str:
    """Look up a MITRE ATT&CK tactic name by ID."""
    return MITRE_TACTICS.get(tactic_id, "Unknown")


def get_all_techniques() -> list[dict]:
    """Return all techniques as a list."""
    result = []
    for tid, info in MITRE_TECHNIQUES.items():
        result.append({"id": tid, **info})
    return result
