"""
Alert Correlation Engine.
Rule-based detection that analyzes log streams and generates security alerts.
"""
import json
from datetime import datetime, timezone
from collections import defaultdict
from backend.mitre.mappings import get_technique


class CorrelationRule:
    """Base class for correlation rules."""
    def __init__(self, name, description, severity, mitre_technique, recommended_action):
        self.name = name
        self.description = description
        self.severity = severity
        self.mitre_technique = mitre_technique
        self.recommended_action = recommended_action
        technique = get_technique(mitre_technique)
        self.mitre_tactic = technique["tactic_name"] if technique else ""
        self.mitre_technique_name = technique["name"] if technique else ""

    def evaluate(self, log, context):
        raise NotImplementedError


class BruteForceRule(CorrelationRule):
    """5+ failed logins from same IP followed by success → brute force alert."""
    def __init__(self):
        super().__init__(
            "Brute Force Detected",
            "Multiple failed login attempts followed by successful login from same source",
            "high", "T1110",
            "Block source IP, force password reset on targeted accounts, investigate compromised session.",
        )

    def evaluate(self, log, context):
        ip = log.get("source_ip", "")
        if not ip:
            return None
        key = f"failed_login_{ip}"
        if log["event_type"] == "failed_login" or log["event_type"] == "ssh_failed_login":
            context[key] = context.get(key, 0) + 1
            return None
        if log["event_type"] in ("successful_login",) and context.get(key, 0) >= 5:
            attempt_count = context.get(key, 0)
            context[key] = 0
            return self._make_alert(log, f"Brute force from {ip}: {attempt_count}+ failed attempts then success")
        return None

    def _make_alert(self, log, desc):
        return {
            "title": self.name, "description": desc, "severity": self.severity,
            "source_ip": log.get("source_ip"), "destination_ip": log.get("destination_ip"),
            "rule_name": self.name, "hostname": log.get("hostname"), "username": log.get("username"),
            "mitre_tactic": self.mitre_tactic, "mitre_technique": self.mitre_technique,
            "mitre_technique_name": self.mitre_technique_name,
            "recommended_action": self.recommended_action,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


class PowerShellObfuscationRule(CorrelationRule):
    """PowerShell with encoded/obfuscated commands → malware execution alert."""
    def __init__(self):
        super().__init__(
            "Suspicious PowerShell Execution",
            "PowerShell executed with encoded or obfuscated command",
            "critical", "T1059.001",
            "Isolate host, collect memory dump, review parent process tree, check for persistence.",
        )

    def evaluate(self, log, context):
        if log.get("event_type") != "powershell_execution":
            return None
        cmd = (log.get("command_line") or "").lower()
        keywords = ["-enc", "iex", "downloadstring", "bypass", "hidden", "invoke-expression", "frombase64"]
        if any(k in cmd for k in keywords):
            return {
                "title": self.name, "description": f"Obfuscated PowerShell on {log.get('hostname')}: {log.get('command_line', '')[:100]}",
                "severity": self.severity, "source_ip": log.get("source_ip"),
                "destination_ip": log.get("destination_ip"), "rule_name": self.name,
                "hostname": log.get("hostname"), "username": log.get("username"),
                "mitre_tactic": self.mitre_tactic, "mitre_technique": self.mitre_technique,
                "mitre_technique_name": self.mitre_technique_name,
                "recommended_action": self.recommended_action,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        return None


class C2CommunicationRule(CorrelationRule):
    """DNS to malicious domain + outbound traffic → C2 alert."""
    def __init__(self):
        super().__init__(
            "C2 Communication Detected",
            "Command and control beaconing activity identified",
            "critical", "T1071",
            "Block C2 domain/IP at firewall, isolate affected host, conduct forensic analysis.",
        )

    def evaluate(self, log, context):
        if log.get("event_type") == "c2_beacon":
            return {
                "title": self.name,
                "description": f"C2 beacon from {log.get('source_ip')} to {log.get('destination_ip')} via {log.get('dns_query', 'unknown')}",
                "severity": self.severity, "source_ip": log.get("source_ip"),
                "destination_ip": log.get("destination_ip"), "rule_name": self.name,
                "hostname": log.get("hostname"), "username": log.get("username"),
                "mitre_tactic": self.mitre_tactic, "mitre_technique": self.mitre_technique,
                "mitre_technique_name": self.mitre_technique_name,
                "recommended_action": self.recommended_action,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        if log.get("event_type") == "dns_query" and log.get("is_malicious", 0) >= 2:
            dns = log.get("dns_query", "")
            context[f"mal_dns_{log.get('source_ip')}"] = dns
            return {
                "title": "Malicious DNS Resolution",
                "description": f"DNS query to known-malicious domain: {dns} from {log.get('source_ip')}",
                "severity": "high", "source_ip": log.get("source_ip"),
                "destination_ip": log.get("destination_ip"), "rule_name": self.name,
                "mitre_tactic": self.mitre_tactic, "mitre_technique": "T1071.004",
                "mitre_technique_name": "DNS",
                "recommended_action": "Investigate DNS query, check for follow-up connections.",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        return None


class LateralMovementRule(CorrelationRule):
    """Internal-to-internal RDP/SMB/SSH → lateral movement alert."""
    def __init__(self):
        super().__init__(
            "Lateral Movement Detected",
            "Suspicious internal host-to-host remote access",
            "high", "T1021",
            "Verify authorized access, check source credentials, trace movement chain.",
        )

    def evaluate(self, log, context):
        if log.get("event_type") == "lateral_movement":
            return {
                "title": self.name,
                "description": f"Lateral movement: {log.get('source_ip')} -> {log.get('destination_ip')} via {log.get('protocol')}",
                "severity": self.severity, "source_ip": log.get("source_ip"),
                "destination_ip": log.get("destination_ip"), "rule_name": self.name,
                "mitre_tactic": self.mitre_tactic, "mitre_technique": self.mitre_technique,
                "mitre_technique_name": self.mitre_technique_name,
                "recommended_action": self.recommended_action,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        return None


class PortScanRule(CorrelationRule):
    """Network service discovery events -> reconnaissance alert."""
    def __init__(self):
        super().__init__(
            "Port Scan Detected",
            "Potential reconnaissance activity against internal assets",
            "medium", "T1046",
            "Identify scanning source, validate whether authorized, check for follow-on exploitation.",
        )

    def evaluate(self, log, context):
        if log.get("event_type") != "port_scan":
            return None
        return {
            "title": self.name,
            "description": f"Port scan from {log.get('source_ip')} targeting {log.get('destination_ip')}",
            "severity": self.severity,
            "source_ip": log.get("source_ip"),
            "destination_ip": log.get("destination_ip"),
            "rule_name": self.name,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "mitre_technique_name": self.mitre_technique_name,
            "recommended_action": self.recommended_action,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


class DnsExfiltrationRule(CorrelationRule):
    """Suspicious DNS tunneling/exfiltration events -> exfiltration alert."""
    def __init__(self):
        super().__init__(
            "DNS Exfiltration Suspected",
            "DNS tunneling or exfiltration-like traffic identified",
            "critical", "T1048",
            "Block DNS channel, preserve packet evidence, identify data scope, and contain the source host.",
        )

    def evaluate(self, log, context):
        dns_query = (log.get("dns_query") or "").lower()
        raw_log = (log.get("raw_log") or "").lower()
        if log.get("event_type") == "dns_query" and ("exfil" in dns_query or "exfiltration" in raw_log or "tunneling" in raw_log):
            return {
                "title": self.name,
                "description": f"Suspicious DNS query from {log.get('source_ip')}: {log.get('dns_query')}",
                "severity": self.severity,
                "source_ip": log.get("source_ip"),
                "destination_ip": log.get("destination_ip"),
                "rule_name": self.name,
                "mitre_tactic": self.mitre_tactic,
                "mitre_technique": self.mitre_technique,
                "mitre_technique_name": self.mitre_technique_name,
                "recommended_action": self.recommended_action,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        return None


class PhishingRule(CorrelationRule):
    """Phishing email detection → alert."""
    def __init__(self):
        super().__init__(
            "Phishing Email Detected",
            "Suspected phishing email with spoofed sender or malicious content",
            "high", "T1566",
            "Quarantine email, scan attachments, notify affected users, check for credential compromise.",
        )

    def evaluate(self, log, context):
        if log.get("event_type") in ("phishing_attempt", "malicious_attachment", "email_spoofing"):
            sev = "critical" if log.get("event_type") == "malicious_attachment" else "high"
            return {
                "title": self.name, "description": log.get("raw_log", "Phishing detected"),
                "severity": sev, "source_ip": log.get("source_ip"),
                "rule_name": self.name, "hostname": log.get("hostname"),
                "username": log.get("username"),
                "mitre_tactic": self.mitre_tactic, "mitre_technique": self.mitre_technique,
                "mitre_technique_name": self.mitre_technique_name,
                "recommended_action": self.recommended_action,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        return None


class PrivilegeEscalationRule(CorrelationRule):
    """Privilege escalation events → alert."""
    def __init__(self):
        super().__init__(
            "Privilege Escalation Attempt",
            "Suspicious privilege elevation detected",
            "high", "T1548",
            "Review escalation chain, audit sudo/UAC config, check for persistence.",
        )

    def evaluate(self, log, context):
        if log.get("event_type") in ("privilege_escalation", "sudo_execution"):
            return {
                "title": self.name,
                "description": f"Privilege escalation by {log.get('username')} on {log.get('hostname')}: {log.get('command_line', '')}",
                "severity": self.severity, "source_ip": log.get("source_ip"),
                "rule_name": self.name, "hostname": log.get("hostname"),
                "username": log.get("username"),
                "mitre_tactic": self.mitre_tactic, "mitre_technique": self.mitre_technique,
                "mitre_technique_name": self.mitre_technique_name,
                "recommended_action": self.recommended_action,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        return None

class AptKillchainRule(CorrelationRule):
    """Multi-stage APT Killchain rule that maintains state over time."""
    def __init__(self):
        super().__init__(
            "Advanced Persistent Threat (APT) Killchain Detected",
            "Multi-stage attack sequence: External exploitation → Lateral Movement → Data Exfiltration.",
            "critical", "T1190", # Primary initial access technique
            "Declare P1 Incident immediately. Sever external connections to compromised DMZ hosts. Isolate Domain Controller.",
        )

    def evaluate(self, log, context):
        ip = log.get("source_ip", "")
        dest_ip = log.get("destination_ip", "")
        event_type = log.get("event_type")
        
        # We track the killchain state globally
        state_key = "apt_killchain_state"
        
        # Step 1: Initial Access (Exploit Log4Shell)
        if event_type == "exploit_public_app" and "CVE-2021-44228" in log.get("raw_log", ""):
            context[state_key] = {"stage": 1, "web_server": dest_ip, "timestamp": datetime.now(timezone.utc).isoformat()}
            return None
            
        # Step 2: Lateral Movement from the compromised web server to the DC
        if event_type == "lateral_movement" and context.get(state_key, {}).get("stage") == 1:
            if ip == context[state_key].get("web_server"):
                context[state_key]["stage"] = 2
                context[state_key]["dc_ip"] = dest_ip
                return None
                
        # Step 3: Exfiltration using multi-hop routing
        if event_type == "multi_hop_exfil" and context.get(state_key, {}).get("stage") == 2:
            if ip == context[state_key].get("web_server"):
                # Trigger the massive multi-stage alert
                alert = {
                    "title": self.name,
                    "description": f"Multi-stage Killchain: {ip} was exploited (Log4Shell), pivoted to DC ({context[state_key].get('dc_ip')}) via ZeroLogon, and exfiltrated data via Multi-Hop Tunnel.",
                    "severity": self.severity,
                    "source_ip": ip,
                    "destination_ip": dest_ip,
                    "rule_name": self.name,
                    "mitre_tactic": "Multiple",
                    "mitre_technique": "T1090.003",
                    "mitre_technique_name": "Multi-hop Proxy",
                    "recommended_action": self.recommended_action,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                
                # Reset state after triggering
                context[state_key] = {"stage": 0}
                return alert

        return None


# Engine that runs all rules
class CorrelationEngine:
    """Runs all correlation rules against incoming log events."""
    def __init__(self):
        # Single-event detections moved to Sigma YAML rules (backend/detection/
        # rules/) and the scheduled brute-force threshold rule. Only genuinely
        # stateful multi-event correlation remains here to avoid duplicate alerts.
        self.rules = [
            AptKillchainRule(),
        ]
        self.context = defaultdict(int)

    def process_log(self, log: dict) -> list[dict]:
        """Process a log event through all rules. Returns list of generated alerts."""
        alerts = []
        for rule in self.rules:
            try:
                alert = rule.evaluate(log, self.context)
                if alert:
                    alerts.append(alert)
            except Exception:
                pass
        return alerts
