"""
Safe Attack Simulation Scenarios.
Educational-only sandboxed simulations that generate realistic log telemetry.
NO real malware or offensive capabilities - everything is simulated data.
"""
import random
from datetime import datetime, timezone

SCENARIOS = {
    "brute_force_attack": {
        "name": "SSH Brute Force Attack",
        "description": "Simulates an SSH brute force attack from an external IP against a Linux server",
        "attack_type": "brute_force",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110",
        "mitre_technique_name": "Brute Force",
        "steps": [
            {"action": "recon", "detail": "Port scan target for SSH (22)"},
            {"action": "attack", "detail": "Attempt 50+ password combinations"},
            {"action": "success", "detail": "Successful login with guessed credentials"},
            {"action": "persist", "detail": "Add SSH key to authorized_keys"},
        ],
    },
    "phishing_campaign": {
        "name": "Spearphishing Campaign",
        "description": "Simulates a targeted phishing email campaign with malicious attachments",
        "attack_type": "phishing",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1566",
        "mitre_technique_name": "Phishing",
        "steps": [
            {"action": "recon", "detail": "Gather target email addresses from OSINT"},
            {"action": "craft", "detail": "Create convincing phishing email with macro-enabled doc"},
            {"action": "deliver", "detail": "Send phishing emails to 10 targets"},
            {"action": "exploit", "detail": "Victim opens attachment, macro executes"},
        ],
    },
    "lateral_movement": {
        "name": "Lateral Movement via RDP",
        "description": "Simulates attacker moving laterally through the network using compromised credentials",
        "attack_type": "lateral_movement",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "T1021",
        "mitre_technique_name": "Remote Services",
        "steps": [
            {"action": "cred_dump", "detail": "Dump credentials from LSASS memory"},
            {"action": "enumerate", "detail": "Discover accessible hosts via SMB"},
            {"action": "move", "detail": "RDP to file server with admin credentials"},
            {"action": "persist", "detail": "Create new service for persistence"},
        ],
    },
    "data_exfiltration": {
        "name": "Data Exfiltration via DNS",
        "description": "Simulates data exfiltration using DNS tunneling",
        "attack_type": "exfiltration",
        "mitre_tactic": "Exfiltration",
        "mitre_technique": "T1048",
        "mitre_technique_name": "Exfiltration Over Alternative Protocol",
        "steps": [
            {"action": "discover", "detail": "Locate sensitive files on file shares"},
            {"action": "stage", "detail": "Compress and encode data for exfil"},
            {"action": "exfil", "detail": "Exfiltrate data via DNS TXT queries"},
            {"action": "cleanup", "detail": "Clear event logs and artifacts"},
        ],
    },
    "ransomware_simulation": {
        "name": "Ransomware Attack Chain",
        "description": "Simulates a full ransomware kill chain from initial access to impact",
        "attack_type": "ransomware",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1486",
        "mitre_technique_name": "Data Encrypted for Impact",
        "steps": [
            {"action": "initial_access", "detail": "Phishing email delivers dropper"},
            {"action": "execution", "detail": "PowerShell downloads ransomware payload"},
            {"action": "escalation", "detail": "Escalate to SYSTEM via service exploit"},
            {"action": "lateral", "detail": "Spread to 5 workstations via SMB"},
            {"action": "encrypt", "detail": "Simulate file encryption on all hosts"},
        ],
    },
    "reverse_shell": {
        "name": "Reverse Shell Simulation",
        "description": "Simulates establishing a reverse shell connection back to attacker C2",
        "attack_type": "command_and_control",
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059",
        "mitre_technique_name": "Command and Scripting Interpreter",
        "steps": [
            {"action": "exploit", "detail": "Exploit web application vulnerability"},
            {"action": "shell", "detail": "Establish reverse shell to C2 server"},
            {"action": "enumerate", "detail": "Run system enumeration commands"},
            {"action": "persist", "detail": "Drop persistence mechanism"},
        ],
    },
}


def get_scenarios():
    """Return all available attack scenarios."""
    return [
        {"id": k, "name": v["name"], "description": v["description"],
         "attack_type": v["attack_type"], "mitre_technique": v["mitre_technique"],
         "mitre_technique_name": v["mitre_technique_name"]}
        for k, v in SCENARIOS.items()
    ]


def get_scenario_detail(scenario_id: str):
    """Return detailed info for a specific scenario."""
    return SCENARIOS.get(scenario_id)


def generate_simulation_logs(scenario_id: str) -> list[dict]:
    """Generate a burst of logs that simulate the attack scenario."""
    scenario = SCENARIOS.get(scenario_id)
    if not scenario:
        return []

    logs = []
    src_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    dst_ip = f"10.0.{random.randint(1,5)}.{random.randint(1,254)}"

    def base_log(step: dict) -> dict:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "attack_simulation",
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "event_type": f"sim_{step['action']}",
            "severity": "critical",
            "hostname": f"target-{random.choice(['srv01','ws01','dc01'])}",
            "username": "attacker",
            "raw_log": f"[SIMULATION] {scenario['name']} - Step: {step['action']} - {step['detail']}",
            "mitre_tactic": scenario["mitre_tactic"],
            "mitre_technique": scenario["mitre_technique"],
            "mitre_technique_name": scenario["mitre_technique_name"],
            "is_malicious": 2,
        }

    for step in scenario["steps"]:
        log = base_log(step)

        if scenario_id == "brute_force_attack":
            log.update({"source": "linux", "destination_port": 22, "process_name": "sshd"})
            if step["action"] == "attack":
                for attempt in range(5):
                    attempt_log = base_log({"action": "attack", "detail": f"Failed SSH password attempt {attempt + 1}"})
                    attempt_log.update({
                        "source": "linux", "event_type": "ssh_failed_login", "destination_port": 22,
                        "process_name": "sshd", "username": "root",
                        "raw_log": f"[SIMULATION] Failed SSH password for root from {src_ip} attempt {attempt + 1}",
                    })
                    logs.append(attempt_log)
                continue
            if step["action"] == "success":
                log.update({
                    "source": "windows", "event_type": "successful_login", "event_id": "4624",
                    "username": "root", "raw_log": f"[SIMULATION] Successful login after brute force from {src_ip}",
                })

        elif scenario_id == "phishing_campaign":
            log.update({
                "source": "email", "event_type": "malicious_attachment", "hostname": "EXCHANGE01",
                "username": "finance.user@company.com", "file_path": "invoice_q4.xlsm",
                "raw_log": f"[SIMULATION] Malicious attachment delivered during phishing campaign: {step['detail']}",
            })

        elif scenario_id == "lateral_movement":
            log.update({
                "source": "network", "event_type": "lateral_movement", "protocol": "RDP",
                "destination_port": 3389,
                "raw_log": f"[SIMULATION] Lateral movement via RDP: {src_ip} -> {dst_ip} - {step['detail']}",
            })

        elif scenario_id == "data_exfiltration":
            log.update({
                "source": "network", "event_type": "dns_query", "protocol": "DNS",
                "destination_port": 53, "dns_query": f"{random.randint(10000,99999)}.exfil.darknet-c2.org",
                "mitre_technique": "T1071.004", "mitre_technique_name": "DNS",
                "raw_log": f"[SIMULATION] DNS tunneling/exfiltration query from {dst_ip}: {step['detail']}",
            })

        elif scenario_id == "ransomware_simulation":
            log.update({
                "source": "windows", "event_type": "powershell_execution", "event_id": "4104",
                "process_name": "powershell.exe",
                "command_line": "powershell -ExecutionPolicy Bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
                "mitre_technique": "T1059.001", "mitre_technique_name": "PowerShell",
                "raw_log": f"[SIMULATION] Ransomware chain PowerShell stage: {step['detail']}",
            })

        elif scenario_id == "reverse_shell":
            log.update({
                "source": "network", "event_type": "c2_beacon", "protocol": "HTTPS",
                "destination_port": 4444, "dns_query": "beacon.darknet-c2.org",
                "mitre_tactic": "Command and Control", "mitre_technique": "T1071.001",
                "mitre_technique_name": "Web Protocols",
                "raw_log": f"[SIMULATION] Reverse shell beacon: {dst_ip} -> {src_ip}:4444 - {step['detail']}",
            })

        logs.append(log)
    return logs
