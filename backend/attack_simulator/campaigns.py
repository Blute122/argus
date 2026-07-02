"""Safe staged attack campaigns for purple-team SOC training."""

from datetime import datetime, timezone


CAMPAIGNS = {
    "enterprise_intrusion": {
        "name": "Enterprise Intrusion Kill Chain",
        "description": "A staged intrusion from reconnaissance through C2, lateral movement, exfiltration, and impact.",
        "difficulty": "intermediate",
        "target_assets": ["WEB-SRV01", "DC01", "FILE-SRV01", "SQL-SRV01"],
        "stages": [
            {
                "name": "Reconnaissance",
                "tactic": "Reconnaissance",
                "technique": "T1595",
                "technique_name": "Active Scanning",
                "objective": "Identify externally exposed services.",
            },
            {
                "name": "Initial Access",
                "tactic": "Initial Access",
                "technique": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "objective": "Simulate exploitation of a vulnerable web service.",
            },
            {
                "name": "Execution",
                "tactic": "Execution",
                "technique": "T1059.001",
                "technique_name": "PowerShell",
                "objective": "Simulate scripted execution on a compromised host.",
            },
            {
                "name": "Persistence",
                "tactic": "Persistence",
                "technique": "T1543.003",
                "technique_name": "Windows Service",
                "objective": "Simulate persistence through service creation.",
            },
            {
                "name": "Lateral Movement",
                "tactic": "Lateral Movement",
                "technique": "T1021",
                "technique_name": "Remote Services",
                "objective": "Move from web tier to internal systems.",
            },
            {
                "name": "Command and Control",
                "tactic": "Command and Control",
                "technique": "T1071.001",
                "technique_name": "Web Protocols",
                "objective": "Simulate periodic beaconing to external infrastructure.",
            },
            {
                "name": "Exfiltration",
                "tactic": "Exfiltration",
                "technique": "T1048",
                "technique_name": "Exfiltration Over Alternative Protocol",
                "objective": "Simulate suspicious data movement out of the network.",
            },
            {
                "name": "Impact",
                "tactic": "Impact",
                "technique": "T1486",
                "technique_name": "Data Encrypted for Impact",
                "objective": "Simulate ransomware-like impact telemetry.",
            },
        ],
    },
    "phishing_to_domain": {
        "name": "Phishing to Domain Compromise",
        "description": "A credential-focused campaign from phishing through account abuse and domain controller access.",
        "difficulty": "advanced",
        "target_assets": ["EXCHANGE01", "WS-PC001", "DC01", "jump-box"],
        "stages": [
            {
                "name": "Spearphishing",
                "tactic": "Initial Access",
                "technique": "T1566.001",
                "technique_name": "Spearphishing Attachment",
                "objective": "Deliver simulated malicious attachment telemetry.",
            },
            {
                "name": "Credential Access",
                "tactic": "Credential Access",
                "technique": "T1110",
                "technique_name": "Brute Force",
                "objective": "Simulate failed attempts followed by account success.",
            },
            {
                "name": "Privilege Escalation",
                "tactic": "Privilege Escalation",
                "technique": "T1548",
                "technique_name": "Abuse Elevation Control Mechanism",
                "objective": "Simulate suspicious elevation telemetry.",
            },
            {
                "name": "Lateral Movement",
                "tactic": "Lateral Movement",
                "technique": "T1021.001",
                "technique_name": "Remote Desktop Protocol",
                "objective": "Simulate RDP movement toward sensitive systems.",
            },
            {
                "name": "Collection",
                "tactic": "Credential Access",
                "technique": "T1003.003",
                "technique_name": "NTDS",
                "objective": "Simulate directory credential collection indicators.",
            },
        ],
    },
}


def list_campaigns():
    return [
        {
            "id": campaign_id,
            "name": campaign["name"],
            "description": campaign["description"],
            "difficulty": campaign["difficulty"],
            "stage_count": len(campaign["stages"]),
            "target_assets": campaign["target_assets"],
        }
        for campaign_id, campaign in CAMPAIGNS.items()
    ]


def get_campaign(campaign_id: str):
    campaign = CAMPAIGNS.get(campaign_id)
    if not campaign:
        return None
    return {"id": campaign_id, **campaign}


def generate_campaign_stage_logs(campaign_id: str, stage_index: int, db=None):
    campaign = CAMPAIGNS.get(campaign_id)
    if not campaign or stage_index < 0 or stage_index >= len(campaign["stages"]):
        return []

    stage = campaign["stages"][stage_index]
    assets = _asset_context(db)
    src_external = "45.33.32.156"
    c2_ip = "185.10.10.20"
    web_ip = assets.get("WEB-SRV01", {}).get("ip_address", "10.0.3.40")
    dc_ip = assets.get("DC01", {}).get("ip_address", "10.0.1.10")
    file_ip = assets.get("FILE-SRV01", {}).get("ip_address", "10.0.1.50")
    ws_ip = assets.get("WS-PC001", {}).get("ip_address", "10.0.2.60")

    def base(**overrides):
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "attack_simulation",
            "source_ip": src_external,
            "destination_ip": web_ip,
            "event_type": f"campaign_{stage['name'].lower().replace(' ', '_')}",
            "severity": "high",
            "hostname": "WEB-SRV01",
            "username": "attacker",
            "raw_log": f"[CAMPAIGN] {campaign['name']} | {stage['name']} | {stage['objective']}",
            "mitre_tactic": stage["tactic"],
            "mitre_technique": stage["technique"],
            "mitre_technique_name": stage["technique_name"],
            "is_malicious": 2,
        }
        payload.update(overrides)
        return payload

    name = stage["name"]
    if name == "Reconnaissance":
        return [
            base(source="network", event_type="port_scan", destination_ip=web_ip, protocol="TCP",
                 raw_log=f"[CAMPAIGN] External scan from {src_external} against {web_ip} ports 80,443,8080",
                 severity="medium"),
            base(source="network", event_type="dns_query", source_ip=src_external, destination_ip="10.0.0.2",
                 dns_query="portal.company.example", raw_log="[CAMPAIGN] Recon DNS resolution for public portal", severity="low"),
        ]
    if name == "Initial Access":
        return [
            base(source="linux", event_type="exploit_public_app", destination_ip=web_ip, hostname="WEB-SRV01",
                 raw_log=f"[CAMPAIGN] Simulated exploit payload delivered to WEB-SRV01 from {src_external}"),
            base(source="network", event_type="http_request", source_ip=src_external, destination_ip=web_ip,
                 destination_port=443, protocol="HTTPS", url="https://portal.company.example/login",
                 raw_log="[CAMPAIGN] Suspicious HTTP POST with exploit-like payload"),
        ]
    if name == "Execution":
        return [
            base(source="windows", event_type="powershell_execution", source_ip=ws_ip, hostname="WS-PC001",
                 process_name="powershell.exe", event_id="4104",
                 command_line="powershell -ExecutionPolicy Bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
                 raw_log="[CAMPAIGN] Encoded PowerShell execution observed on WS-PC001"),
        ]
    if name == "Persistence":
        return [
            base(source="windows", event_type="service_creation", source_ip=ws_ip, hostname="WS-PC001",
                 event_id="7045", process_name="services.exe",
                 raw_log="[CAMPAIGN] New suspicious Windows service created: SystemHealthMonitor -> C:\\temp\\beacon.exe"),
        ]
    if name == "Privilege Escalation":
        return [
            base(source="windows", event_type="privilege_escalation", source_ip=ws_ip, hostname="WS-PC001",
                 event_id="4672", username="svc_backup", process_name="lsass.exe",
                 raw_log="[CAMPAIGN] Special privileges assigned to svc_backup outside maintenance window"),
        ]
    if name == "Spearphishing":
        return [
            base(source="email", event_type="malicious_attachment", source_ip=src_external, destination_ip=None,
                 hostname="EXCHANGE01", username="finance.user@company.com", file_path="q2_invoice.xlsm",
                 raw_log="[CAMPAIGN] Spearphishing attachment delivered to finance.user@company.com"),
        ]
    if name == "Credential Access":
        logs = []
        for attempt in range(5):
            logs.append(base(source="windows", event_type="failed_login", source_ip=src_external, destination_ip=dc_ip,
                             hostname="DC01", username="svc_backup", event_id="4625", severity="medium",
                             raw_log=f"[CAMPAIGN] Failed logon attempt {attempt + 1} for svc_backup from {src_external}"))
        logs.append(base(source="windows", event_type="successful_login", source_ip=src_external, destination_ip=dc_ip,
                         hostname="DC01", username="svc_backup", event_id="4624", severity="info",
                         raw_log=f"[CAMPAIGN] Successful logon for svc_backup from {src_external} after failures"))
        return logs
    if name == "Lateral Movement":
        return [
            base(source="network", event_type="lateral_movement", source_ip=web_ip, destination_ip=dc_ip,
                 destination_port=3389, protocol="RDP", hostname="DC01",
                 raw_log=f"[CAMPAIGN] Lateral RDP movement from WEB-SRV01 ({web_ip}) to DC01 ({dc_ip})"),
            base(source="network", event_type="lateral_movement", source_ip=dc_ip, destination_ip=file_ip,
                 destination_port=445, protocol="SMB", hostname="FILE-SRV01",
                 raw_log=f"[CAMPAIGN] SMB admin share access from DC01 ({dc_ip}) to FILE-SRV01 ({file_ip})"),
        ]
    if name == "Command and Control":
        return [
            base(source="network", event_type="c2_beacon", source_ip=web_ip, destination_ip=c2_ip,
                 destination_port=443, protocol="HTTPS", dns_query="beacon.darknet-c2.org",
                 url="https://beacon.darknet-c2.org/checkin",
                 raw_log=f"[CAMPAIGN] C2 beacon from {web_ip} to {c2_ip} via beacon.darknet-c2.org"),
        ]
    if name == "Exfiltration":
        return [
            base(source="network", event_type="dns_query", source_ip=file_ip, destination_ip="10.0.0.2",
                 destination_port=53, protocol="DNS", dns_query="784221.exfil.darknet-c2.org",
                 raw_log=f"[CAMPAIGN] DNS tunneling/exfiltration query from FILE-SRV01 ({file_ip})"),
        ]
    if name == "Collection":
        return [
            base(source="windows", event_type="credential_dumping", source_ip=dc_ip, destination_ip=c2_ip,
                 hostname="DC01", process_name="ntdsutil.exe", raw_log="[CAMPAIGN] NTDS.dit access pattern observed on DC01",
                 mitre_tactic="Credential Access", mitre_technique="T1003.003", mitre_technique_name="NTDS"),
        ]
    if name == "Impact":
        return [
            base(source="windows", event_type="powershell_execution", source_ip=ws_ip, hostname="WS-PC001",
                 event_id="4104", process_name="powershell.exe",
                 command_line="powershell -ExecutionPolicy Bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
                 raw_log="[CAMPAIGN] Simulated ransomware impact script execution on workstation",
                 mitre_tactic="Impact", mitre_technique="T1486", mitre_technique_name="Data Encrypted for Impact"),
        ]
    return [base()]


def _asset_context(db):
    if not db:
        return {}
    try:
        from backend.models.asset import Asset
        return {
            asset.hostname: {"ip_address": asset.ip_address, "criticality": asset.criticality}
            for asset in db.query(Asset).all()
        }
    except Exception:
        return {}
