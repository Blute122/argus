"""Network telemetry generator - DNS, HTTP, C2 beaconing, port scans, lateral movement."""
import random
from datetime import datetime, timezone

INTERNAL_HOSTS = ["10.0.1.10", "10.0.1.20", "10.0.2.30", "10.0.3.40", "10.0.1.50", "10.0.2.60"]
EXT_IPS = ["203.0.113.5", "198.51.100.23", "45.33.32.156", "185.220.101.1", "91.219.236.222",
           "104.244.72.115", "5.255.99.2", "176.10.104.240"]
C2_DOMAINS = ["evil-update.com", "cdn-check.xyz", "api.malware-c2.net", "dl.trojan-payload.com",
              "beacon.darknet-c2.org", "update.stealthy-rat.io"]
MALICIOUS_DOMAINS = C2_DOMAINS + ["phishing-login.com", "fake-bank.xyz", "crypto-steal.net"]
NORMAL_DOMAINS = ["google.com", "github.com", "microsoft.com", "aws.amazon.com", "cdn.cloudflare.com",
                  "api.slack.com", "outlook.office365.com", "zoom.us"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1)", "curl/7.68.0",
    "python-requests/2.28.0", "PowerShell/7.2",
]


def _rip():
    return f"10.{random.randint(0,5)}.{random.randint(0,255)}.{random.randint(1,254)}"


def generate_dns_traffic():
    is_mal = random.random() > 0.7
    domain = random.choice(MALICIOUS_DOMAINS) if is_mal else random.choice(NORMAL_DOMAINS)
    src = random.choice(INTERNAL_HOSTS)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(), "source": "network",
        "source_ip": src, "destination_ip": "10.0.0.2", "destination_port": 53,
        "protocol": "DNS", "event_type": "dns_query", "severity": "high" if is_mal else "info",
        "dns_query": domain,
        "raw_log": f"DNS query from {src} -> {domain} (A record) {'[SUSPICIOUS]' if is_mal else ''}",
        "mitre_tactic": "Command and Control" if is_mal else "", "mitre_technique": "T1071.004" if is_mal else "",
        "mitre_technique_name": "DNS" if is_mal else "", "is_malicious": 2 if is_mal else 0,
    }


def generate_http_request():
    src = random.choice(INTERNAL_HOSTS)
    is_mal = random.random() > 0.75
    domain = random.choice(MALICIOUS_DOMAINS) if is_mal else random.choice(NORMAL_DOMAINS)
    dst = random.choice(EXT_IPS) if is_mal else f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    paths = ["/login", "/api/data", "/upload", "/download/payload.exe", "/beacon", "/admin"]
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(), "source": "network",
        "source_ip": src, "destination_ip": dst, "destination_port": random.choice([80, 443, 8080, 8443]),
        "protocol": "HTTP", "event_type": "http_request", "severity": "high" if is_mal else "info",
        "http_method": random.choice(["GET", "POST"]), "http_status": random.choice([200, 301, 403, 404, 500]),
        "url": f"http{'s' if random.random()>0.5 else ''}://{domain}{random.choice(paths)}",
        "user_agent": random.choice(USER_AGENTS),
        "bytes_sent": random.randint(100, 50000), "bytes_received": random.randint(200, 500000),
        "raw_log": f"HTTP {random.choice(['GET','POST'])} {domain}{random.choice(paths)} from {src} -> {dst}",
        "mitre_tactic": "Command and Control" if is_mal else "",
        "mitre_technique": "T1071.001" if is_mal else "", "is_malicious": 2 if is_mal else 0,
    }


def generate_c2_beacon():
    src = random.choice(INTERNAL_HOSTS)
    domain = random.choice(C2_DOMAINS)
    dst = random.choice(EXT_IPS)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(), "source": "network",
        "source_ip": src, "destination_ip": dst, "destination_port": random.choice([443, 8443, 4444, 8080]),
        "protocol": "HTTPS", "event_type": "c2_beacon", "severity": "critical",
        "url": f"https://{domain}/beacon", "dns_query": domain,
        "bytes_sent": random.randint(50, 500), "bytes_received": random.randint(100, 2000),
        "raw_log": f"C2 BEACON detected: {src} -> {dst}:{443} via {domain} (interval: {random.randint(30,300)}s)",
        "mitre_tactic": "Command and Control", "mitre_technique": "T1071.001",
        "mitre_technique_name": "Web Protocols", "is_malicious": 2,
    }


def generate_port_scan():
    src = random.choice(EXT_IPS + INTERNAL_HOSTS)
    dst = random.choice(INTERNAL_HOSTS)
    ports = sorted(random.sample(range(1, 65535), random.randint(5, 20)))
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(), "source": "network",
        "source_ip": src, "destination_ip": dst, "protocol": "TCP",
        "event_type": "port_scan", "severity": "medium",
        "raw_log": f"Port scan detected: {src} -> {dst} ports: {','.join(map(str, ports[:10]))}...",
        "mitre_tactic": "Discovery", "mitre_technique": "T1046",
        "mitre_technique_name": "Network Service Discovery", "is_malicious": 1,
    }


def generate_lateral_movement():
    src = random.choice(INTERNAL_HOSTS)
    dst = random.choice([h for h in INTERNAL_HOSTS if h != src])
    protocols = [("SMB", 445), ("RDP", 3389), ("WinRM", 5985), ("SSH", 22)]
    proto, port = random.choice(protocols)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(), "source": "network",
        "source_ip": src, "destination_ip": dst, "destination_port": port,
        "protocol": proto, "event_type": "lateral_movement", "severity": "high",
        "raw_log": f"Lateral movement: {src} -> {dst}:{port} ({proto}) using admin credentials",
        "mitre_tactic": "Lateral Movement", "mitre_technique": "T1021",
        "mitre_technique_name": "Remote Services", "is_malicious": 2,
    }


NETWORK_GENERATORS = [
    (generate_dns_traffic, 25), (generate_http_request, 25), (generate_c2_beacon, 10),
    (generate_port_scan, 20), (generate_lateral_movement, 20),
]


def generate_network_log():
    gens, weights = zip(*NETWORK_GENERATORS)
    return random.choices(gens, weights=weights, k=1)[0]()
