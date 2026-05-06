"""Email telemetry generator - phishing, malicious attachments, spoofing."""
import random
from datetime import datetime, timezone

SENDERS_LEGIT = ["hr@company.com", "it-support@company.com", "ceo@company.com", "finance@company.com"]
SENDERS_PHISH = ["hr@c0mpany.com", "support@micr0soft.com", "security@paypa1.com",
                 "admin@g00gle-verify.com", "noreply@amaz0n-secure.net", "billing@app1e-id.com"]
RECIPIENTS = ["john.doe@company.com", "jane.smith@company.com", "bob.wilson@company.com",
              "karen.lee@company.com", "mike.brown@company.com"]
SUBJECTS_LEGIT = ["Q4 Report", "Meeting Tomorrow", "Project Update", "Holiday Schedule"]
SUBJECTS_PHISH = ["Urgent: Account Suspended", "Invoice #38291 Attached", "Password Expires Today",
                  "You have a package waiting", "Action Required: Verify Identity", "Shared Document"]
ATTACHMENTS_MAL = ["invoice.pdf.exe", "document.docm", "report.xlsm", "update.scr", "resume.js"]
ATTACHMENTS_SAFE = ["report.pdf", "meeting_notes.docx", "budget.xlsx", "presentation.pptx"]


def generate_phishing():
    sender = random.choice(SENDERS_PHISH)
    rcpt = random.choice(RECIPIENTS)
    subj = random.choice(SUBJECTS_PHISH)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(), "source": "email",
        "source_ip": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "event_type": "phishing_attempt", "severity": "high",
        "username": rcpt, "hostname": "EXCHANGE01",
        "raw_log": f"Phishing email detected | From: {sender} | To: {rcpt} | Subject: {subj} | SPF: FAIL | DKIM: FAIL",
        "mitre_tactic": "Initial Access", "mitre_technique": "T1566.002",
        "mitre_technique_name": "Spearphishing Link", "is_malicious": 2,
    }


def generate_malicious_attachment():
    sender = random.choice(SENDERS_PHISH)
    rcpt = random.choice(RECIPIENTS)
    attach = random.choice(ATTACHMENTS_MAL)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(), "source": "email",
        "source_ip": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "event_type": "malicious_attachment", "severity": "critical",
        "username": rcpt, "hostname": "EXCHANGE01", "file_path": attach,
        "raw_log": f"Malicious attachment | From: {sender} | To: {rcpt} | Attachment: {attach} | Verdict: MALICIOUS",
        "mitre_tactic": "Initial Access", "mitre_technique": "T1566.001",
        "mitre_technique_name": "Spearphishing Attachment", "is_malicious": 2,
    }


def generate_email_spoof():
    real = random.choice(SENDERS_LEGIT)
    spoofed_from = real.replace("company.com", "c0mpany.com")
    rcpt = random.choice(RECIPIENTS)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(), "source": "email",
        "source_ip": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "event_type": "email_spoofing", "severity": "high",
        "username": rcpt, "hostname": "EXCHANGE01",
        "raw_log": f"Email spoofing detected | From: {spoofed_from} (spoofing {real}) | To: {rcpt} | DMARC: FAIL",
        "mitre_tactic": "Initial Access", "mitre_technique": "T1566",
        "mitre_technique_name": "Phishing", "is_malicious": 2,
    }


EMAIL_GENERATORS = [(generate_phishing, 40), (generate_malicious_attachment, 35), (generate_email_spoof, 25)]


def generate_email_log():
    gens, weights = zip(*EMAIL_GENERATORS)
    return random.choices(gens, weights=weights, k=1)[0]()
