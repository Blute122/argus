"""Cloud telemetry generator - AWS IAM, Azure sign-in, GCP API events."""
import random
from datetime import datetime, timezone

AWS_ACTIONS = ["ConsoleLogin", "CreateUser", "AttachUserPolicy", "DeleteTrail",
               "StopLogging", "CreateAccessKey", "AssumeRole", "PutBucketPolicy"]
AZURE_ACTIONS = ["Sign-in activity", "Conditional Access failure", "MFA denied",
                 "Risky sign-in", "Password change", "Role assignment"]
GCP_ACTIONS = ["compute.instances.create", "iam.serviceAccountKeys.create",
               "storage.buckets.delete", "logging.sinks.delete", "compute.firewalls.delete"]

CLOUD_USERS = ["admin@corp.onmicrosoft.com", "devops-svc", "lambda-role", "root",
               "ci-cd-pipeline", "analyst@corp.com", "unknown-actor"]
REGIONS = ["us-east-1", "eu-west-1", "ap-southeast-1", "westus2", "eastus", "us-central1"]


def generate_aws_event():
    action = random.choice(AWS_ACTIONS)
    user = random.choice(CLOUD_USERS[:3])
    is_sus = action in ["DeleteTrail", "StopLogging", "CreateAccessKey"]
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(), "source": "cloud",
        "source_ip": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "event_type": f"aws_{action.lower()}", "severity": "critical" if is_sus else "medium",
        "username": user, "hostname": f"aws-{random.choice(REGIONS)}",
        "raw_log": f"CloudTrail | {action} by {user} from {random.choice(REGIONS)} | {'SUSPICIOUS' if is_sus else 'OK'}",
        "mitre_tactic": "Defense Evasion" if is_sus else "Discovery",
        "mitre_technique": "T1078.004" if is_sus else "T1078",
        "mitre_technique_name": "Cloud Accounts", "is_malicious": 2 if is_sus else 0,
    }


def generate_azure_event():
    action = random.choice(AZURE_ACTIONS)
    user = random.choice(CLOUD_USERS)
    is_sus = "Risky" in action or "denied" in action.lower()
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(), "source": "cloud",
        "source_ip": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "event_type": f"azure_{action.lower().replace(' ', '_')}", "severity": "high" if is_sus else "info",
        "username": user, "hostname": f"azure-{random.choice(REGIONS[3:5])}",
        "raw_log": f"Azure AD | {action} | User: {user} | {'ANOMALOUS' if is_sus else 'NORMAL'}",
        "mitre_tactic": "Initial Access" if is_sus else "", "mitre_technique": "T1078.004" if is_sus else "",
        "mitre_technique_name": "Cloud Accounts" if is_sus else "", "is_malicious": 1 if is_sus else 0,
    }


def generate_gcp_event():
    action = random.choice(GCP_ACTIONS)
    user = random.choice(CLOUD_USERS)
    is_sus = "delete" in action.lower()
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(), "source": "cloud",
        "source_ip": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "event_type": f"gcp_{action.split('.')[-1].lower()}", "severity": "high" if is_sus else "info",
        "username": user, "hostname": f"gcp-{random.choice(REGIONS[5:])}",
        "raw_log": f"GCP Audit | {action} by {user} | {'DESTRUCTIVE' if is_sus else 'OK'}",
        "mitre_tactic": "Impact" if is_sus else "", "mitre_technique": "T1078.004" if is_sus else "",
        "mitre_technique_name": "Cloud Accounts" if is_sus else "", "is_malicious": 2 if is_sus else 0,
    }


CLOUD_GENERATORS = [(generate_aws_event, 40), (generate_azure_event, 35), (generate_gcp_event, 25)]


def generate_cloud_log():
    gens, weights = zip(*CLOUD_GENERATORS)
    return random.choices(gens, weights=weights, k=1)[0]()
