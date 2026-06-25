"""
IRIS → AWS CloudTrail Integration

Pulls security-relevant CloudTrail events and normalizes them for the
IRIS XDR correlator. Supports real AWS mode (boto3) and simulation mode
for demos when no live AWS environment is available.

Usage:
    # Pull real CloudTrail events (last 30 minutes)
    from integrations.cloudtrail_source import CloudTrailSource
    source = CloudTrailSource()
    events = source.fetch(minutes=30)

    # Run simulation mode (for demos)
    source = CloudTrailSource(simulate=True)
    events = source.fetch(minutes=30)

    # CLI test
    python -m integrations.cloudtrail_source --simulate
    python -m integrations.cloudtrail_source --live --minutes 60

Environment variables:
    AWS_ACCESS_KEY_ID       AWS credentials (or use IAM role / aws configure)
    AWS_SECRET_ACCESS_KEY
    AWS_REGION              Default: us-east-1
    CLOUDTRAIL_SIMULATE     Set to "true" to force simulation mode
"""

import os
import json
import random
import argparse
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

# CloudTrail event types that matter for XDR correlation
# Grouped by MITRE ATT&CK tactic
WATCHED_EVENTS = {
    # Credential Access
    "sts:GetSessionToken":          {"tactic": "Credential Access",     "severity": "HIGH",     "mitre": "T1528"},
    "sts:AssumeRole":               {"tactic": "Privilege Escalation",  "severity": "HIGH",     "mitre": "T1548"},
    "sts:AssumeRoleWithWebIdentity":{"tactic": "Privilege Escalation",  "severity": "HIGH",     "mitre": "T1548"},
    "secretsmanager:GetSecretValue":{"tactic": "Credential Access",     "severity": "CRITICAL", "mitre": "T1555"},
    "ssm:GetParameter":             {"tactic": "Credential Access",     "severity": "HIGH",     "mitre": "T1552"},
    "kms:Decrypt":                  {"tactic": "Credential Access",     "severity": "MEDIUM",   "mitre": "T1486"},
    # Persistence
    "iam:CreateAccessKey":          {"tactic": "Persistence",           "severity": "CRITICAL", "mitre": "T1098"},
    "iam:AttachUserPolicy":         {"tactic": "Privilege Escalation",  "severity": "CRITICAL", "mitre": "T1098"},
    "iam:CreateUser":               {"tactic": "Persistence",           "severity": "HIGH",     "mitre": "T1136"},
    "iam:PutUserPolicy":            {"tactic": "Privilege Escalation",  "severity": "HIGH",     "mitre": "T1098"},
    # Exfiltration
    "s3:GetObject":                 {"tactic": "Exfiltration",          "severity": "MEDIUM",   "mitre": "T1530"},
    "s3:PutObject":                 {"tactic": "Exfiltration",          "severity": "MEDIUM",   "mitre": "T1537"},
    "s3:GetBucketPolicy":           {"tactic": "Discovery",             "severity": "LOW",      "mitre": "T1619"},
    # Reconnaissance
    "ec2:DescribeInstances":        {"tactic": "Discovery",             "severity": "LOW",      "mitre": "T1580"},
    "ec2:DescribeSecurityGroups":   {"tactic": "Discovery",             "severity": "LOW",      "mitre": "T1580"},
    "iam:ListUsers":                {"tactic": "Discovery",             "severity": "MEDIUM",   "mitre": "T1087"},
    "iam:ListRoles":                {"tactic": "Discovery",             "severity": "MEDIUM",   "mitre": "T1087"},
    # Execution
    "lambda:InvokeFunction":        {"tactic": "Execution",             "severity": "MEDIUM",   "mitre": "T1648"},
    # Defense Evasion
    "cloudtrail:StopLogging":       {"tactic": "Defense Evasion",       "severity": "CRITICAL", "mitre": "T1562"},
    "cloudtrail:DeleteTrail":       {"tactic": "Defense Evasion",       "severity": "CRITICAL", "mitre": "T1562"},
}

# Maps IRIS TTP IDs to the CloudTrail events most likely to follow
# Used by simulation mode to generate realistic correlated events
IRIS_TTP_TO_CLOUDTRAIL = {
    "AML.T0051": ["sts:GetSessionToken", "secretsmanager:GetSecretValue"],       # LLM Data Theft
    "AML.T0048": ["iam:CreateAccessKey", "iam:AttachUserPolicy"],                 # Credential Compromise
    "AML.T0054": ["s3:GetObject", "s3:PutObject", "sts:GetSessionToken"],         # Indirect Prompt Injection
    "AML.T0025": ["ec2:DescribeInstances", "iam:ListUsers", "iam:ListRoles"],     # Reconnaissance
    "AML.T0043": ["iam:AttachUserPolicy", "sts:AssumeRole"],                      # Privilege Escalation
    "AML.T0047": ["cloudtrail:StopLogging", "iam:CreateAccessKey"],               # Evasion
    "AML.T0040": ["lambda:InvokeFunction", "s3:PutObject"],                       # Exfiltration
    "AML.T0049": ["kms:Decrypt", "secretsmanager:GetSecretValue"],                # Lateral Movement
    "AML.T0055": ["iam:CreateUser", "iam:PutUserPolicy"],                         # Persistence
    "AML.T0044": ["ec2:DescribeSecurityGroups", "s3:GetBucketPolicy"],            # Discovery
}

SIMULATED_PRINCIPALS = [
    "arn:aws:iam::123456789012:user/iris-agent",
    "arn:aws:sts::123456789012:assumed-role/LLMAgentRole/session-01",
    "arn:aws:sts::123456789012:assumed-role/AnalystRole/session-02",
]

SIMULATED_RESOURCES = {
    "s3:GetObject":                  "arn:aws:s3:::iris-sensitive-data/credentials.json",
    "s3:PutObject":                  "arn:aws:s3:::iris-exfil-staging/dump.json",
    "secretsmanager:GetSecretValue": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/api-keys",
    "iam:CreateAccessKey":           "arn:aws:iam::123456789012:user/iris-agent",
    "iam:AttachUserPolicy":          "arn:aws:iam::123456789012:user/iris-agent",
    "sts:GetSessionToken":           "arn:aws:sts::123456789012:assumed-role/LLMAgentRole",
    "sts:AssumeRole":                "arn:aws:iam::123456789012:role/AdminRole",
    "lambda:InvokeFunction":         "arn:aws:lambda:us-east-1:123456789012:function:iris-exfil",
    "cloudtrail:StopLogging":        "arn:aws:cloudtrail:us-east-1:123456789012:trail/main",
    "kms:Decrypt":                   "arn:aws:kms:us-east-1:123456789012:key/abc12345",
}


class CloudTrailSource:
    """
    Fetches and normalizes CloudTrail events for IRIS XDR correlation.

    In live mode: connects to AWS CloudTrail via boto3.
    In simulate mode: generates realistic events that pair with IRIS alerts.
    """

    def __init__(self, simulate: bool = False, region: str = None):
        env_sim = os.getenv("CLOUDTRAIL_SIMULATE", "false").lower() == "true"
        self.simulate = simulate or env_sim
        self.region   = region or os.getenv("AWS_REGION", "us-east-1")
        self._client  = None

        if not self.simulate:
            self._client = self._init_boto3()

    def _init_boto3(self):
        try:
            import boto3
            client = boto3.client(
                "cloudtrail",
                region_name=self.region,
                aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
                aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            )
            client.get_trail_status(Name="default")
            return client
        except Exception as e:
            print(f"[CloudTrail] AWS connection failed: {e} — falling back to simulation")
            self.simulate = True
            return None

    def fetch(self, minutes: int = 30, iris_alert: Optional[dict] = None) -> list[dict]:
        """
        Fetch CloudTrail events from the last N minutes.
        If iris_alert is provided in simulate mode, generates correlated events.
        """
        if self.simulate:
            return self._simulate(minutes=minutes, iris_alert=iris_alert)
        return self._fetch_live(minutes=minutes)

    def _fetch_live(self, minutes: int = 30) -> list[dict]:
        end   = datetime.now(timezone.utc)
        start = end - timedelta(minutes=minutes)
        events = []
        kwargs = {
            "StartTime": start,
            "EndTime":   end,
            "MaxResults": 50,
        }
        while True:
            resp = self._client.lookup_events(**kwargs)
            for raw in resp.get("Events", []):
                normalized = self._normalize(raw)
                if normalized:
                    events.append(normalized)
            token = resp.get("NextToken")
            if not token:
                break
            kwargs["NextToken"] = token
        return events

    def _normalize(self, raw: dict) -> Optional[dict]:
        event_name = raw.get("EventName", "")
        service    = raw.get("EventSource", "").replace(".amazonaws.com", "")
        full_name  = f"{service}:{event_name}"

        meta = WATCHED_EVENTS.get(full_name)
        if not meta:
            return None

        resources = raw.get("Resources") or []
        resource_arn = resources[0].get("ResourceARN", "unknown") if resources else "unknown"

        ct_detail = {}
        if raw.get("CloudTrailEvent"):
            try:
                ct_detail = json.loads(raw["CloudTrailEvent"])
            except Exception:
                pass

        user_identity = ct_detail.get("userIdentity", {})
        principal = (
            user_identity.get("arn")
            or user_identity.get("userName")
            or user_identity.get("type", "unknown")
        )

        return {
            "event_id":       raw.get("EventId", ""),
            "event_name":     full_name,
            "timestamp":      raw["EventTime"].isoformat() if raw.get("EventTime") else "",
            "tactic":         meta["tactic"],
            "severity":       meta["severity"],
            "mitre_id":       meta["mitre"],
            "principal":      principal,
            "source_ip":      ct_detail.get("sourceIPAddress", "unknown"),
            "region":         ct_detail.get("awsRegion", self.region),
            "resource_arn":   resource_arn,
            "user_agent":     ct_detail.get("userAgent", ""),
            "layer":          "cloud",
            "source":         "cloudtrail",
        }

    def _simulate(self, minutes: int = 30, iris_alert: Optional[dict] = None) -> list[dict]:
        now    = datetime.now(timezone.utc)
        events = []

        if iris_alert:
            # Generate events that correlate with this specific IRIS alert
            ttp_id     = iris_alert.get("ttp_id", "")
            alert_time = iris_alert.get("timestamp", now.isoformat())
            if isinstance(alert_time, str):
                try:
                    alert_time = datetime.fromisoformat(alert_time.replace("Z", "+00:00"))
                except Exception:
                    alert_time = now

            ct_events = IRIS_TTP_TO_CLOUDTRAIL.get(ttp_id, ["sts:GetSessionToken", "s3:GetObject"])
            for i, event_name in enumerate(ct_events):
                # Stagger events 5–45 seconds after the IRIS alert
                offset_sec = random.randint(5, 45) + (i * random.randint(3, 12))
                event_time = alert_time + timedelta(seconds=offset_sec)
                meta       = WATCHED_EVENTS.get(event_name, {"tactic": "Unknown", "severity": "MEDIUM", "mitre": "T0000"})
                events.append({
                    "event_id":     f"sim-{ttp_id}-{i:03d}",
                    "event_name":   event_name,
                    "timestamp":    event_time.isoformat(),
                    "tactic":       meta["tactic"],
                    "severity":     meta["severity"],
                    "mitre_id":     meta["mitre"],
                    "principal":    random.choice(SIMULATED_PRINCIPALS),
                    "source_ip":    f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                    "region":       self.region,
                    "resource_arn": SIMULATED_RESOURCES.get(event_name, "arn:aws:s3:::iris-demo"),
                    "user_agent":   "aws-sdk-python/1.34.0",
                    "layer":        "cloud",
                    "source":       "cloudtrail_simulated",
                    "correlated_iris_ttp": ttp_id,
                })
        else:
            # Generate a random mix of background events for the time window
            base_events = random.sample(list(WATCHED_EVENTS.keys()), k=random.randint(3, 7))
            for i, event_name in enumerate(base_events):
                offset_min = random.randint(0, minutes)
                event_time = now - timedelta(minutes=offset_min)
                meta       = WATCHED_EVENTS[event_name]
                events.append({
                    "event_id":     f"sim-bg-{i:03d}",
                    "event_name":   event_name,
                    "timestamp":    event_time.isoformat(),
                    "tactic":       meta["tactic"],
                    "severity":     meta["severity"],
                    "mitre_id":     meta["mitre"],
                    "principal":    random.choice(SIMULATED_PRINCIPALS),
                    "source_ip":    f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                    "region":       self.region,
                    "resource_arn": SIMULATED_RESOURCES.get(event_name, "arn:aws:s3:::iris-demo"),
                    "user_agent":   "aws-sdk-python/1.34.0",
                    "layer":        "cloud",
                    "source":       "cloudtrail_simulated",
                })

        events.sort(key=lambda e: e["timestamp"])
        return events


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IRIS CloudTrail Source")
    parser.add_argument("--simulate", action="store_true", help="Use simulation mode")
    parser.add_argument("--live",     action="store_true", help="Use live AWS mode")
    parser.add_argument("--minutes",  type=int, default=30, help="Look-back window in minutes")
    args = parser.parse_args()

    source = CloudTrailSource(simulate=args.simulate or not args.live)
    events = source.fetch(minutes=args.minutes)

    print(f"\n[CloudTrail] Fetched {len(events)} security events (last {args.minutes} min)\n")
    for e in events:
        ts    = e["timestamp"][:19].replace("T", " ")
        name  = e["event_name"]
        tact  = e["tactic"]
        sev   = e["severity"]
        res   = e["resource_arn"].split(":")[-1][:40]
        print(f"  [{sev:8s}] {ts}  {name:40s}  {tact:25s}  {res}")
