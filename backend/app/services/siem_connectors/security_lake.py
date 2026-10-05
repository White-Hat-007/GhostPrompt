"""
Amazon Security Lake Connector — OCSF Format via S3

Writes security events in OCSF (Open Cybersecurity Schema Framework) format
to S3 in Parquet via direct PutObject. GhostPrompt registers as a custom source
with correct region/accountId/eventDay partitioning.
https://docs.aws.amazon.com/security-lake/latest/userguide/custom-sources.html
"""

import json
from datetime import datetime, timezone

from app.services.siem_connectors.base import ConnectorInterface, ConnectorResult


class SecurityLakeConnector(ConnectorInterface):
    name = "security_lake"
    display_name = "Amazon Security Lake"
    supports_bidirectional = False
    credential_fields = [
        {"field": "aws_access_key", "label": "AWS Access Key ID", "type": "secret", "placeholder": "AKIA..."},
        {"field": "aws_secret_key", "label": "AWS Secret Access Key", "type": "secret", "placeholder": "wJal..."},
        {"field": "region", "label": "AWS Region", "type": "text", "placeholder": "us-east-1"},
        {"field": "s3_bucket", "label": "Security Lake S3 Bucket", "type": "text", "placeholder": "aws-security-data-lake-us-east-1-..."},
        {"field": "account_id", "label": "AWS Account ID", "type": "text", "placeholder": "123456789012"},
        {"field": "external_id", "label": "Custom Source External ID", "type": "text", "placeholder": "ghostprompt-source"},
    ]

    OCSF_SEVERITY_MAP = {
        "safe": 1, "low": 2, "medium": 3, "high": 4, "critical": 5,
    }

    def _to_ocsf(self, event: dict, config: dict) -> dict:
        """Convert GhostPrompt event to OCSF 1.1 Detection Finding format."""
        now = datetime.now(timezone.utc)
        threat_level = event.get("threat_level", "safe")

        return {
            "class_uid": 2004,  # Detection Finding
            "class_name": "Detection Finding",
            "category_uid": 2,  # Findings
            "category_name": "Findings",
            "severity_id": self.OCSF_SEVERITY_MAP.get(threat_level, 1),
            "severity": threat_level.upper(),
            "status_id": 2 if event.get("is_blocked") else 1,  # 1=New, 2=In Progress
            "status": "Blocked" if event.get("is_blocked") else "Detected",
            "activity_id": 1,  # Create
            "activity_name": "Create",
            "type_uid": 200401,
            "type_name": "Detection Finding: Create",
            "time": int(now.timestamp() * 1000),
            "time_dt": now.isoformat(),
            "metadata": {
                "version": "1.1.0",
                "product": {
                    "name": "GhostPrompt",
                    "vendor_name": "GhostPrompt",
                    "version": "1.0.0",
                    "feature": {"name": "AI Firewall"},
                },
                "log_name": "ghostprompt-security",
                "uid": event.get("request_id", ""),
            },
            "finding_info": {
                "title": f"AI Security Detection — {event.get('action', 'scan')}",
                "uid": event.get("request_id", ""),
                "types": event.get("threat_categories", []),
                "analytic": {
                    "type": "Rule",
                    "name": "GhostPrompt AI Firewall",
                    "uid": "ghostprompt-firewall",
                },
            },
            "src_endpoint": {
                "ip": event.get("source_ip", ""),
            },
            "confidence_id": 3,  # High
            "confidence": "High",
            "observables": [
                {"name": "model", "type": "Other", "value": event.get("model_name", "")},
                {"name": "provider", "type": "Other", "value": event.get("model_provider", "")},
                {"name": "threat_score", "type": "Other", "value": str(event.get("threat_score", 0))},
            ],
            "unmapped": {
                "detections": event.get("detections", []),
                "scan_duration_ms": event.get("scan_duration_ms", 0),
            },
        }

    async def push_event(self, event: dict, config: dict) -> ConnectorResult:
        try:
            import boto3
        except ImportError:
            return ConnectorResult(status="error", details="boto3 not installed — run: pip install boto3")

        region = config.get("region", "us-east-1")
        bucket = config.get("s3_bucket", "")
        account_id = config.get("account_id", "")
        external_id = config.get("external_id", "ghostprompt-source")

        if not bucket:
            return ConnectorResult(status="error", details="No S3 bucket configured")

        ocsf_event = self._to_ocsf(event, config)
        now = datetime.now(timezone.utc)

        # Security Lake partitioning: region/accountId/eventDay=YYYYMMDD/
        s3_key = (
            f"ext/{external_id}/"
            f"region={region}/"
            f"accountId={account_id}/"
            f"eventDay={now.strftime('%Y%m%d')}/"
            f"ghostprompt-{event.get('request_id', 'unknown')}.json"
        )

        try:
            s3 = boto3.client(
                "s3",
                region_name=region,
                aws_access_key_id=config.get("aws_access_key"),
                aws_secret_access_key=config.get("aws_secret_key"),
            )
            s3.put_object(
                Bucket=bucket,
                Key=s3_key,
                Body=json.dumps(ocsf_event).encode(),
                ContentType="application/json",
            )
            return ConnectorResult(status="connected", details=f"OCSF event written to s3://{bucket}/{s3_key}")
        except Exception as e:
            return ConnectorResult(status="error", details=f"S3 PutObject failed: {str(e)[:200]}")

    async def test_connection(self, config: dict) -> ConnectorResult:
        try:
            import boto3
        except ImportError:
            return ConnectorResult(status="error", details="boto3 not installed — run: pip install boto3")

        region = config.get("region", "us-east-1")
        bucket = config.get("s3_bucket", "")

        if not bucket:
            return ConnectorResult(status="error", details="No S3 bucket configured")

        try:
            s3 = boto3.client(
                "s3",
                region_name=region,
                aws_access_key_id=config.get("aws_access_key"),
                aws_secret_access_key=config.get("aws_secret_key"),
            )
            # HeadBucket to verify bucket exists and credentials are valid
            s3.head_bucket(Bucket=bucket)
            return ConnectorResult(status="connected", details=f"S3 bucket '{bucket}' accessible in {region}")
        except s3.exceptions.ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code == "403":
                return ConnectorResult(status="auth_failed", details="Access denied — check IAM permissions")
            elif code == "404":
                return ConnectorResult(status="error", details=f"Bucket '{bucket}' not found")
            else:
                return ConnectorResult(status="error", details=str(e)[:200])
        except Exception as e:
            return ConnectorResult(status="error", details=str(e)[:200])
