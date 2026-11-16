#!/usr/bin/env python3
"""
Converts Checkov SARIF output into AWS Security Finding Format (ASFF),
saves the normalized ASFF JSON artifact, and imports findings into AWS Security Hub
(falling back to SNS SecOps alerting when Security Hub ingestion APIs are unavailable locally).
"""
import datetime
import json
import os
import sys
import boto3
from botocore.exceptions import ClientError


def convert_sarif_to_asff(sarif_path: str, account_id: str, region: str) -> list[dict]:
    with open(sarif_path, "r", encoding="utf-8") as f:
        sarif_data = json.load(f)

    findings = []
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for run in sarif_data.get("runs", []):
        rules = {
            r["id"]: r
            for r in run.get("tool", {}).get("driver", {}).get("rules", [])
        }
        for idx, result in enumerate(run.get("results", [])):
            rule_id = result.get("ruleId", "UNKNOWN_RULE")
            rule_meta = rules.get(rule_id, {})
            message = result.get("message", {}).get("text", "Policy violation detected")
            uri = (
                result.get("locations", [{}])[0]
                .get("physicalLocation", {})
                .get("artifactLocation", {})
                .get("uri", "unknown.tf")
            )

            findings.append(
                {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"checkov-{rule_id}-{idx}",
                    "ProductArn": f"arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default",
                    "GeneratorId": "checkov-policy-as-code-gate",
                    "AwsAccountId": account_id,
                    "Types": ["Software and Configuration Checks/Vulnerabilities/CVE"],
                    "CreatedAt": now,
                    "UpdatedAt": now,
                    "Severity": {"Label": "HIGH"},
                    "Title": f"[{rule_id}] {rule_meta.get('name', message)[:120]}",
                    "Description": message,
                    "Resources": [
                        {
                            "Type": "Other",
                            "Id": f"terraform://{uri}",
                            "Partition": "aws",
                            "Region": region,
                        }
                    ],
                }
            )
    return findings


def main() -> None:
    sarif_file = sys.argv[1] if len(sys.argv) > 1 else "results_sarif.sarif"
    if not os.path.exists(sarif_file):
        print(f"SARIF file not found: {sarif_file}")
        sys.exit(1)

    region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    endpoint_url = os.getenv("AWS_ENDPOINT_URL", "http://localhost:4566")
    account_id = os.getenv("AWS_ACCOUNT_ID", "000000000000")
    sns_topic_arn = os.getenv(
        "SNS_TOPIC_ARN",
        f"arn:aws:sns:{region}:{account_id}:ec2-vpc-drift-alerts-junlab",
    )

    asff_findings = convert_sarif_to_asff(sarif_file, account_id, region)
    with open("asff_findings.json", "w", encoding="utf-8") as out:
        json.dump({"Findings": asff_findings}, out, indent=2)

    print(f"Converted {len(asff_findings)} Checkov SARIF findings into ASFF format (saved to asff_findings.json).")

    if not asff_findings:
        return

    sh_client = boto3.client("securityhub", region_name=region, endpoint_url=endpoint_url)
    try:
        resp = sh_client.batch_import_findings(Findings=asff_findings[:100])
        print(
            f"Security Hub BatchImportFindings -> SuccessCount={resp.get('SuccessCount')}, "
            f"FailedCount={resp.get('FailedCount')}"
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "UnknownOperationException":
            sns_client = boto3.client("sns", region_name=region, endpoint_url=endpoint_url)
            summary = "\n".join(f"- {item['Title']}" for item in asff_findings)
            sns_client.publish(
                TopicArn=sns_topic_arn,
                Subject=f"[Policy-as-Code Gate] {len(asff_findings)} Checkov Violations Detected",
                Message=f"ASFF findings exported to asff_findings.json:\n\n{summary}",
            )
            print(
                f"Local emulator fallback: published {len(asff_findings)} ASFF findings summary to SNS ({sns_topic_arn})."
            )
        else:
            raise


if __name__ == "__main__":
    main()
