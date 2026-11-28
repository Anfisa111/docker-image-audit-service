from datetime import datetime, timezone
import json
import os
import subprocess
import time
from typing import Any

import psycopg2
import redis

PG_DSN = (
    f"host={os.environ['POSTGRES_HOST']} "
    f"port={os.getenv('POSTGRES_PORT', '5432')} "
    f"dbname={os.environ['POSTGRES_DB']} "
    f"user={os.environ['POSTGRES_USER']} "
    f"password={os.environ['POSTGRES_PASSWORD']}"
)
REDIS_HOST = os.environ["REDIS_HOST"]
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD") or None
REDIS_QUEUE = os.getenv("REDIS_QUEUE", "trivy_scan_jobs")

redis_client = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    password=REDIS_PASSWORD,
    decode_responses=True,
)


def get_pg_conn():
    return psycopg2.connect(PG_DSN)


def update_status(job_id: str, status: str, summary: dict[str, Any] | None = None,
                  report: dict[str, Any] | None = None, error_message: str | None = None):
    now = datetime.now(timezone.utc)
    with get_pg_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE scan_jobs
                SET status = %s,
                    summary = COALESCE(%s::jsonb, summary),
                    report = COALESCE(%s::jsonb, report),
                    error_message = %s,
                    updated_at = %s
                WHERE id = %s
                """,
                (
                    status,
                    json.dumps(summary) if summary is not None else None,
                    json.dumps(report) if report is not None else None,
                    error_message,
                    now,
                    job_id,
                ),
            )
        conn.commit()


def run_trivy(image: str) -> tuple[dict[str, int], dict[str, Any]]:
    cmd = ["trivy", "image", "--quiet", "--format", "json", image]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"Trivy exited with code {proc.returncode}")

    raw_data = json.loads(proc.stdout)
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    findings = []

    for result in raw_data.get("Results", []):
        target = result.get("Target")
        for vuln in result.get("Vulnerabilities", []) or []:
            sev = vuln.get("Severity", "UNKNOWN").upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts["UNKNOWN"] += 1

            findings.append({
                "target": target,
                "pkg_name": vuln.get("PkgName"),
                "installed_version": vuln.get("InstalledVersion"),
                "fixed_version": vuln.get("FixedVersion"),
                "severity": sev,
                "vulnerability_id": vuln.get("VulnerabilityID"),
                "title": vuln.get("Title"),
            })

    summary = {
        "total_vulnerabilities": len(findings),
        "by_severity": severity_counts,
    }
    report = {
        "image": image,
        "summary": summary,
        "vulnerabilities": findings[:100],  # ограничиваем размер отчета в БД
    }
    return summary, report


def process_job(raw_msg: str):
    data = json.loads(raw_msg)
    job_id = data["job_id"]
    image = data["image"]

    update_status(job_id, "running")
    try:
        summary, report = run_trivy(image)
        update_status(job_id, "completed", summary=summary, report=report)
    except Exception as exc:
        update_status(job_id, "failed", error_message=str(exc))

def main():
    print(f"Worker started. Listening on Redis queue '{REDIS_QUEUE}'...")
    while True:
        try:
            item = redis_client.blpop(REDIS_QUEUE, timeout=5)
            if item:
                _, raw_msg = item
                process_job(raw_msg)
        except Exception as exc:
            print(f"Loop error: {exc}")
            time.sleep(2)


if __name__ == "__main__":
    main()