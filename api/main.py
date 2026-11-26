from datetime import datetime, timezone
import json
import os
import uuid
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
import psycopg2
from psycopg2.extras import RealDictCursor
from pydantic import BaseModel, Field
import redis

app = FastAPI(title="Docker Image Security Audit API")

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


class ScanCreateRequest(BaseModel):
    image: str = Field(..., min_length=1, examples=["alpine:3.19"])


class ScanResponse(BaseModel):
    id: str
    image: str
    status: str
    created_at: str
    updated_at: str
    summary: Optional[dict[str, Any]] = None
    report: Optional[dict[str, Any]] = None
    error_message: Optional[str] = None


def row_to_response(row: dict[str, Any]) -> ScanResponse:
    return ScanResponse(
        id=str(row["id"]),
        image=row["image_name"],
        status=row["status"],
        created_at=row["created_at"].isoformat(),
        updated_at=row["updated_at"].isoformat(),
        summary=row["summary"],
        report=row["report"],
        error_message=row["error_message"],
    )


@app.get("/health")
def health():
    redis_client.ping()
    with get_pg_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
    return {"status": "ok"}


@app.post("/scans", response_model=ScanResponse, status_code=202)
def create_scan(payload: ScanCreateRequest):
    job_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    with get_pg_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO scan_jobs (id, image_name, status, created_at, updated_at)
                VALUES (%s, %s, 'queued', %s, %s)
                RETURNING *
                """,
                (job_id, payload.image.strip(), now, now),
            )
            row = cur.fetchone()
        conn.commit()

    task_message = json.dumps({"job_id": job_id, "image": payload.image.strip()})
    redis_client.rpush(REDIS_QUEUE, task_message)

    return row_to_response(row)


@app.get("/scans/{job_id}", response_model=ScanResponse)
def get_scan(job_id: str):
    try:
        uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid job_id format")

    with get_pg_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM scan_jobs WHERE id = %s", (job_id,))
            row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Scan job not found")

    return row_to_response(row)