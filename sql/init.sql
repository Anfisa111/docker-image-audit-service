CREATE TABLE IF NOT EXISTS scan_jobs (
    id UUID PRIMARY KEY,
    image_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued', -- queued | running | completed | failed
    summary JSONB,
    report JSONB,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs (status);