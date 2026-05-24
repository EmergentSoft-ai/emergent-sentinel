-- ═══════════════════════════════════════════════════════════════
-- SENTINEL MIND OS — init.sql (Final)
-- PostgreSQL 15 · RLS · Indices ultra-rapidos para Learning Loop
-- ═══════════════════════════════════════════════════════════════

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- TIPOS
DO $$ BEGIN
    CREATE TYPE severity_level AS ENUM ('CRITICAL','HIGH','MEDIUM','LOW','INFO');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE finding_category AS ENUM ('SECRET_EXPOSED','LOGIC_FLAW','DEPENDENCY_VULN','MISCONFIGURATION');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE finding_status AS ENUM ('OPEN','PATCHED','DISMISSED','FALSE_POSITIVE','IN_REVIEW');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE notification_channel AS ENUM ('TELEGRAM','SLACK','EMAIL','WEBHOOK');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ─────────────────────────────────────────────────────────────
-- TABLA: monitored_repos
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS monitored_repos (
    id               UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
    repo_full_name   TEXT        NOT NULL UNIQUE,
    webhook_secret_h TEXT        NOT NULL,  -- SHA-256 del HMAC secret, nunca el raw
    is_active        BOOLEAN     DEFAULT TRUE,
    scan_config      JSONB       DEFAULT '{
        "max_commits_per_event": 5,
        "max_files_per_commit": 10,
        "notify_on_severity": ["CRITICAL","HIGH"],
        "auto_pr_on_severity": ["CRITICAL","HIGH"],
        "monitored_branches": ["main","master","develop"],
        "ignored_paths": [".github/","docs/","*.md"]
    }'::jsonb,
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    updated_at       TIMESTAMPTZ DEFAULT NOW()
);

-- ─────────────────────────────────────────────────────────────
-- TABLA: findings  (central del sistema)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS findings (
    id              UUID             DEFAULT gen_random_uuid() PRIMARY KEY,
    repo_name       TEXT             NOT NULL,
    repo_url        TEXT             NOT NULL,
    commit_sha      TEXT             NOT NULL,
    file_path       TEXT             NOT NULL,
    line_number     INTEGER          DEFAULT 0 CHECK (line_number >= 0),
    severity        severity_level   NOT NULL,
    category        finding_category NOT NULL,
    description     TEXT             NOT NULL,
    raw_match       TEXT             DEFAULT '',     -- Preview truncado + ***REDACTED
    ai_analysis     JSONB            DEFAULT '{}',   -- JSON completo de Claude
    patch_pr_url    TEXT,
    patch_applied   BOOLEAN          DEFAULT FALSE,
    status          finding_status   DEFAULT 'OPEN',
    reviewer_note   TEXT,                            -- Nota del revisor (alimenta Learning Loop)
    created_at      TIMESTAMPTZ      DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ      DEFAULT NOW(),
    CONSTRAINT resolved_requires_non_open
        CHECK (resolved_at IS NULL OR status <> 'OPEN')
);

-- ─────────────────────────────────────────────────────────────
-- TABLA: notifications
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS notifications (
    id            UUID                 DEFAULT gen_random_uuid() PRIMARY KEY,
    finding_id    UUID                 REFERENCES findings(id) ON DELETE CASCADE,
    channel       notification_channel NOT NULL,
    payload       JSONB                DEFAULT '{}',
    success       BOOLEAN              DEFAULT TRUE,
    error_message TEXT,
    sent_at       TIMESTAMPTZ          DEFAULT NOW()
);

-- ─────────────────────────────────────────────────────────────
-- TABLA: scan_runs  (metricas y costos)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_runs (
    id                 UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
    repo_name          TEXT        NOT NULL,
    trigger_commit_sha TEXT        NOT NULL,
    commits_scanned    INTEGER     DEFAULT 0,
    files_scanned      INTEGER     DEFAULT 0,
    findings_total     INTEGER     DEFAULT 0,
    findings_critical  INTEGER     DEFAULT 0,
    findings_high      INTEGER     DEFAULT 0,
    prs_created        INTEGER     DEFAULT 0,
    duration_ms        INTEGER,
    errors             JSONB       DEFAULT '[]',
    started_at         TIMESTAMPTZ DEFAULT NOW(),
    completed_at       TIMESTAMPTZ
);

-- ─────────────────────────────────────────────────────────────
-- INDICES — Optimizados para queries criticos
-- ─────────────────────────────────────────────────────────────

-- Dashboard: CRITICAL/HIGH abiertos
CREATE INDEX IF NOT EXISTS idx_findings_open_critical
    ON findings (severity, created_at DESC)
    WHERE status = 'OPEN';

-- Filtrar por repo y fecha
CREATE INDEX IF NOT EXISTS idx_findings_repo_created
    ON findings (repo_name, created_at DESC);

-- Filtrar por status
CREATE INDEX IF NOT EXISTS idx_findings_status_created
    ON findings (status, created_at DESC);

-- Filtrar por categoria
CREATE INDEX IF NOT EXISTS idx_findings_category_status
    ON findings (category, status);

-- ═══════════════════════════════════════════════════════════════
-- INDICE CRITICO: Learning Loop
-- Es el indice mas importante. get_learning_context() lo usa
-- en CADA llamada a Claude. Diseñado para O(log n).
-- Cubre: repo + category + status (resueltos) + resolved_at
-- ═══════════════════════════════════════════════════════════════
CREATE INDEX IF NOT EXISTS idx_findings_learning_loop
    ON findings (repo_name, category, status, resolved_at DESC)
    WHERE status IN ('PATCHED','DISMISSED','FALSE_POSITIVE')
      AND resolved_at IS NOT NULL;

-- Learning Loop con reviewer_note (para contexto mas rico)
CREATE INDEX IF NOT EXISTS idx_findings_learning_with_note
    ON findings (repo_name, category, resolved_at DESC)
    WHERE status IN ('PATCHED','DISMISSED','FALSE_POSITIVE')
      AND reviewer_note IS NOT NULL;

-- Full-text en description
CREATE INDEX IF NOT EXISTS idx_findings_description_trgm
    ON findings USING GIN (description gin_trgm_ops);

-- JSONB en ai_analysis
CREATE INDEX IF NOT EXISTS idx_findings_ai_gin
    ON findings USING GIN (ai_analysis);

-- notifications
CREATE INDEX IF NOT EXISTS idx_notifications_finding
    ON notifications (finding_id, sent_at DESC);

-- scan_runs con hallazgos criticos
CREATE INDEX IF NOT EXISTS idx_scan_runs_critical
    ON scan_runs (repo_name, started_at DESC)
    WHERE findings_critical > 0;

-- ─────────────────────────────────────────────────────────────
-- TRIGGERS: updated_at automatico
-- ─────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION fn_update_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END; $$;

CREATE OR REPLACE TRIGGER trg_findings_updated_at
    BEFORE UPDATE ON findings FOR EACH ROW EXECUTE FUNCTION fn_update_updated_at();

CREATE OR REPLACE TRIGGER trg_repos_updated_at
    BEFORE UPDATE ON monitored_repos FOR EACH ROW EXECUTE FUNCTION fn_update_updated_at();

-- ─────────────────────────────────────────────────────────────
-- FUNCION: Registrar decision humana (cierra el Learning Loop)
-- Llamada desde /feedback/{id} del Scanner o Edge Functions.
-- ─────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION fn_record_human_decision(
    p_finding_id    UUID,
    p_decision      TEXT,
    p_reviewer_note TEXT DEFAULT NULL
)
RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE valid_decisions TEXT[] := ARRAY['PATCHED','DISMISSED','FALSE_POSITIVE'];
BEGIN
    IF NOT (p_decision = ANY(valid_decisions)) THEN
        RAISE EXCEPTION 'Decision invalida: %. Validas: %', p_decision, valid_decisions;
    END IF;
    UPDATE findings SET
        status        = p_decision::finding_status,
        resolved_at   = NOW(),
        reviewer_note = COALESCE(p_reviewer_note, reviewer_note),
        updated_at    = NOW()
    WHERE id = p_finding_id AND status = 'OPEN';
    RETURN FOUND;
END; $$;

-- ─────────────────────────────────────────────────────────────
-- VISTAS
-- ─────────────────────────────────────────────────────────────
CREATE OR REPLACE VIEW vw_open_critical_findings AS
SELECT
    f.id, f.repo_name, f.file_path, f.line_number,
    f.severity, f.category, f.description, f.patch_pr_url,
    f.created_at,
    ROUND(EXTRACT(EPOCH FROM (NOW()-f.created_at))/3600, 1) AS hours_open,
    f.ai_analysis->>'confidence' AS ai_confidence
FROM findings f
WHERE f.status = 'OPEN' AND f.severity IN ('CRITICAL','HIGH')
ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 ELSE 3 END, f.created_at ASC;

CREATE OR REPLACE VIEW vw_learning_context AS
SELECT
    f.repo_name, f.category, f.status AS decision,
    f.description AS finding_description, f.file_path,
    f.reviewer_note,
    f.ai_analysis->>'summary'            AS ai_summary,
    f.ai_analysis->>'confidence'         AS ai_confidence,
    f.ai_analysis->>'is_false_positive'  AS was_false_positive,
    f.resolved_at, f.created_at,
    EXTRACT(EPOCH FROM (f.resolved_at - f.created_at))/3600 AS hours_to_resolve
FROM findings f
WHERE f.status IN ('PATCHED','DISMISSED','FALSE_POSITIVE') AND f.resolved_at IS NOT NULL
ORDER BY f.resolved_at DESC;

CREATE OR REPLACE VIEW vw_repo_stats_7d AS
SELECT
    repo_name,
    COUNT(*)              AS total_scans,
    SUM(findings_total)   AS total_findings,
    SUM(findings_critical)AS total_critical,
    SUM(findings_high)    AS total_high,
    SUM(prs_created)      AS total_prs,
    ROUND(AVG(duration_ms))AS avg_duration_ms,
    MAX(completed_at)     AS last_scan_at
FROM scan_runs
WHERE started_at >= NOW() - INTERVAL '7 days'
GROUP BY repo_name ORDER BY total_critical DESC;

-- ─────────────────────────────────────────────────────────────
-- ROW LEVEL SECURITY (deny-by-default)
-- ─────────────────────────────────────────────────────────────
ALTER TABLE findings        ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitored_repos ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications   ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_runs       ENABLE ROW LEVEL SECURITY;

CREATE POLICY "sentinel_findings"    ON findings        FOR ALL TO sentinel USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY "sentinel_repos"       ON monitored_repos FOR ALL TO sentinel USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY "sentinel_notifs"      ON notifications   FOR ALL TO sentinel USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY "sentinel_scan_runs"   ON scan_runs       FOR ALL TO sentinel USING (TRUE) WITH CHECK (TRUE);

-- GRANTS
GRANT SELECT,INSERT,UPDATE ON findings,monitored_repos,scan_runs TO sentinel;
GRANT SELECT,INSERT        ON notifications TO sentinel;
GRANT SELECT ON vw_open_critical_findings, vw_learning_context, vw_repo_stats_7d TO sentinel;
GRANT EXECUTE ON FUNCTION fn_record_human_decision TO sentinel;

-- DATO INICIAL (reemplazar con tu repo real)
INSERT INTO monitored_repos (repo_full_name, webhook_secret_h, is_active)
VALUES (
    'your-org/your-repo',
    encode(sha256('REPLACE_WITH_SHA256_OF_YOUR_WEBHOOK_SECRET'::bytea), 'hex'),
    TRUE
) ON CONFLICT (repo_full_name) DO NOTHING;

-- VERIFICACION:
-- SELECT table_name FROM information_schema.tables WHERE table_schema='public';
-- SELECT indexname FROM pg_indexes WHERE schemaname='public' ORDER BY indexname;
