"""
╔══════════════════════════════════════════════════════════════════════╗
║  SENTINEL MIND OS — main.py (Final Unified)                          ║
║  FastAPI · HMAC Validation · Learning Loop · Claude Super Prompt     ║
║  GitHub PR Generator · Supabase · Telegram/Slack · Structlog         ║
╚══════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

import httpx
import structlog
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

# ═══════════════════════════════════════════════════════════════════════
# BOOTSTRAP
# ═══════════════════════════════════════════════════════════════════════
load_dotenv()

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=True,
)

log: structlog.BoundLogger = structlog.get_logger("sentinel_mind")


# ═══════════════════════════════════════════════════════════════════════
# CONFIGURACION — Todas las variables desde os.environ sin defaults
#                 para secretos. Falla rapido si alguna falta.
# ═══════════════════════════════════════════════════════════════════════
class Config:
    CLAUDE_API_KEY:        str = os.environ["CLAUDE_API_KEY"]
    GITHUB_TOKEN:          str = os.environ["GITHUB_TOKEN"]
    GITHUB_WEBHOOK_SECRET: str = os.environ["GITHUB_WEBHOOK_SECRET"]
    SUPABASE_URL:          str = os.environ["SUPABASE_URL"]
    SUPABASE_KEY:          str = os.environ["SUPABASE_SERVICE_KEY"]
    TELEGRAM_TOKEN:        str = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    TELEGRAM_CHAT_ID:      str = os.environ.get("TELEGRAM_CHAT_ID", "")
    SLACK_WEBHOOK:         str = os.environ.get("SLACK_WEBHOOK_URL", "")
    INTERNAL_TOKEN:        str = os.environ["INTERNAL_SERVICE_TOKEN"]
    MAX_COMMITS_PER_EVENT: int = int(os.environ.get("MAX_COMMITS_PER_EVENT", "5"))
    MAX_FILES_PER_COMMIT:  int = int(os.environ.get("MAX_FILES_PER_COMMIT", "10"))
    MAX_FILE_BYTES:        int = int(os.environ.get("MAX_FILE_BYTES", "150000"))
    CODE_TRUNCATE_CHARS:   int = int(os.environ.get("CODE_TRUNCATE_CHARS", "12000"))
    CLAUDE_MAX_TOKENS:     int = int(os.environ.get("CLAUDE_MAX_TOKENS", "2048"))
    CLAUDE_MODEL:          str = os.environ.get("CLAUDE_MODEL", "claude-opus-4-5")


cfg = Config()


# ═══════════════════════════════════════════════════════════════════════
# ENUMS Y DATACLASSES
# ═══════════════════════════════════════════════════════════════════════
class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class Category(str, Enum):
    SECRET     = "SECRET_EXPOSED"
    LOGIC_FLAW = "LOGIC_FLAW"
    MISCONFIG  = "MISCONFIGURATION"
    DEPENDENCY = "DEPENDENCY_VULN"


@dataclass
class Finding:
    repo_name:    str
    repo_url:     str
    commit_sha:   str
    file_path:    str
    line_number:  int
    severity:     Severity
    category:     Category
    description:  str
    raw_match:    str
    ai_analysis:  dict          = field(default_factory=dict)
    patch_pr_url: Optional[str] = None
    db_id:        Optional[str] = None


@dataclass
class ScanResult:
    repo:              str
    commits_scanned:   int       = 0
    files_scanned:     int       = 0
    findings_total:    int       = 0
    findings_critical: int       = 0
    findings_high:     int       = 0
    prs_created:       list[str] = field(default_factory=list)
    errors:            list[str] = field(default_factory=list)
    duration_ms:       int       = 0


# ═══════════════════════════════════════════════════════════════════════
# MODULO 1 — SECRET SCANNER
# ═══════════════════════════════════════════════════════════════════════
SECRET_PATTERNS: dict[str, tuple[str, Severity]] = {
    "AWS_ACCESS_KEY":  (r"AKIA[0-9A-Z]{16}",                                                           Severity.CRITICAL),
    "AWS_SECRET_KEY":  (r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",                    Severity.CRITICAL),
    "GITHUB_PAT":      (r"ghp_[a-zA-Z0-9]{36}",                                                        Severity.CRITICAL),
    "GITHUB_OAUTH":    (r"gho_[a-zA-Z0-9]{36}",                                                        Severity.CRITICAL),
    "OPENAI_KEY":      (r"sk-[a-zA-Z0-9]{48}",                                                         Severity.CRITICAL),
    "ANTHROPIC_KEY":   (r"sk-ant-[a-zA-Z0-9\-]{93}",                                                   Severity.CRITICAL),
    "STRIPE_LIVE":     (r"sk_live_[0-9a-zA-Z]{24,}",                                                   Severity.CRITICAL),
    "STRIPE_RKEY":     (r"rk_live_[0-9a-zA-Z]{24,}",                                                   Severity.CRITICAL),
    "SENDGRID_KEY":    (r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",                                  Severity.CRITICAL),
    "PRIVATE_KEY_PEM": (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",                                    Severity.CRITICAL),
    "DATABASE_URL":    (r"(?i)(?:postgres|mysql|mongodb|redis)://[^:]+:[^@]+@[^\s\"']+",               Severity.CRITICAL),
    "SLACK_TOKEN":     (r"xox[baprs]-[0-9A-Za-z\-]{10,}",                                              Severity.HIGH),
    "TWILIO_TOKEN":    (r"SK[a-f0-9]{32}",                                                              Severity.HIGH),
    "GENERIC_TOKEN":   (r"(?i)(?:api_key|apikey|api_token|auth_token)\s*[=:]\s*['\"][^'\"]{16,}['\"]", Severity.HIGH),
    "GENERIC_SECRET":  (r"(?i)(?:secret|password|passwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]",              Severity.HIGH),
    "JWT_SECRET":      (r"(?i)jwt.{0,15}secret.{0,15}['\"][^'\"]{16,}['\"]",                           Severity.HIGH),
}

IGNORED_EXTENSIONS: frozenset = frozenset({
    ".min.js", ".map", ".lock", ".sum", ".mod", ".snap",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".zip", ".tar", ".gz", ".bz2", ".bin", ".exe", ".dll",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
})

RELEVANT_EXTENSIONS: frozenset = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".go", ".rb", ".php", ".java", ".cs", ".rs", ".cpp", ".c",
    ".env", ".yaml", ".yml", ".toml", ".json", ".ini", ".cfg",
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".config",
    ".tf", ".hcl",
})

COMMENT_PREFIXES: tuple = ("#", "//", "*", "<!--", "/*", "--", "'", ";")


def scan_content_for_secrets(
    content: str, file_path: str,
    repo_name: str, repo_url: str, commit_sha: str,
) -> list[Finding]:
    """
    Escanea el contenido de un archivo con regex.
    NUNCA almacena el valor completo del secreto — solo preview truncado.
    """
    ext = os.path.splitext(file_path)[1].lower()
    if ext in IGNORED_EXTENSIONS:
        return []
    if len(content.encode("utf-8", errors="replace")) > cfg.MAX_FILE_BYTES:
        log.warning("file_skipped_too_large", file=file_path)
        return []

    findings: list[Finding] = []

    for line_num, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(COMMENT_PREFIXES):
            continue

        for name, (pattern, severity) in SECRET_PATTERNS.items():
            try:
                match = re.search(pattern, line)
            except re.error:
                continue
            if not match:
                continue

            raw_val = match.group(0)
            safe    = raw_val[:10] + "***[REDACTED]" if len(raw_val) > 10 else "[REDACTED]"

            findings.append(Finding(
                repo_name=repo_name, repo_url=repo_url, commit_sha=commit_sha,
                file_path=file_path, line_number=line_num,
                severity=severity, category=Category.SECRET,
                description=f"{name} detectado en linea {line_num}",
                raw_match=safe,
            ))
            log.info("secret_matched", pattern=name, file=file_path, line=line_num, sev=severity.value)

    return findings


# ═══════════════════════════════════════════════════════════════════════
# MODULO 2 — LEARNING LOOP
# ═══════════════════════════════════════════════════════════════════════
async def get_learning_context(repo_name: str, category: str) -> str:
    """
    Recupera las ultimas 5 decisiones humanas (PATCHED/DISMISSED/FALSE_POSITIVE)
    para el mismo repo y categoria. Inyecta memoria institucional en el prompt
    de Claude para reducir falsos positivos iteracion tras iteracion.
    """
    log.info("learning_loop_fetch", repo=repo_name, category=category)
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"{cfg.SUPABASE_URL}/rest/v1/findings",
                params={
                    "repo_name": f"eq.{repo_name}",
                    "category":  f"eq.{category}",
                    "status":    "in.(PATCHED,DISMISSED,FALSE_POSITIVE)",
                    "select":    "status,description,file_path,ai_analysis,reviewer_note",
                    "order":     "resolved_at.desc",
                    "limit":     "5",
                },
                headers={"apikey": cfg.SUPABASE_KEY, "Authorization": f"Bearer {cfg.SUPABASE_KEY}"},
            )
            resp.raise_for_status()
            history: list[dict] = resp.json()
    except httpx.HTTPError as exc:
        log.error("learning_loop_failed", error=str(exc))
        return "Sin historial disponible (error de conexion)."

    if not history:
        return f"Sin historial previo para '{repo_name}' / '{category}'. Primer analisis de este tipo."

    labels = {
        "PATCHED":        "ACEPTADO — fix correcto y mergeado",
        "DISMISSED":      "DESCARTADO — no era riesgo real",
        "FALSE_POSITIVE": "FALSO POSITIVO — no tomar accion",
    }
    lines = [f"HISTORIAL ({len(history)} decisiones para '{repo_name}'):"]
    for item in history:
        summary = (item.get("ai_analysis") or {}).get("summary", "sin resumen")
        lines.append(
            f"\n  [{labels.get(item['status'], item['status'])}]\n"
            f"  Archivo: {item.get('file_path','?')}\n"
            f"  Hallazgo: {(item.get('description') or '')[:100]}\n"
            f"  Analisis: {summary[:120]}\n"
            f"  Nota revisor: {item.get('reviewer_note') or 'sin nota'}"
        )
    return "\n".join(lines)


async def record_human_decision(finding_id: str, decision: str, reviewer_note: Optional[str] = None) -> bool:
    """Cierra el Learning Loop: actualiza el finding con la decision del revisor."""
    payload: dict[str, Any] = {"status": decision, "resolved_at": datetime.now(timezone.utc).isoformat()}
    if reviewer_note:
        payload["reviewer_note"] = reviewer_note
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.patch(
                f"{cfg.SUPABASE_URL}/rest/v1/findings",
                params={"id": f"eq.{finding_id}"},
                headers={
                    "apikey": cfg.SUPABASE_KEY, "Authorization": f"Bearer {cfg.SUPABASE_KEY}",
                    "Content-Type": "application/json", "Prefer": "return=minimal",
                },
                json=payload,
            )
            success = resp.status_code == 204
            if success:
                log.info("decision_recorded", finding_id=finding_id, decision=decision)
            else:
                log.error("decision_record_failed", status=resp.status_code)
            return success
    except httpx.HTTPError as exc:
        log.error("decision_http_error", error=str(exc))
        return False


# ═══════════════════════════════════════════════════════════════════════
# MODULO 3 — CLAUDE API
# ═══════════════════════════════════════════════════════════════════════
@retry(
    retry=retry_if_exception_type((httpx.HTTPStatusError, httpx.TimeoutException)),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=2, min=2, max=20),
)
async def _call_claude(prompt: str) -> str:
    async with httpx.AsyncClient(timeout=90.0) as client:
        resp = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": cfg.CLAUDE_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": cfg.CLAUDE_MODEL,
                "max_tokens": cfg.CLAUDE_MAX_TOKENS,
                "messages": [{"role": "user", "content": prompt}],
            },
        )
        resp.raise_for_status()
        return resp.json()["content"][0]["text"]


def _parse_json(raw: str, ctx: str = "") -> dict:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{.*\}", raw, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    log.warning("claude_json_parse_failed", ctx=ctx, preview=raw[:200])
    return {"error": "json_parse_failed", "raw_preview": raw[:200]}


# ═══════════════════════════════════════════════════════════════════════
# MODULO 4 — SUPER PROMPT INJECTOR
# ═══════════════════════════════════════════════════════════════════════
async def analyze_logic_with_claude(
    file_content: str, file_path: str,
    secret_findings: list[Finding], learning_ctx: str,
) -> dict:
    """
    Analiza la logica del archivo con Claude inyectando el contexto
    del Learning Loop y los secretos ya detectados por regex.
    """
    sep = "=" * 60
    truncated = file_content[: cfg.CODE_TRUNCATE_CHARS]
    regex_ctx = json.dumps(
        [{"linea": f.line_number, "tipo": f.category, "desc": f.description} for f in secret_findings],
        indent=2, ensure_ascii=False,
    )

    prompt = f"""Sos un Senior Security Research Engineer especializado en analisis de codigo.

{sep}
MEMORIA INSTITUCIONAL (decisiones pasadas — aprender de esto):
{sep}
{learning_ctx}

{sep}
SECRETOS YA DETECTADOS POR SCANNER REGEX:
{sep}
{regex_ctx if secret_findings else "Ninguno detectado por regex."}

{sep}
ARCHIVO: {file_path}
{sep}
{truncated}

{sep}
INSTRUCCIONES:
{sep}
Busca EXCLUSIVAMENTE:
1. Fallos de logica (IDOR, auth bypass, race conditions, privilege escalation)
2. Inyecciones (SQL, NoSQL, command injection, SSTI, path traversal, XXE)
3. Configs inseguras (CORS abierto, debug=True, HTTP sin TLS, headers faltantes)
4. Deserializacion insegura o inputs sin validar
5. Exposicion de datos en logs o errores

REGLA: Si el historial marca algo como FALSE_POSITIVE o DISMISSED, NO reportes el mismo tipo sin evidencia nueva concreta.

RESPONDE SOLO JSON valido, sin backticks ni texto adicional:
{{
  "logic_flaws": [
    {{
      "line_estimate": <int>,
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "cwe_id": "CWE-XXX",
      "description": "<descripcion tecnica>",
      "evidence": "<fragmento de codigo>",
      "fix_suggestion": "<codigo sugerido>"
    }}
  ],
  "overall_risk_score": <0-10>,
  "summary": "<resumen en 2 oraciones>"
}}"""

    try:
        raw    = await _call_claude(prompt)
        result = _parse_json(raw, ctx=f"analyze:{file_path}")
        log.info("claude_analysis_done", file=file_path,
                 flaws=len(result.get("logic_flaws", [])),
                 risk=result.get("overall_risk_score", 0))
        return result
    except Exception as exc:
        log.error("claude_analysis_error", error=str(exc), file=file_path)
        return {"logic_flaws": [], "overall_risk_score": 0, "summary": f"Error: {exc}"}


async def generate_patch_with_claude(
    file_content: str, file_path: str,
    finding: Finding, learning_ctx: str, ai_analysis: dict,
) -> dict:
    """
    Genera un unified diff aplicable con el parche de seguridad.
    Inyecta el Learning Loop completo para no repetir errores pasados.
    """
    sep       = "=" * 60
    truncated = file_content[: cfg.CODE_TRUNCATE_CHARS]
    flaws_ctx = json.dumps(ai_analysis.get("logic_flaws", [])[:3], indent=2, ensure_ascii=False)

    prompt = f"""Actuate como Senior Security Research Engineer de Google Project Zero.
Genera un PARCHE DE SEGURIDAD de produccion: correcto, minimo, sin romper funcionalidad.

{sep}
MEMORIA INSTITUCIONAL (NO repetir DISMISSED/FALSE_POSITIVE):
{sep}
{learning_ctx}

{sep}
HALLAZGO A RESOLVER:
{sep}
Archivo    : {file_path}
Severidad  : {finding.severity.value}
Categoria  : {finding.category.value}
Descripcion: {finding.description}
Preview    : {finding.raw_match}

{sep}
VULNERABILIDADES LOGICAS ADICIONALES:
{sep}
{flaws_ctx if ai_analysis.get("logic_flaws") else "Ninguna adicional."}

{sep}
CODIGO FUENTE:
{sep}
{truncated}

{sep}
REGLAS ESTRICTAS:
{sep}
1. NO romper la logica de negocio existente.
2. Secretos: reemplazar con os.environ["NOMBRE_VAR"] (Python) o process.env.VAR (Node).
3. Fallos logicos: fail-fast pattern con validacion de inputs.
4. diff_patch debe ser unified diff valido aplicable con `git apply`.
5. Minimo cambio necesario. No refactorizar codigo fuera del hallazgo.
6. Si es falso positivo con alta confianza, indicarlo.

RESPONDE SOLO JSON valido, sin backticks ni texto adicional:
{{
  "is_false_positive": false,
  "confidence": 0.95,
  "explanation": "<descripcion tecnica del fix>",
  "cwe_references": ["CWE-798"],
  "diff_patch": "--- a/{file_path}\\n+++ b/{file_path}\\n@@ -L,N +L,M @@\\n-linea vieja\\n+linea nueva",
  "env_vars_to_add": ["NOMBRE_VAR"],
  "breaking_change_risk": "LOW|MEDIUM|HIGH",
  "test_suggestion": "<como verificar el fix>"
}}"""

    try:
        raw    = await _call_claude(prompt)
        result = _parse_json(raw, ctx=f"patch:{file_path}")
        log.info("patch_generated", file=file_path,
                 is_fp=result.get("is_false_positive"),
                 confidence=result.get("confidence"),
                 risk=result.get("breaking_change_risk"))
        return result
    except Exception as exc:
        log.error("patch_generation_error", error=str(exc), file=file_path)
        return {"error": str(exc), "is_false_positive": False, "confidence": 0.0, "diff_patch": ""}


# ═══════════════════════════════════════════════════════════════════════
# MODULO 5 — GITHUB PR GENERATOR
# ═══════════════════════════════════════════════════════════════════════
_GH_HEADERS = {
    "Authorization":        f"Bearer {cfg.GITHUB_TOKEN}",
    "Accept":               "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "Content-Type":         "application/json",
}


async def _get_default_branch(client: httpx.AsyncClient, repo: str) -> str:
    resp = await client.get(f"https://api.github.com/repos/{repo}", headers=_GH_HEADERS)
    resp.raise_for_status()
    return resp.json().get("default_branch", "main")


@retry(stop=stop_after_attempt(2), wait=wait_exponential(min=2, max=8))
async def create_security_pr(
    repo_full_name: str, file_path: str, patch_result: dict,
    commit_sha: str, all_findings: list[Finding],
) -> Optional[str]:
    """
    Crea un PR en modo DRAFT con el fix de seguridad.
    SIEMPRE draft — requiere revision humana antes de merge.
    Retorna URL del PR o None si es falso positivo.
    """
    if patch_result.get("is_false_positive") and patch_result.get("confidence", 0) >= 0.85:
        log.info("pr_skipped_fp", file=file_path, confidence=patch_result.get("confidence"))
        return None

    branch = f"sentinel/fix-{commit_sha[:8]}-{int(time.time())}"

    async with httpx.AsyncClient(timeout=30.0) as client:
        default_branch = await _get_default_branch(client, repo_full_name)

        ref_resp = await client.get(
            f"https://api.github.com/repos/{repo_full_name}/git/ref/heads/{default_branch}",
            headers=_GH_HEADERS,
        )
        ref_resp.raise_for_status()
        base_sha = ref_resp.json()["object"]["sha"]

        create_resp = await client.post(
            f"https://api.github.com/repos/{repo_full_name}/git/refs",
            headers=_GH_HEADERS,
            json={"ref": f"refs/heads/{branch}", "sha": base_sha},
        )
        if create_resp.status_code not in (201, 422):
            create_resp.raise_for_status()

        findings_table = "\n".join(
            f"| `{f.file_path}:{f.line_number}` | **{f.severity.value}** | {f.category.value} | {f.description[:70]} |"
            for f in all_findings[:8]
        )
        cwe_refs   = ", ".join(f"`{c}`" for c in patch_result.get("cwe_references", []))
        env_vars   = ", ".join(f"`{v}`" for v in patch_result.get("env_vars_to_add", []))
        diff_block = patch_result.get("diff_patch", "Ver analisis adjunto.")

        pr_body = f"""## SENTINEL MIND OS — Parche de Seguridad Automatico

> ESTE PR FUE GENERADO POR IA. Revisa el diff antes de mergear.
> Tu decision (merge/close) alimenta el Learning Loop.

### Metricas del Analisis
| Campo | Valor |
|-------|-------|
| Commit | `{commit_sha[:12]}` |
| Confianza | {patch_result.get('confidence', 0)*100:.0f}% |
| Riesgo breaking | **{patch_result.get('breaking_change_risk','UNKNOWN')}** |
| CWE | {cwe_refs or "N/A"} |

### Hallazgos del Commit
| Ubicacion | Severidad | Tipo | Descripcion |
|-----------|-----------|------|-------------|
{findings_table}

### Explicacion del Fix
{patch_result.get('explanation', 'Ver diff.')}

### Variables de Entorno a Agregar
{env_vars or "Ninguna adicional."}

### Verificacion
{patch_result.get('test_suggestion', 'Ejecutar suite de tests.')}

### Diff del Parche
```diff
{diff_block[:3000]}
```

*Generado por Sentinel Mind OS — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*"""

        pr_resp = await client.post(
            f"https://api.github.com/repos/{repo_full_name}/pulls",
            headers=_GH_HEADERS,
            json={
                "title": f"[Sentinel] {all_findings[0].severity.value} fix — {os.path.basename(file_path)} ({commit_sha[:8]})",
                "body":  pr_body,
                "head":  branch,
                "base":  default_branch,
                "draft": True,
            },
        )
        pr_resp.raise_for_status()
        pr_url = pr_resp.json()["html_url"]
        log.info("pr_created", url=pr_url, repo=repo_full_name)
        return pr_url


# ═══════════════════════════════════════════════════════════════════════
# MODULO 6 — NOTIFICACIONES
# ═══════════════════════════════════════════════════════════════════════
_SEV_EMOJI = {"CRITICAL": "ALERTA CRITICA", "HIGH": "ALTO", "MEDIUM": "MEDIO", "LOW": "BAJO"}
_SEV_COLOR = {"CRITICAL": "#FF0000", "HIGH": "#FF6600", "MEDIUM": "#FFCC00", "LOW": "#00CC00"}


async def notify_telegram(finding: Finding, pr_url: Optional[str] = None) -> None:
    if not cfg.TELEGRAM_TOKEN or not cfg.TELEGRAM_CHAT_ID:
        return
    label = _SEV_EMOJI.get(finding.severity.value, finding.severity.value)
    text  = (
        f"*SENTINEL MIND — {label}*\n\n"
        f"*Repo:* `{finding.repo_name}`\n"
        f"*Archivo:* `{finding.file_path}:{finding.line_number}`\n"
        f"*Tipo:* `{finding.category.value}`\n"
        f"*Hallazgo:* {finding.description}\n"
    )
    if pr_url:
        text += f"\n*Fix:* [Ver PR Draft]({pr_url})"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(
                f"https://api.telegram.org/bot{cfg.TELEGRAM_TOKEN}/sendMessage",
                json={"chat_id": cfg.TELEGRAM_CHAT_ID, "text": text,
                      "parse_mode": "Markdown", "disable_web_page_preview": True},
            )
    except Exception as exc:
        log.warning("telegram_failed", error=str(exc))


async def notify_slack(finding: Finding, pr_url: Optional[str] = None) -> None:
    if not cfg.SLACK_WEBHOOK:
        return
    color = _SEV_COLOR.get(finding.severity.value, "#CCCCCC")
    attachment: dict[str, Any] = {
        "color": color,
        "title": f"Sentinel Mind — {finding.severity.value}",
        "title_link": pr_url or "",
        "fields": [
            {"title": "Repo",        "value": finding.repo_name,                              "short": True},
            {"title": "Severidad",   "value": finding.severity.value,                         "short": True},
            {"title": "Archivo",     "value": f"`{finding.file_path}:{finding.line_number}`", "short": False},
            {"title": "Descripcion", "value": finding.description[:200],                       "short": False},
        ],
        "footer": "Sentinel Mind OS",
        "ts": int(time.time()),
    }
    if pr_url:
        attachment["actions"] = [{"type": "button", "text": "Ver PR de Fix", "url": pr_url, "style": "primary"}]
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(cfg.SLACK_WEBHOOK, json={"attachments": [attachment]})
    except Exception as exc:
        log.warning("slack_failed", error=str(exc))


# ═══════════════════════════════════════════════════════════════════════
# MODULO 7 — SUPABASE PERSISTENCIA
# ═══════════════════════════════════════════════════════════════════════
_SB_HEADERS = lambda: {
    "apikey": cfg.SUPABASE_KEY,
    "Authorization": f"Bearer {cfg.SUPABASE_KEY}",
    "Content-Type": "application/json",
}


async def save_finding(finding: Finding) -> Optional[str]:
    """Persiste el finding en Supabase. Retorna el UUID asignado."""
    payload = {
        "repo_name":    finding.repo_name,
        "repo_url":     finding.repo_url,
        "commit_sha":   finding.commit_sha,
        "file_path":    finding.file_path,
        "line_number":  finding.line_number,
        "severity":     finding.severity.value,
        "category":     finding.category.value,
        "description":  finding.description,
        "raw_match":    finding.raw_match,
        "ai_analysis":  finding.ai_analysis or {},
        "patch_pr_url": finding.patch_pr_url,
        "status":       "OPEN",
    }
    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            resp = await client.post(
                f"{cfg.SUPABASE_URL}/rest/v1/findings",
                headers={**_SB_HEADERS(), "Prefer": "return=representation"},
                json=payload,
            )
            resp.raise_for_status()
            result = resp.json()
            db_id  = result[0]["id"] if result else None
            log.info("finding_saved", id=db_id, sev=finding.severity.value, file=finding.file_path)
            return db_id
    except Exception as exc:
        log.error("supabase_save_failed", error=str(exc), file=finding.file_path)
        return None


async def save_scan_run(result: ScanResult, commit_sha: str) -> None:
    payload = {
        "repo_name": result.repo, "trigger_commit_sha": commit_sha,
        "commits_scanned": result.commits_scanned, "files_scanned": result.files_scanned,
        "findings_total": result.findings_total, "findings_critical": result.findings_critical,
        "findings_high": result.findings_high, "prs_created": len(result.prs_created),
        "errors": result.errors, "duration_ms": result.duration_ms,
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{cfg.SUPABASE_URL}/rest/v1/scan_runs",
                headers={**_SB_HEADERS(), "Prefer": "return=minimal"},
                json=payload,
            )
            resp.raise_for_status()
    except Exception as exc:
        log.error("scan_run_save_failed", error=str(exc))


# ═══════════════════════════════════════════════════════════════════════
# MODULO 8 — SEGURIDAD HMAC (Zero Trust)
# ═══════════════════════════════════════════════════════════════════════
def verify_github_hmac(body: bytes, sig_header: str) -> bool:
    """Verifica firma HMAC-SHA256 de GitHub con timing-safe compare."""
    if not sig_header or not sig_header.startswith("sha256="):
        log.warning("hmac_header_invalid")
        return False
    expected = "sha256=" + hmac.new(
        cfg.GITHUB_WEBHOOK_SECRET.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected.encode(), sig_header.encode())


def verify_internal_token(token: str) -> bool:
    return hmac.compare_digest(
        token.encode("utf-8"), cfg.INTERNAL_TOKEN.encode("utf-8")
    )


# ═══════════════════════════════════════════════════════════════════════
# MODULO 9 — ORQUESTADOR CENTRAL
# ═══════════════════════════════════════════════════════════════════════
async def process_push_event(payload: dict) -> ScanResult:
    """
    Pipeline completo para un evento push de GitHub:
    1.  Extraer archivos modificados de cada commit
    2.  MODULO 1: Secret Scanner (regex en cada archivo)
    3.  MODULO 2: Learning Loop — get_learning_context desde Supabase
    4.  MODULO 4: Claude analiza logica inyectando contexto del Loop
    5.  Si CRITICAL/HIGH: Claude genera unified diff con patch
    6.  Si patch valido: create_security_pr en draft
    7.  Notificaciones paralelas (Telegram + Slack)
    8.  Persistencia en Supabase (findings + scan_run)
    """
    start_ts  = time.monotonic()
    repo      = payload.get("repository", {})
    repo_name = repo.get("full_name", "unknown/unknown")
    repo_url  = repo.get("html_url", "")
    commits   = payload.get("commits", [])
    result    = ScanResult(repo=repo_name)

    structlog.contextvars.bind_contextvars(repo=repo_name)
    log.info("pipeline_started", commits_total=len(commits))

    for commit in commits[: cfg.MAX_COMMITS_PER_EVENT]:
        commit_sha = commit.get("id", "")
        files = list({*commit.get("added", []), *commit.get("modified", [])})[: cfg.MAX_FILES_PER_COMMIT]
        result.commits_scanned += 1

        log.info("processing_commit", sha=commit_sha[:12], files=len(files))

        for file_path in files:
            result.files_scanned += 1
            ext = os.path.splitext(file_path)[1].lower()

            # Obtener contenido del archivo
            try:
                async with httpx.AsyncClient(timeout=20.0) as client:
                    file_resp = await client.get(
                        f"https://api.github.com/repos/{repo_name}/contents/{file_path}",
                        headers={**_GH_HEADERS, "Accept": "application/vnd.github.raw+json"},
                        params={"ref": commit_sha},
                    )
                if file_resp.status_code == 404:
                    continue
                file_resp.raise_for_status()
                file_content = file_resp.text
            except httpx.HTTPError as exc:
                log.warning("file_fetch_failed", file=file_path, error=str(exc))
                result.errors.append(f"fetch:{file_path}:{exc}")
                continue

            # PASO 1: Secret Scanner
            secret_findings = scan_content_for_secrets(file_content, file_path, repo_name, repo_url, commit_sha)

            # PASO 2+3+4: Learning Loop + Claude (solo archivos relevantes)
            should_analyze = bool(secret_findings) or ext in RELEVANT_EXTENSIONS
            ai_analysis: dict = {}
            learning_ctx = "Archivo no relevante para analisis logico."

            if should_analyze:
                learning_secret = await get_learning_context(repo_name, Category.SECRET.value)
                learning_logic  = await get_learning_context(repo_name, Category.LOGIC_FLAW.value)
                learning_ctx    = f"{learning_secret}\n\n{learning_logic}"
                ai_analysis     = await analyze_logic_with_claude(file_content, file_path, secret_findings, learning_ctx)

            # Combinar hallazgos
            all_findings: list[Finding] = list(secret_findings)
            for flaw in ai_analysis.get("logic_flaws", []):
                if flaw.get("severity") in ("CRITICAL", "HIGH", "MEDIUM"):
                    all_findings.append(Finding(
                        repo_name=repo_name, repo_url=repo_url, commit_sha=commit_sha,
                        file_path=file_path, line_number=flaw.get("line_estimate", 0),
                        severity=Severity(flaw["severity"]), category=Category.LOGIC_FLAW,
                        description=f"{flaw.get('cwe_id','CWE-?')}: {flaw.get('description','')}",
                        raw_match=flaw.get("evidence", "")[:80],
                        ai_analysis=ai_analysis,
                    ))

            result.findings_total    += len(all_findings)
            result.findings_critical += sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
            result.findings_high     += sum(1 for f in all_findings if f.severity == Severity.HIGH)

            # PASOS 5-8: Por cada hallazgo CRITICAL/HIGH
            for finding in all_findings:
                pr_url: Optional[str] = None

                if finding.severity in (Severity.CRITICAL, Severity.HIGH):
                    try:
                        # PASO 5: Generar patch con Learning Loop
                        patch_result = await generate_patch_with_claude(
                            file_content, file_path, finding, learning_ctx, ai_analysis
                        )
                        finding.ai_analysis = {**finding.ai_analysis, **patch_result}

                        # PASO 6: Crear PR si no es falso positivo
                        is_fp = patch_result.get("is_false_positive") and patch_result.get("confidence", 0) >= 0.85
                        if not is_fp:
                            try:
                                pr_url = await create_security_pr(
                                    repo_name, file_path, patch_result, commit_sha, all_findings
                                )
                                if pr_url:
                                    finding.patch_pr_url = pr_url
                                    result.prs_created.append(pr_url)
                            except Exception as pr_exc:
                                log.error("pr_failed", error=str(pr_exc), file=file_path)
                                result.errors.append(f"pr:{file_path}:{pr_exc}")

                    except Exception as patch_exc:
                        log.error("patch_failed", error=str(patch_exc), file=file_path)
                        result.errors.append(f"patch:{file_path}:{patch_exc}")

                    # PASO 7: Notificaciones paralelas
                    await asyncio.gather(
                        notify_telegram(finding, pr_url),
                        notify_slack(finding, pr_url),
                        return_exceptions=True,
                    )

                # PASO 8: Persistir todos los hallazgos
                db_id = await save_finding(finding)
                finding.db_id = db_id

    result.duration_ms = int((time.monotonic() - start_ts) * 1000)
    first_sha = commits[0].get("id", "unknown") if commits else "unknown"
    await save_scan_run(result, first_sha)

    structlog.contextvars.unbind_contextvars("repo")
    log.info("pipeline_done", repo=repo_name, files=result.files_scanned,
             findings=result.findings_total, prs=len(result.prs_created),
             duration_ms=result.duration_ms, errors=len(result.errors))
    return result


# ═══════════════════════════════════════════════════════════════════════
# FASTAPI APPLICATION
# ═══════════════════════════════════════════════════════════════════════
app = FastAPI(
    title="Sentinel Mind OS", version="2.0.0",
    description="Security-First Autonomous Agent with Learning Loop",
    docs_url=None, redoc_url=None, openapi_url=None,
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start    = time.monotonic()
    response = await call_next(request)
    log.info("http", method=request.method, path=request.url.path,
             status=response.status_code, ms=int((time.monotonic() - start) * 1000),
             ip=request.client.host if request.client else "?")
    return response


@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "sentinel-mind-os",
                         "version": "2.0.0", "ts": datetime.now(timezone.utc).isoformat()})


@app.post("/scan", status_code=202)
async def webhook_scan(request: Request, background_tasks: BackgroundTasks) -> JSONResponse:
    """
    Entry point del webhook de GitHub (enviado por N8N).
    1. Verifica token interno N8N → Scanner
    2. Verifica firma HMAC-SHA256 de GitHub
    3. Filtra push events en ramas monitoreadas
    4. Lanza pipeline en background (responde <1s para no hacer timeout a GitHub)
    """
    # Validar token interno
    if not verify_internal_token(request.headers.get("X-Internal-Token", "")):
        log.warning("unauthorized_request", ip=request.client.host if request.client else "?")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized")

    body      = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")

    if not verify_github_hmac(body, signature):
        log.warning("invalid_hmac", ip=request.client.host if request.client else "?")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid HMAC")

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"JSON invalido: {exc}")

    event_type = request.headers.get("X-GitHub-Event", "")
    if event_type != "push":
        return JSONResponse({"status": "skipped", "reason": f"Evento '{event_type}' no procesado"})

    ref = payload.get("ref", "")
    monitored_branches = ("main", "master", "develop", "staging")
    if not any(ref.endswith(b) for b in monitored_branches):
        return JSONResponse({"status": "skipped", "reason": f"Branch '{ref}' no monitoreado"})

    background_tasks.add_task(process_push_event, payload)
    repo_name = payload.get("repository", {}).get("full_name", "?")
    log.info("webhook_accepted", repo=repo_name, ref=ref)
    return JSONResponse({"status": "accepted", "repo": repo_name, "ref": ref})


@app.post("/feedback/{finding_id}")
async def human_feedback(finding_id: str, request: Request) -> JSONResponse:
    """
    Cierra el Learning Loop. N8N llama esto cuando un PR de Sentinel
    es mergeado (PATCHED) o cerrado sin merge (DISMISSED/FALSE_POSITIVE).

    Body: {"decision": "PATCHED|DISMISSED|FALSE_POSITIVE", "note": "opcional"}
    """
    if not verify_internal_token(request.headers.get("X-Internal-Token", "")):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="JSON invalido")

    decision = body.get("decision", "").upper()
    if decision not in {"PATCHED", "DISMISSED", "FALSE_POSITIVE"}:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail="decision debe ser PATCHED, DISMISSED o FALSE_POSITIVE")

    success = await record_human_decision(finding_id, decision, body.get("note", ""))
    if not success:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="No se pudo registrar la decision en Supabase")

    return JSONResponse({"status": "learning_loop_updated",
                         "finding_id": finding_id, "decision": decision})


@app.get("/stats")
async def get_stats(request: Request) -> JSONResponse:
    """Estadisticas agregadas para dashboard o N8N."""
    if not verify_internal_token(request.headers.get("X-Internal-Token", "")):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized")
    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            resp = await client.get(
                f"{cfg.SUPABASE_URL}/rest/v1/findings",
                params={"select": "severity,status,category", "limit": "2000"},
                headers=_SB_HEADERS(),
            )
            resp.raise_for_status()
            findings = resp.json()

        stats: dict[str, Any] = {"total": len(findings), "by_severity": {}, "by_status": {}, "by_category": {}}
        for f in findings:
            for key, val in [("by_severity", f.get("severity")), ("by_status", f.get("status")), ("by_category", f.get("category"))]:
                if val:
                    stats[key][val] = stats[key].get(val, 0) + 1
        stats["open_critical"] = sum(1 for f in findings if f.get("status") == "OPEN" and f.get("severity") == "CRITICAL")
        return JSONResponse(stats)
    except Exception as exc:
        log.error("stats_failed", error=str(exc))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))
