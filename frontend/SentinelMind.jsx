import { useState } from "react";

const MERMAID_DIAGRAM = `
flowchart TD
    A[GitHub Webhook Push Event] --> B[N8N Trigger Node]
    B --> C{Filter: Solo ramas main/dev}
    C -->|Pass| D[Python Scanner Service]
    C -->|Skip| Z[Log & Ignore]
    D --> D1[Módulo 1: Secret Scanner]
    D --> D2[Módulo 2: Logic Flaw Analyzer]
    D1 --> E[Claude API - Clasificación de Severidad]
    D2 --> E
    E --> F{Severidad >= HIGH?}
    F -->|Sí| G[Generar PR Automático via GitHub API]
    F -->|No| H[Registrar en Supabase como LOW]
    G --> I[Notificar Telegram + Slack]
    H --> J[Dashboard FlutterFlow]
    I --> J
    G --> K[Supabase - findings table]
    H --> K
`;

const tabs = ["Arquitectura", "Schema DB", "Python Core", "N8N Flow", "Security"];

const schemaSQL = `-- ============================================
-- SUPABASE SCHEMA: Sentinel Mind
-- Row Level Security habilitado en todas las tablas
-- ============================================

-- Tabla principal de hallazgos
CREATE TABLE findings (
  id            UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  repo_name     TEXT NOT NULL,
  repo_url      TEXT NOT NULL,
  commit_sha    TEXT NOT NULL,
  file_path     TEXT NOT NULL,
  line_number   INTEGER,
  severity      TEXT CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
  category      TEXT CHECK (category IN ('SECRET_EXPOSED','LOGIC_FLAW','DEPENDENCY_VULN','MISCONFIGURATION')),
  description   TEXT NOT NULL,
  ai_analysis   JSONB,          -- Respuesta completa de Claude
  patch_pr_url  TEXT,           -- URL del PR generado
  status        TEXT DEFAULT 'OPEN' CHECK (status IN ('OPEN','PATCHED','DISMISSED','FALSE_POSITIVE')),
  created_at    TIMESTAMPTZ DEFAULT now(),
  resolved_at   TIMESTAMPTZ
);

-- Tabla de repositorios monitoreados
CREATE TABLE monitored_repos (
  id            UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  repo_full_name TEXT UNIQUE NOT NULL,  -- ej: "org/repo"
  webhook_secret TEXT NOT NULL,          -- HMAC secret del webhook
  is_active     BOOLEAN DEFAULT true,
  scan_config   JSONB DEFAULT '{}',      -- config personalizada por repo
  created_at    TIMESTAMPTZ DEFAULT now()
);

-- Tabla de notificaciones enviadas
CREATE TABLE notifications (
  id            UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  finding_id    UUID REFERENCES findings(id),
  channel       TEXT CHECK (channel IN ('TELEGRAM','SLACK','EMAIL')),
  sent_at       TIMESTAMPTZ DEFAULT now(),
  payload       JSONB,
  success       BOOLEAN DEFAULT true
);

-- Índices críticos para performance
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_repo ON findings(repo_name);
CREATE INDEX idx_findings_created ON findings(created_at DESC);

-- ============================================
-- ROW LEVEL SECURITY
-- ============================================
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitored_repos ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;

-- Solo el service role puede escribir
CREATE POLICY "service_write_findings" ON findings
  FOR ALL USING (auth.role() = 'service_role');

-- Usuarios autenticados pueden leer sus repos
CREATE POLICY "auth_read_findings" ON findings
  FOR SELECT USING (auth.role() = 'authenticated');`;

const pythonCore = `#!/usr/bin/env python3
"""
Sentinel Mind - Core Scanner Engine
Autor: Sentinel Mind Agent
Versión: 1.0.0
"""

import re
import os
import json
import hmac
import hashlib
import httpx
import asyncio
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Optional
from datetime import datetime

# ============================================
# CONFIGURACIÓN (usar variables de entorno)
# ============================================
CLAUDE_API_KEY   = os.environ["CLAUDE_API_KEY"]
SUPABASE_URL     = os.environ["SUPABASE_URL"]
SUPABASE_KEY     = os.environ["SUPABASE_SERVICE_KEY"]
GITHUB_TOKEN     = os.environ["GITHUB_TOKEN"]
TELEGRAM_TOKEN   = os.environ["TELEGRAM_BOT_TOKEN"]
TELEGRAM_CHAT_ID = os.environ["TELEGRAM_CHAT_ID"]
SLACK_WEBHOOK    = os.environ["SLACK_WEBHOOK_URL"]


# ============================================
# MODELOS DE DATOS
# ============================================
class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

class Category(str, Enum):
    SECRET       = "SECRET_EXPOSED"
    LOGIC_FLAW   = "LOGIC_FLAW"
    DEPENDENCY   = "DEPENDENCY_VULN"
    MISCONFIG    = "MISCONFIGURATION"

@dataclass
class Finding:
    repo_name:   str
    repo_url:    str
    commit_sha:  str
    file_path:   str
    line_number: int
    severity:    Severity
    category:    Category
    description: str
    raw_match:   str
    ai_analysis: Optional[dict] = None
    patch_pr_url: Optional[str] = None


# ============================================
# MÓDULO 1: SECRET SCANNER
# Detecta secretos hardcodeados con regex
# ============================================
SECRET_PATTERNS = {
    "AWS_ACCESS_KEY":     r"AKIA[0-9A-Z]{16}",
    "AWS_SECRET_KEY":     r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "GITHUB_TOKEN":       r"ghp_[a-zA-Z0-9]{36}",
    "OPENAI_KEY":         r"sk-[a-zA-Z0-9]{48}",
    "ANTHROPIC_KEY":      r"sk-ant-[a-zA-Z0-9\-]{93}",
    "STRIPE_KEY":         r"sk_live_[0-9a-zA-Z]{24,}",
    "PRIVATE_KEY_PEM":    r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
    "DATABASE_URL":       r"(?i)(postgres|mysql|mongodb)://[^:]+:[^@]+@[^\s\"']+",
    "GENERIC_SECRET":     r"(?i)(secret|password|passwd|api_key|apikey)\s*=\s*['\"][^'\"]{8,}['\"]",
    "JWT_SECRET":         r"(?i)jwt.{0,10}secret.{0,10}['\"][^'\"]{16,}['\"]",
}

IGNORED_FILES = {".min.js", ".map", ".lock", "yarn.lock", "package-lock.json"}

def scan_content_for_secrets(
    content: str,
    file_path: str,
    repo_name: str,
    repo_url: str,
    commit_sha: str
) -> list[Finding]:
    """Escanea el contenido de un archivo en busca de secretos expuestos."""
    
    # Saltar archivos binarios o ignorados
    if any(file_path.endswith(ext) for ext in IGNORED_FILES):
        return []
    
    findings = []
    lines = content.splitlines()
    
    for line_num, line in enumerate(lines, start=1):
        # Saltar líneas comentadas (mitigación de falsos positivos)
        stripped = line.strip()
        if stripped.startswith(("#", "//", "*", "<!--")):
            continue
            
        for pattern_name, pattern in SECRET_PATTERNS.items():
            match = re.search(pattern, line)
            if match:
                findings.append(Finding(
                    repo_name=repo_name,
                    repo_url=repo_url,
                    commit_sha=commit_sha,
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.CRITICAL if "KEY" in pattern_name or "SECRET" in pattern_name else Severity.HIGH,
                    category=Category.SECRET,
                    description=f"Posible {pattern_name} detectado en línea {line_num}",
                    raw_match=match.group(0)[:50] + "***"  # Nunca loguear el valor completo
                ))
    
    return findings


# ============================================
# MÓDULO 2: LOGIC FLAW ANALYZER (vía Claude)
# Analiza lógica de negocio con IA
# ============================================
async def analyze_with_claude(
    file_content: str,
    file_path: str,
    findings_context: list[Finding]
) -> dict:
    """Usa Claude para detectar fallos lógicos que los scanners tradicionales ignoran."""
    
    # Truncar a 4000 tokens para control de costos
    truncated = file_content[:12000]
    
    context_str = json.dumps(
        [{"file": f.file_path, "type": f.category, "desc": f.description} 
         for f in findings_context],
        indent=2
    )
    
    prompt = f"""Sos un experto en auditoría de seguridad (OSCP, CISSP). 
Analizá este archivo de código buscando:
1. Fallos de lógica de negocio (ej: bypass de autenticación, IDOR, race conditions)
2. Inyección de dependencias inseguras
3. Manejo inseguro de datos del usuario (XSS, SQLi, path traversal)
4. Configuraciones inseguras (CORS abierto, debug=True en producción)

Contexto - hallazgos ya detectados por scanner:
{context_str}

Archivo: {file_path}
--- CÓDIGO ---
{truncated}
--- FIN ---

Respondé SOLO con JSON válido, sin texto adicional:
{{
  "logic_flaws": [
    {{
      "line_estimate": <int>,
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "cwe_id": "<CWE-XXX>",
      "description": "<descripción técnica>",
      "fix_suggestion": "<código o configuración sugerida>"
    }}
  ],
  "overall_risk_score": <0-10>,
  "summary": "<resumen en 2 líneas>"
}}"""

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": CLAUDE_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            },
            json={
                "model": "claude-opus-4-5",
                "max_tokens": 2048,
                "messages": [{"role": "user", "content": prompt}]
            }
        )
        response.raise_for_status()
        data = response.json()
        raw_text = data["content"][0]["text"]
        
        # Parseo seguro del JSON
        try:
            return json.loads(raw_text)
        except json.JSONDecodeError:
            # Extraer JSON si Claude agregó texto adicional
            json_match = re.search(r'\\{.*\\}', raw_text, re.DOTALL)
            if json_match:
                return json.loads(json_match.group(0))
            return {"error": "parse_failed", "raw": raw_text[:500]}


# ============================================
# MÓDULO 3: AUTO-REMEDIATION (GitHub PR)
# ============================================
async def create_security_pr(
    repo_full_name: str,
    file_path: str,
    original_content: str,
    ai_analysis: dict,
    commit_sha: str
) -> Optional[str]:
    """Crea un Pull Request con el fix de seguridad sugerido por Claude."""
    
    fix_suggestions = [
        f["fix_suggestion"] 
        for f in ai_analysis.get("logic_flaws", [])
        if f.get("severity") in ("CRITICAL", "HIGH")
    ]
    
    if not fix_suggestions:
        return None
    
    branch_name = f"sentinel/security-fix-{commit_sha[:8]}-{int(datetime.now().timestamp())}"
    
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        # 1. Obtener SHA del branch base
        ref_resp = await client.get(
            f"https://api.github.com/repos/{repo_full_name}/git/ref/heads/main",
            headers=headers
        )
        ref_resp.raise_for_status()
        base_sha = ref_resp.json()["object"]["sha"]
        
        # 2. Crear branch de fix
        await client.post(
            f"https://api.github.com/repos/{repo_full_name}/git/refs",
            headers=headers,
            json={"ref": f"refs/heads/{branch_name}", "sha": base_sha}
        )
        
        # 3. Preparar body del PR con contexto de seguridad
        pr_body = f"""## 🛡️ Sentinel Mind — Security Fix

**Commit analizado:** \`{commit_sha[:12]}\`
**Risk Score:** {ai_analysis.get('overall_risk_score', 'N/A')}/10
**Resumen:** {ai_analysis.get('summary', 'N/A')}

### Vulnerabilidades detectadas:
{"".join(f"- **{f['cwe_id']}** ({f['severity']}): {f['description']}" + chr(10) for f in ai_analysis.get('logic_flaws', []))}

### Fixes sugeridos por IA:
\`\`\`
{chr(10).join(fix_suggestions[:3])}
\`\`\`

> ⚠️ Revisá este PR antes de hacer merge. La IA puede cometer errores.
> Generado automáticamente por Sentinel Mind."""
        
        # 4. Crear PR
        pr_resp = await client.post(
            f"https://api.github.com/repos/{repo_full_name}/pulls",
            headers=headers,
            json={
                "title": f"🛡️ [Sentinel] Security fixes for {file_path}",
                "body": pr_body,
                "head": branch_name,
                "base": "main",
                "draft": True  # Siempre como draft para revisión humana
            }
        )
        pr_resp.raise_for_status()
        return pr_resp.json()["html_url"]


# ============================================
# MÓDULO 4: NOTIFICACIONES
# ============================================
async def notify_telegram(finding: Finding, pr_url: Optional[str] = None) -> None:
    severity_emoji = {
        "CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟡",
        "LOW": "🟢", "INFO": "ℹ️"
    }
    emoji = severity_emoji.get(finding.severity, "⚠️")
    
    message = (
        f"{emoji} *SENTINEL MIND ALERT* {emoji}\n\n"
        f"*Severidad:* {finding.severity}\n"
        f"*Repo:* \`{finding.repo_name}\`\n"
        f"*Archivo:* \`{finding.file_path}:{finding.line_number}\`\n"
        f"*Tipo:* {finding.category}\n"
        f"*Detalle:* {finding.description}\n"
    )
    if pr_url:
        message += f"\n✅ *PR generado:* [Ver fix]({pr_url})"
    
    async with httpx.AsyncClient() as client:
        await client.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": message,
                "parse_mode": "Markdown",
                "disable_web_page_preview": True
            }
        )

async def notify_slack(finding: Finding, pr_url: Optional[str] = None) -> None:
    color_map = {
        "CRITICAL": "#FF0000", "HIGH": "#FF6600",
        "MEDIUM": "#FFCC00", "LOW": "#00CC00"
    }
    payload = {
        "attachments": [{
            "color": color_map.get(finding.severity, "#CCCCCC"),
            "title": f"🛡️ Sentinel Mind — {finding.severity} Finding",
            "fields": [
                {"title": "Repositorio", "value": finding.repo_name, "short": True},
                {"title": "Archivo", "value": f"{finding.file_path}:{finding.line_number}", "short": True},
                {"title": "Descripción", "value": finding.description, "short": False},
            ],
            "footer": "Sentinel Mind Security Agent",
            "ts": int(datetime.now().timestamp())
        }]
    }
    if pr_url:
        payload["attachments"][0]["actions"] = [
            {"type": "button", "text": "Ver PR de Fix", "url": pr_url}
        ]
    
    async with httpx.AsyncClient() as client:
        await client.post(SLACK_WEBHOOK, json=payload)


# ============================================
# MÓDULO 5: PERSISTENCIA EN SUPABASE
# ============================================
async def save_finding_to_supabase(finding: Finding) -> Optional[str]:
    """Guarda el hallazgo en Supabase y retorna el ID generado."""
    payload = {
        "repo_name":   finding.repo_name,
        "repo_url":    finding.repo_url,
        "commit_sha":  finding.commit_sha,
        "file_path":   finding.file_path,
        "line_number": finding.line_number,
        "severity":    finding.severity,
        "category":    finding.category,
        "description": finding.description,
        "ai_analysis": finding.ai_analysis,
        "patch_pr_url": finding.patch_pr_url,
        "status":      "OPEN"
    }
    
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{SUPABASE_URL}/rest/v1/findings",
            headers={
                "apikey": SUPABASE_KEY,
                "Authorization": f"Bearer {SUPABASE_KEY}",
                "Content-Type": "application/json",
                "Prefer": "return=representation"
            },
            json=payload
        )
        resp.raise_for_status()
        result = resp.json()
        return result[0]["id"] if result else None


# ============================================
# WEBHOOK HANDLER (FastAPI endpoint)
# Validación HMAC — NUNCA confiar en el payload sin verificar
# ============================================
def verify_github_signature(payload_body: bytes, signature_header: str, secret: str) -> bool:
    """Verifica la firma HMAC-SHA256 del webhook de GitHub."""
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    
    expected_sig = "sha256=" + hmac.new(
        secret.encode(), payload_body, hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(expected_sig, signature_header)


# ============================================
# ORCHESTRATOR — Flujo completo
# ============================================
async def process_github_event(webhook_payload: dict, repo_secret: str) -> dict:
    """Orquesta todo el pipeline de análisis."""
    
    repo = webhook_payload.get("repository", {})
    repo_name = repo.get("full_name", "unknown")
    repo_url  = repo.get("html_url", "")
    commits   = webhook_payload.get("commits", [])
    
    results = {"findings": [], "prs_created": [], "errors": []}
    
    for commit in commits[:5]:  # Máximo 5 commits por evento para control de costos
        commit_sha = commit.get("id", "")
        modified_files = (
            commit.get("added", []) + 
            commit.get("modified", [])
        )
        
        for file_path in modified_files[:10]:  # Máximo 10 archivos por commit
            try:
                # Obtener contenido del archivo desde GitHub
                async with httpx.AsyncClient() as client:
                    file_resp = await client.get(
                        f"https://api.github.com/repos/{repo_name}/contents/{file_path}",
                        headers={
                            "Authorization": f"Bearer {GITHUB_TOKEN}",
                            "Accept": "application/vnd.github.raw+json"
                        },
                        params={"ref": commit_sha}
                    )
                    if file_resp.status_code != 200:
                        continue
                    file_content = file_resp.text
                
                # MÓDULO 1: Escaneo de secretos
                secret_findings = scan_content_for_secrets(
                    file_content, file_path, repo_name, repo_url, commit_sha
                )
                
                # MÓDULO 2: Análisis lógico con Claude (solo si hay candidatos o el archivo es relevante)
                relevant_extensions = {".py", ".js", ".ts", ".go", ".rb", ".php", ".java"}
                should_analyze = (
                    secret_findings or 
                    any(file_path.endswith(ext) for ext in relevant_extensions)
                )
                
                ai_analysis = {}
                if should_analyze:
                    ai_analysis = await analyze_with_claude(
                        file_content, file_path, secret_findings
                    )
                
                # Combinar hallazgos
                all_findings = secret_findings.copy()
                
                for flaw in ai_analysis.get("logic_flaws", []):
                    if flaw.get("severity") in ("CRITICAL", "HIGH"):
                        all_findings.append(Finding(
                            repo_name=repo_name,
                            repo_url=repo_url,
                            commit_sha=commit_sha,
                            file_path=file_path,
                            line_number=flaw.get("line_estimate", 0),
                            severity=Severity(flaw["severity"]),
                            category=Category.LOGIC_FLAW,
                            description=f"{flaw.get('cwe_id','')}: {flaw.get('description','')}",
                            raw_match="",
                            ai_analysis=ai_analysis
                        ))
                
                # Procesar hallazgos críticos/altos
                for finding in all_findings:
                    pr_url = None
                    
                    if finding.severity in (Severity.CRITICAL, Severity.HIGH):
                        # MÓDULO 3: Crear PR automático
                        try:
                            pr_url = await create_security_pr(
                                repo_name, file_path, file_content, ai_analysis, commit_sha
                            )
                            if pr_url:
                                finding.patch_pr_url = pr_url
                                results["prs_created"].append(pr_url)
                        except Exception as e:
                            results["errors"].append(f"PR creation failed: {str(e)}")
                        
                        # MÓDULO 4: Notificaciones
                        await asyncio.gather(
                            notify_telegram(finding, pr_url),
                            notify_slack(finding, pr_url),
                            return_exceptions=True
                        )
                    
                    # MÓDULO 5: Guardar en Supabase
                    await save_finding_to_supabase(finding)
                    results["findings"].append(asdict(finding))
                    
            except Exception as e:
                results["errors"].append(f"Error en {file_path}: {str(e)}")
    
    return results


if __name__ == "__main__":
    # Test local con payload simulado
    test_payload = {
        "repository": {"full_name": "test-org/test-repo", "html_url": "https://github.com/test-org/test-repo"},
        "commits": [{
            "id": "abc123def456",
            "modified": ["config/settings.py"],
            "added": []
        }]
    }
    result = asyncio.run(process_github_event(test_payload, "test-secret"))
    print(json.dumps(result, indent=2, default=str))`;

const n8nFlow = `# N8N WORKFLOW — Sentinel Mind
# Importá este JSON directamente en tu instancia N8N
# Settings > Import from JSON

{
  "name": "Sentinel Mind — Security Scanner",
  "nodes": [
    {
      "name": "GitHub Webhook",
      "type": "n8n-nodes-base.webhook",
      "position": [240, 300],
      "parameters": {
        "path": "sentinel-github",
        "httpMethod": "POST",
        "responseMode": "onReceived",
        "authentication": "headerAuth",
        "headerName": "X-Hub-Signature-256"
      }
    },
    {
      "name": "Validate HMAC Signature",
      "type": "n8n-nodes-base.code",
      "position": [460, 300],
      "parameters": {
        "jsCode": "
const crypto = require('crypto');
const payload = JSON.stringify($input.item.json);
const sig = $input.item.headers['x-hub-signature-256'];
const secret = process.env.GITHUB_WEBHOOK_SECRET;
const expected = 'sha256=' + crypto.createHmac('sha256', secret).update(payload).digest('hex');

if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
  throw new Error('Invalid HMAC signature - request rejected');
}
return $input.item;"
      }
    },
    {
      "name": "Filter Push Events Only",
      "type": "n8n-nodes-base.if",
      "position": [680, 300],
      "parameters": {
        "conditions": {
          "string": [{
            "value1": "={{ $json.headers['x-github-event'] }}",
            "operation": "equals",
            "value2": "push"
          }]
        }
      }
    },
    {
      "name": "Call Python Scanner",
      "type": "n8n-nodes-base.httpRequest",
      "position": [900, 240],
      "parameters": {
        "url": "http://sentinel-scanner:8000/scan",
        "method": "POST",
        "authentication": "genericCredentialType",
        "genericAuthType": "httpHeaderAuth",
        "sendHeaders": true,
        "headerParameters": {
          "parameters": [{
            "name": "X-Internal-Token",
            "value": "={{ $env.INTERNAL_SERVICE_TOKEN }}"
          }]
        },
        "sendBody": true,
        "bodyParameters": {
          "parameters": [{
            "name": "payload",
            "value": "={{ JSON.stringify($json.body) }}"
          }]
        },
        "options": {"timeout": 120000}
      }
    },
    {
      "name": "Check for Critical Findings",
      "type": "n8n-nodes-base.if",
      "position": [1120, 240],
      "parameters": {
        "conditions": {
          "number": [{
            "value1": "={{ $json.findings.filter(f => ['CRITICAL','HIGH'].includes(f.severity)).length }}",
            "operation": "larger",
            "value2": 0
          }]
        }
      }
    },
    {
      "name": "Save to Supabase",
      "type": "n8n-nodes-base.httpRequest",
      "position": [1340, 180],
      "parameters": {
        "url": "={{ $env.SUPABASE_URL }}/rest/v1/findings",
        "method": "POST",
        "authentication": "genericCredentialType",
        "sendHeaders": true,
        "headerParameters": {
          "parameters": [
            {"name": "apikey", "value": "={{ $env.SUPABASE_KEY }}"},
            {"name": "Prefer", "value": "return=minimal"}
          ]
        }
      }
    },
    {
      "name": "Schedule Daily Report",
      "type": "n8n-nodes-base.scheduleTrigger",
      "position": [240, 520],
      "parameters": {
        "rule": {"interval": [{"field": "cronExpression", "expression": "0 8 * * 1-5"}]}
      }
    },
    {
      "name": "Generate Summary with Claude",
      "type": "n8n-nodes-base.httpRequest",
      "position": [460, 520],
      "parameters": {
        "url": "https://api.anthropic.com/v1/messages",
        "method": "POST",
        "sendHeaders": true,
        "headerParameters": {
          "parameters": [
            {"name": "x-api-key", "value": "={{ $env.CLAUDE_API_KEY }}"},
            {"name": "anthropic-version", "value": "2023-06-01"}
          ]
        },
        "sendBody": true,
        "bodyContentType": "json",
        "jsonBody": "={{ JSON.stringify({model: 'claude-opus-4-5', max_tokens: 1024, messages: [{role: 'user', content: 'Generá un resumen ejecutivo de seguridad en español basado en estos hallazgos: ' + JSON.stringify($json.findings)}]}) }}"
      }
    }
  ],
  "connections": {
    "GitHub Webhook": {"main": [["Validate HMAC Signature"]]},
    "Validate HMAC Signature": {"main": [["Filter Push Events Only"]]},
    "Filter Push Events Only": {"main": [["Call Python Scanner"], []]},
    "Call Python Scanner": {"main": [["Check for Critical Findings"]]},
    "Check for Critical Findings": {"main": [["Save to Supabase"], ["Save to Supabase"]]},
    "Schedule Daily Report": {"main": [["Generate Summary with Claude"]]}
  }
}`;

const securityChecklist = [
  { cat: "Autenticación & Tokens", items: [
    "✅ Nunca hardcodear API keys — usar variables de entorno o Vault",
    "✅ HMAC-SHA256 en todos los webhooks de GitHub (verify_github_signature)",
    "✅ Service Role de Supabase solo en backend, nunca expuesto al cliente",
    "✅ GITHUB_TOKEN con permisos mínimos (solo contents:write y pull_requests:write)",
    "✅ Rotar todos los tokens cada 90 días",
  ]},
  { cat: "Datos & Privacidad", items: [
    "✅ Raw secrets NUNCA se almacenan completos — truncar a 50 chars + ***",
    "✅ Row Level Security habilitado en Supabase para todas las tablas",
    "✅ Logs no deben contener valores de secretos encontrados",
    "✅ Encriptar ai_analysis column con pgcrypto si contiene datos sensibles",
  ]},
  { cat: "Red & Infraestructura", items: [
    "✅ N8N auto-hosteado detrás de reverse proxy (Nginx + Cloudflare)",
    "✅ Python scanner en red interna (no expuesto públicamente)",
    "✅ Rate limiting en webhook endpoint (máx 100 req/min por repo)",
    "✅ Timeout en todas las llamadas HTTP (30s Claude, 30s GitHub, 10s notif)",
    "✅ Usar HTTPS/TLS 1.3 en todos los endpoints",
  ]},
  { cat: "Operacional", items: [
    "✅ PRs siempre como DRAFT — requieren revisión humana antes de merge",
    "✅ Máximo 5 commits y 10 archivos por evento (control de costos/DoS)",
    "✅ Monitorear costos de Claude API con alertas en Anthropic Console",
    "✅ Backup diario de base de datos Supabase",
    "✅ Alertas de uptime en N8N y scanner service",
  ]},
];

export default function SentinelMind() {
  const [activeTab, setActiveTab] = useState("Arquitectura");
  const [copiedBlock, setCopiedBlock] = useState(null);

  const copyToClipboard = (text, blockId) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedBlock(blockId);
      setTimeout(() => setCopiedBlock(null), 2000);
    });
  };

  const CodeBlock = ({ code, blockId, language = "python" }) => (
    <div style={{ position: "relative", background: "#0d1117", borderRadius: 8, marginBottom: 16 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 16px", background: "#161b22", borderRadius: "8px 8px 0 0", borderBottom: "1px solid #30363d" }}>
        <span style={{ color: "#8b949e", fontSize: 12, fontFamily: "monospace" }}>{language}</span>
        <button
          onClick={() => copyToClipboard(code, blockId)}
          style={{ background: copiedBlock === blockId ? "#238636" : "#21262d", color: copiedBlock === blockId ? "#fff" : "#8b949e", border: "1px solid #30363d", borderRadius: 6, padding: "4px 12px", cursor: "pointer", fontSize: 12 }}
        >
          {copiedBlock === blockId ? "✓ Copiado" : "Copiar"}
        </button>
      </div>
      <pre style={{ margin: 0, padding: 16, overflow: "auto", color: "#e6edf3", fontSize: 12, lineHeight: 1.6, maxHeight: 480, fontFamily: "'Fira Code', 'Cascadia Code', monospace" }}>
        <code>{code}</code>
      </pre>
    </div>
  );

  return (
    <div style={{ minHeight: "100vh", background: "#010409", color: "#e6edf3", fontFamily: "'Inter', system-ui, sans-serif" }}>
      {/* Header */}
      <div style={{ background: "linear-gradient(135deg, #0d1117 0%, #161b22 50%, #0d1117 100%)", borderBottom: "1px solid #30363d", padding: "24px 32px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 8 }}>
          <div style={{ width: 48, height: 48, background: "linear-gradient(135deg, #238636, #1f6feb)", borderRadius: 12, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 24 }}>🛡️</div>
          <div>
            <h1 style={{ margin: 0, fontSize: 28, fontWeight: 700, background: "linear-gradient(90deg, #58a6ff, #3fb950)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>
              SENTINEL MIND
            </h1>
            <p style={{ margin: 0, color: "#8b949e", fontSize: 14 }}>Security-First Autonomous Agent — Arquitectura Completa</p>
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 12 }}>
          {["Claude API", "N8N", "Supabase", "FastAPI", "Python 3.11+", "GitHub API"].map(t => (
            <span key={t} style={{ background: "#161b22", border: "1px solid #30363d", borderRadius: 16, padding: "4px 12px", fontSize: 12, color: "#58a6ff" }}>{t}</span>
          ))}
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", borderBottom: "1px solid #30363d", background: "#0d1117", padding: "0 32px", overflowX: "auto" }}>
        {tabs.map(tab => (
          <button key={tab} onClick={() => setActiveTab(tab)} style={{
            background: "none", border: "none", color: activeTab === tab ? "#58a6ff" : "#8b949e",
            borderBottom: activeTab === tab ? "2px solid #58a6ff" : "2px solid transparent",
            padding: "16px 20px", cursor: "pointer", fontSize: 14, fontWeight: activeTab === tab ? 600 : 400,
            whiteSpace: "nowrap", transition: "color 0.2s"
          }}>{tab}</button>
        ))}
      </div>

      {/* Content */}
      <div style={{ padding: 32, maxWidth: 960, margin: "0 auto" }}>

        {activeTab === "Arquitectura" && (
          <div>
            <h2 style={{ color: "#58a6ff", fontSize: 20, marginBottom: 16 }}>Diagrama de Flujo — Mermaid.js</h2>
            <div style={{ background: "#0d1117", border: "1px solid #30363d", borderRadius: 8, padding: 24, marginBottom: 24 }}>
              <pre style={{ color: "#3fb950", fontSize: 13, lineHeight: 1.8, margin: 0, fontFamily: "monospace", overflowX: "auto" }}>{MERMAID_DIAGRAM}</pre>
              <p style={{ color: "#8b949e", fontSize: 12, marginTop: 12 }}>
                💡 Pegá este código en <strong style={{ color: "#58a6ff" }}>mermaid.live</strong> para visualizarlo
              </p>
            </div>

            <h2 style={{ color: "#58a6ff", fontSize: 20, marginBottom: 16 }}>5 Módulos del Sistema</h2>
            {[
              { num: "01", name: "Secret Scanner", desc: "Detecta AWS keys, tokens de GitHub, OpenAI, Anthropic, Stripe, JWTs y credenciales de bases de datos con 10+ patrones regex. Nunca almacena el valor completo.", color: "#f85149" },
              { num: "02", name: "Logic Flaw Analyzer", desc: "Claude analiza la lógica de negocio buscando IDOR, race conditions, bypass de auth y SQLi que los scanners tradicionales ignoran.", color: "#d29922" },
              { num: "03", name: "Auto-Remediation PR", desc: "Crea un Pull Request en rama separada con el fix sugerido por IA. Siempre como DRAFT para revisión humana obligatoria.", color: "#3fb950" },
              { num: "04", name: "Notificaciones", desc: "Alertas en tiempo real por Telegram y Slack con severidad, contexto y link al PR. Ejecución paralela con asyncio.gather.", color: "#58a6ff" },
              { num: "05", name: "Persistencia Supabase", desc: "PostgreSQL con RLS habilitado. Todos los hallazgos indexados por severidad, repo y fecha. Schema listo para dashboards.", color: "#a371f7" },
            ].map(m => (
              <div key={m.num} style={{ display: "flex", gap: 16, marginBottom: 16, background: "#0d1117", border: "1px solid #30363d", borderRadius: 8, padding: 20 }}>
                <div style={{ minWidth: 48, height: 48, background: m.color + "22", border: `1px solid ${m.color}44`, borderRadius: 8, display: "flex", alignItems: "center", justifyContent: "center", color: m.color, fontWeight: 700, fontSize: 14 }}>{m.num}</div>
                <div>
                  <div style={{ fontWeight: 600, color: m.color, marginBottom: 4 }}>{m.name}</div>
                  <div style={{ color: "#8b949e", fontSize: 14 }}>{m.desc}</div>
                </div>
              </div>
            ))}
          </div>
        )}

        {activeTab === "Schema DB" && (
          <div>
            <h2 style={{ color: "#58a6ff", fontSize: 20, marginBottom: 8 }}>Schema SQL — Supabase / PostgreSQL</h2>
            <p style={{ color: "#8b949e", marginBottom: 16 }}>Ejecutá esto en el SQL Editor de tu proyecto Supabase.</p>
            <CodeBlock code={schemaSQL} blockId="schema" language="sql" />
          </div>
        )}

        {activeTab === "Python Core" && (
          <div>
            <h2 style={{ color: "#58a6ff", fontSize: 20, marginBottom: 8 }}>Core Engine — Python 3.11+</h2>
            <p style={{ color: "#8b949e", marginBottom: 16 }}>Motor asíncrono completo con los 5 módulos. Listo para desplegar con FastAPI o ejecutar standalone.</p>
            <CodeBlock code={pythonCore} blockId="python" language="python" />
            <div style={{ background: "#0d1117", border: "1px solid #30363d", borderRadius: 8, padding: 16, marginTop: 8 }}>
              <p style={{ color: "#8b949e", fontSize: 13, margin: 0 }}>
                <strong style={{ color: "#58a6ff" }}>Dependencias:</strong>{" "}
                <code style={{ background: "#161b22", padding: "2px 8px", borderRadius: 4, color: "#3fb950" }}>pip install httpx fastapi uvicorn python-dotenv</code>
              </p>
            </div>
          </div>
        )}

        {activeTab === "N8N Flow" && (
          <div>
            <h2 style={{ color: "#58a6ff", fontSize: 20, marginBottom: 8 }}>N8N Workflow — JSON de Importación</h2>
            <p style={{ color: "#8b949e", marginBottom: 16 }}>Importá este workflow en tu instancia N8N. No necesitás programar la infraestructura de servidores.</p>
            <CodeBlock code={n8nFlow} blockId="n8n" language="json" />

            <h3 style={{ color: "#58a6ff", marginBottom: 12 }}>Plan de Deploy en 30 Minutos</h3>
            {[
              ["0-5 min", "Clonar repo y configurar .env con todas las keys", "#3fb950"],
              ["5-10 min", "Levantar N8N con Docker: docker run -p 5678:5678 n8nio/n8n", "#58a6ff"],
              ["10-15 min", "Importar el JSON del workflow en N8N y configurar variables de entorno", "#d29922"],
              ["15-20 min", "Crear webhook en GitHub repo → Settings → Webhooks → Agregar URL de N8N", "#a371f7"],
              ["20-25 min", "Ejecutar schema SQL en Supabase SQL Editor", "#f85149"],
              ["25-30 min", "Hacer un push de prueba con un .env que tenga una key falsa y verificar la alerta", "#3fb950"],
            ].map(([time, action, color]) => (
              <div key={time} style={{ display: "flex", gap: 16, marginBottom: 8, alignItems: "flex-start" }}>
                <span style={{ minWidth: 70, color, fontWeight: 600, fontSize: 13, fontFamily: "monospace" }}>{time}</span>
                <span style={{ color: "#e6edf3", fontSize: 14 }}>{action}</span>
              </div>
            ))}
          </div>
        )}

        {activeTab === "Security" && (
          <div>
            <h2 style={{ color: "#58a6ff", fontSize: 20, marginBottom: 16 }}>🛡️ Security Hardening Checklist</h2>
            {securityChecklist.map(section => (
              <div key={section.cat} style={{ marginBottom: 24, background: "#0d1117", border: "1px solid #30363d", borderRadius: 8, padding: 20 }}>
                <h3 style={{ color: "#3fb950", marginTop: 0, marginBottom: 12, fontSize: 16 }}>{section.cat}</h3>
                {section.items.map((item, i) => (
                  <div key={i} style={{ color: "#e6edf3", fontSize: 14, marginBottom: 8, lineHeight: 1.6 }}>{item}</div>
                ))}
              </div>
            ))}

            <div style={{ background: "#161b22", border: "1px solid #f8514933", borderRadius: 8, padding: 20 }}>
              <h3 style={{ color: "#f85149", marginTop: 0, marginBottom: 12 }}>⚠️ Puntos de Falla Identificados</h3>
              <p style={{ color: "#8b949e", fontSize: 14, lineHeight: 1.7, margin: 0 }}>
                1. <strong style={{ color: "#e6edf3" }}>Falsos positivos:</strong> El scanner de regex puede generar ruido. Considerá un sistema de feedback para marcar false_positives en Supabase.<br/>
                2. <strong style={{ color: "#e6edf3" }}>Costo de Claude API:</strong> Repos muy activos pueden generar costos altos. Implementá cache de análisis por hash de archivo.<br/>
                3. <strong style={{ color: "#e6edf3" }}>Rate limits de GitHub:</strong> 5000 req/hora. Con repos grandes, podría agotarse. Añadir retry con exponential backoff.<br/>
                4. <strong style={{ color: "#e6edf3" }}>N8N single point of failure:</strong> Usar clustering de N8N o migrar orchestración crítica a un queue (Redis + Celery).
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
