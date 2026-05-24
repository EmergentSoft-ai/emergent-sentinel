import { useState, useEffect, useRef } from "react";

// ─── DESIGN TOKENS ────────────────────────────────────────────────
const C = {
  bg:      "#03060A",
  surface: "#080D14",
  card:    "#0C1520",
  border:  "#1A2535",
  borderHi:"#243448",
  green:   "#00FF88",
  greenDim:"#00CC6A",
  red:     "#FF3355",
  amber:   "#FFB020",
  blue:    "#1E90FF",
  cyan:    "#00D4FF",
  purple:  "#9B59FF",
  text:    "#E8F4F0",
  muted:   "#4A6A5A",
  mutedHi: "#7A9A8A",
};

// ─── CONTENT DATA ─────────────────────────────────────────────────
const DOCKER_COMPOSE = `version: '3.8'

services:
  db:
    image: postgres:15-alpine
    restart: always
    environment:
      POSTGRES_DB: sentinel_db
      POSTGRES_USER: sentinel
      POSTGRES_PASSWORD: \${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U sentinel"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - sentinel_internal  # NO expuesto al exterior

  n8n:
    image: n8nio/n8n:latest
    restart: always
    ports:
      - "127.0.0.1:5678:5678"  # Solo localhost — Nginx hace el proxy
    environment:
      - N8N_ENCRYPTION_KEY=\${N8N_KEY}
      - N8N_BASIC_AUTH_ACTIVE=true
      - N8N_BASIC_AUTH_USER=\${N8N_USER}
      - N8N_BASIC_AUTH_PASSWORD=\${N8N_PASSWORD}
      - GITHUB_WEBHOOK_SECRET=\${GITHUB_SECRET}
      - EXECUTIONS_DATA_PRUNE=true
      - EXECUTIONS_DATA_MAX_AGE=48
    volumes:
      - n8n_data:/home/node/.n8n
    depends_on:
      db:
        condition: service_healthy
    networks:
      - sentinel_internal
      - sentinel_external

  scanner:
    build:
      context: .
      dockerfile: Dockerfile
    restart: always
    environment:
      - CLAUDE_API_KEY=\${CLAUDE_API_KEY}
      - GITHUB_TOKEN=\${GITHUB_TOKEN}
      - SUPABASE_URL=\${SUPABASE_URL}
      - SUPABASE_SERVICE_KEY=\${SUPABASE_SERVICE_KEY}
      - TELEGRAM_BOT_TOKEN=\${TELEGRAM_BOT_TOKEN}
      - TELEGRAM_CHAT_ID=\${TELEGRAM_CHAT_ID}
      - SLACK_WEBHOOK_URL=\${SLACK_WEBHOOK_URL}
      - INTERNAL_SERVICE_TOKEN=\${INTERNAL_SERVICE_TOKEN}
    depends_on:
      db:
        condition: service_healthy
    networks:
      - sentinel_internal  # Nunca expuesto al exterior

  nginx:
    image: nginx:alpine
    restart: always
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/ssl/sentinel:ro
    depends_on:
      - n8n
    networks:
      - sentinel_external

volumes:
  postgres_data:
  n8n_data:

networks:
  sentinel_internal:
    driver: bridge
    internal: true   # Sin acceso a internet — Zero Trust
  sentinel_external:
    driver: bridge`;

const LEARNING_LOOP = `#!/usr/bin/env python3
"""
Sentinel Mind — Learning Loop (Módulo de Metacognición)
Consulta el historial de decisiones humanas para contextualizar
cada nuevo análisis y reducir falsos positivos.
"""

import os
import httpx
from dataclasses import dataclass
from typing import Optional

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_SERVICE_KEY"]
CLAUDE_API_KEY = os.environ["CLAUDE_API_KEY"]


# ── 1. Recuperar contexto de aprendizaje desde Supabase ───────────
async def get_learning_context(repo_name: str, category: str) -> str:
    """
    Consulta PRs anteriores (PATCHED/DISMISSED) para el mismo repo
    y categoría. Permite a Claude aprender del feedback humano.
    """
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(
            f"{SUPABASE_URL}/rest/v1/findings",
            params={
                "repo_name": f"eq.{repo_name}",
                "category":  f"eq.{category}",
                "status":    "in.(PATCHED,DISMISSED)",
                "select":    "category,status,description,ai_analysis",
                "order":     "created_at.desc",
                "limit":     "5",
            },
            headers={
                "apikey":        SUPABASE_KEY,
                "Authorization": f"Bearer {SUPABASE_KEY}",
            },
        )
        resp.raise_for_status()
        history = resp.json()

    if not history:
        return "Sin historial previo para este repositorio y categoría."

    lines = ["DECISIONES PASADAS (aprender de estas):"]
    for item in history:
        decision = "✅ APROBADO (merge)" if item["status"] == "PATCHED" else "❌ RECHAZADO (falso positivo)"
        summary = (item.get("ai_analysis") or {}).get("summary", "sin resumen")
        lines.append(
            f"  - [{item['category']}] {decision}\n"
            f"    Descripción: {item['description'][:120]}\n"
            f"    Contexto IA: {summary[:120]}"
        )
    return "\n".join(lines)


# ── 2. Registrar feedback humano (cierra el loop) ─────────────────
async def record_human_decision(
    finding_id: str,
    decision: str,  # "PATCHED" | "DISMISSED" | "FALSE_POSITIVE"
    reviewer_note: Optional[str] = None,
) -> bool:
    """
    Cuando un humano acepta o rechaza un PR, esta función actualiza
    el finding en Supabase para alimentar el aprendizaje futuro.
    Llamar desde el webhook de GitHub PR events.
    """
    from datetime import datetime, timezone

    payload = {
        "status":      decision,
        "resolved_at": datetime.now(timezone.utc).isoformat(),
    }
    if reviewer_note:
        payload["ai_analysis"] = {"reviewer_note": reviewer_note}

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.patch(
            f"{SUPABASE_URL}/rest/v1/findings",
            params={"id": f"eq.{finding_id}"},
            headers={
                "apikey":        SUPABASE_KEY,
                "Authorization": f"Bearer {SUPABASE_KEY}",
                "Content-Type":  "application/json",
                "Prefer":        "return=minimal",
            },
            json=payload,
        )
        return resp.status_code == 204


# ── 3. Super Prompt Injector — Claude con contexto de aprendizaje ──
async def generate_security_patch(
    file_content:  str,
    file_path:     str,
    finding_desc:  str,
    learning_ctx:  str,
    severity:      str,
) -> dict:
    """
    Envía el Super Prompt a Claude con todo el contexto necesario
    para generar un parche de seguridad preciso y aprendido.
    """
    # Truncar código para control de costos
    truncated_code = file_content[:10_000]

    prompt = f"""Actuá como un Senior Security Research Engineer de Google Project Zero.
Tu misión es generar un PARCHE DE SEGURIDAD de producción.

══════════════════════════════════════════
MEMORIA INSTITUCIONAL (aprendé de esto):
══════════════════════════════════════════
{learning_ctx}

══════════════════════════════════════════
HALLAZGO A RESOLVER:
══════════════════════════════════════════
Archivo    : {file_path}
Severidad  : {severity}
Descripción: {finding_desc}

══════════════════════════════════════════
CÓDIGO A ANALIZAR:
══════════════════════════════════════════
{truncated_code}

══════════════════════════════════════════
REGLAS DE GENERACIÓN:
══════════════════════════════════════════
1. NO rompas la lógica de negocio existente.
2. Secretos expuestos → migrar a variables de entorno con os.environ[].
3. Fallos lógicos → implementar validaciones con fail-fast pattern.
4. Si el historial marca algo como RECHAZADO, no repitas ese enfoque.
5. Generá el mínimo cambio necesario (principio de menor privilegio).

RESPONDÉ SOLO con JSON válido, sin backticks ni texto adicional:
{{
  "is_false_positive": false,
  "confidence": 0.95,
  "explanation": "Descripción técnica del fix en 2-3 oraciones",
  "cwe_references": ["CWE-798", "CWE-312"],
  "diff_patch": "--- a/{file_path}\\n+++ b/{file_path}\\n@@ ... @@\\n...",
  "env_vars_to_add": ["SECRET_KEY", "API_TOKEN"],
  "breaking_change_risk": "LOW|MEDIUM|HIGH",
  "test_suggestion": "Cómo verificar que el fix funciona"
}}"""

    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key":         CLAUDE_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type":      "application/json",
            },
            json={
                "model":      "claude-opus-4-5",
                "max_tokens": 2048,
                "messages":   [{"role": "user", "content": prompt}],
            },
        )
        resp.raise_for_status()
        import json, re
        raw = resp.json()["content"][0]["text"]
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            match = re.search(r'\\{.*\\}', raw, re.DOTALL)
            return json.loads(match.group(0)) if match else {"error": "parse_failed"}


# ── 4. Pipeline completo con Learning Loop ────────────────────────
async def full_analysis_with_learning(
    repo_name:    str,
    file_path:    str,
    file_content: str,
    finding_desc: str,
    category:     str,
    severity:     str,
) -> dict:
    """Orquesta: aprendizaje → análisis → parche → persistencia."""

    # Paso 1: Recuperar memoria institucional
    learning_ctx = await get_learning_context(repo_name, category)

    # Paso 2: Generar parche con contexto completo
    patch_result = await generate_security_patch(
        file_content, file_path, finding_desc, learning_ctx, severity
    )

    # Paso 3: Si Claude detecta falso positivo con alta confianza, no crear PR
    if patch_result.get("is_false_positive") and patch_result.get("confidence", 0) > 0.85:
        return {
            "action":  "SKIPPED_FALSE_POSITIVE",
            "reason":  patch_result.get("explanation"),
            "patch":   None,
        }

    return {
        "action":        "PATCH_GENERATED",
        "patch":         patch_result,
        "learning_used": learning_ctx != "Sin historial previo para este repositorio y categoría.",
    }`;

const ENV_FILE = `# ══════════════════════════════════════════
# SENTINEL MIND — Variables de Entorno
# NUNCA commitear este archivo. Agregar a .gitignore
# ══════════════════════════════════════════

# ── IA ────────────────────────────────────
CLAUDE_API_KEY=sk-ant-xxxxxxxxxxxxxxxxxxxxxxxxxxxx

# ── GitHub ────────────────────────────────
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx
GITHUB_WEBHOOK_SECRET=genera_con_openssl_rand_hex_32

# ── Base de Datos ─────────────────────────
DB_PASSWORD=usa_un_password_muy_largo_y_random
SUPABASE_URL=https://tu-proyecto.supabase.co
SUPABASE_SERVICE_KEY=eyJhbxxxxxxxxxxxxxx

# ── N8N ───────────────────────────────────
N8N_KEY=genera_con_openssl_rand_base64_32
N8N_USER=admin
N8N_PASSWORD=otro_password_fuerte

# ── Notificaciones ────────────────────────
TELEGRAM_BOT_TOKEN=123456789:AAxxxxxxxxxxxxxxxxxxxxxxxx
TELEGRAM_CHAT_ID=-1001234567890
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxx/yyy/zzz

# ── Seguridad Interna ─────────────────────
INTERNAL_SERVICE_TOKEN=genera_con_openssl_rand_hex_32

# ══════════════════════════════════════════
# CÓMO GENERAR VALORES SEGUROS:
# openssl rand -hex 32          → para secrets/tokens
# openssl rand -base64 32       → para N8N_KEY
# python -c "import secrets; print(secrets.token_urlsafe(48))"
# ══════════════════════════════════════════`;

const DOCKERFILE = `# ── Stage 1: Builder ──────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ── Stage 2: Runtime (imagen mínima) ──────
FROM python:3.11-slim AS runtime

# Usuario sin privilegios — nunca correr como root
RUN groupadd -r sentinel && useradd -r -g sentinel sentinel

WORKDIR /app
COPY --from=builder /root/.local /home/sentinel/.local
COPY --chown=sentinel:sentinel . .

# Solo el puerto interno — Nginx hace el proxy
EXPOSE 8000

USER sentinel

# Health check para Docker
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import httpx; httpx.get('http://localhost:8000/health')"

CMD ["python", "-m", "uvicorn", "main:app", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--workers", "2", "--no-access-log"]`;

const DEPLOY_STEPS = [
  {
    step: "01",
    title: "Clonar y preparar",
    time: "2 min",
    color: C.green,
    commands: [
      "git clone https://github.com/tu-org/sentinel-mind",
      "cd sentinel-mind",
      "cp .env.example .env",
      "# Editar .env con tus valores reales",
    ],
    note: "Nunca commitear el .env — ya está en .gitignore por defecto"
  },
  {
    step: "02",
    title: "Generar secrets seguros",
    time: "2 min",
    color: C.cyan,
    commands: [
      "openssl rand -hex 32  # → GITHUB_WEBHOOK_SECRET",
      "openssl rand -hex 32  # → INTERNAL_SERVICE_TOKEN",
      "openssl rand -base64 32  # → N8N_KEY",
    ],
    note: "Copiar cada valor al .env antes de continuar"
  },
  {
    step: "03",
    title: "Levantar el Búnker",
    time: "3 min",
    color: C.amber,
    commands: [
      "docker-compose up -d",
      "docker-compose ps  # Verificar que todos estén 'healthy'",
      "docker-compose logs scanner -f  # Monitorear arranque",
    ],
    note: "El scanner estará listo cuando veas 'Uvicorn running on 0.0.0.0:8000'"
  },
  {
    step: "04",
    title: "Configurar GitHub Webhook",
    time: "3 min",
    color: C.purple,
    commands: [
      "# Ir a: GitHub Repo → Settings → Webhooks → Add webhook",
      "# Payload URL: https://tu-dominio.com/webhook/sentinel-github",
      "# Content type: application/json",
      "# Secret: el valor de GITHUB_WEBHOOK_SECRET del .env",
      "# Events: Just the push event",
    ],
    note: "Usar HTTPS obligatorio — el HMAC valida cada request"
  },
  {
    step: "05",
    title: "Verificar el sistema",
    time: "2 min",
    color: C.red,
    commands: [
      "# Test: hacer un push con un archivo que tenga una key falsa",
      "echo 'FAKE_KEY=AKIAFAKEKEY12345678' > test_secret.txt",
      "git add test_secret.txt && git commit -m 'test sentinel'",
      "git push  # Sentinel debería alertar en <30 segundos",
      "git rm test_secret.txt && git push  # Limpiar",
    ],
    note: "Si recibís la alerta en Telegram/Slack, el sistema está operativo"
  },
];

const SECTIONS = ["Bunker", "Learning Loop", "Deploy", "Variables"];

// ─── COMPONENT ────────────────────────────────────────────────────
export default function SentinelGodMode() {
  const [activeSection, setActiveSection] = useState("Bunker");
  const [copied, setCopied] = useState(null);
  const [scanActive, setScanActive] = useState(false);
  const [pulseCount, setPulseCount] = useState(0);
  const [termLines, setTermLines] = useState([]);
  const termRef = useRef(null);

  // Simulated terminal boot sequence
  const bootLines = [
    { t: 200,  text: "$ docker-compose up -d", color: C.green },
    { t: 600,  text: "[+] Building scanner:latest ...", color: C.mutedHi },
    { t: 1000, text: "[+] Container sentinel_db_1 — healthy", color: C.green },
    { t: 1400, text: "[+] Container sentinel_n8n_1 — started", color: C.green },
    { t: 1800, text: "[+] Container sentinel_scanner_1 — started", color: C.green },
    { t: 2200, text: "[+] Container sentinel_nginx_1 — started", color: C.green },
    { t: 2600, text: "", color: C.muted },
    { t: 2800, text: "INFO:     Sentinel Mind v1.0.0 — ONLINE", color: C.cyan },
    { t: 3000, text: "INFO:     Zero-Trust network: sentinel_internal", color: C.mutedHi },
    { t: 3200, text: "INFO:     Learning Loop: connected to Supabase", color: C.mutedHi },
    { t: 3400, text: "INFO:     GitHub webhook listener: ACTIVE", color: C.mutedHi },
    { t: 3800, text: "INFO:     Uvicorn running on 0.0.0.0:8000 ✓", color: C.green },
    { t: 4200, text: "⚡ SENTINEL MIND — ALL SYSTEMS GO", color: C.amber },
  ];

  useEffect(() => {
    if (activeSection !== "Bunker") return;
    setTermLines([]);
    setScanActive(false);
    const timers = bootLines.map(({ t, text, color }) =>
      setTimeout(() => setTermLines(prev => [...prev, { text, color }]), t)
    );
    const finalTimer = setTimeout(() => setScanActive(true), 4500);
    return () => { timers.forEach(clearTimeout); clearTimeout(finalTimer); };
  }, [activeSection]);

  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight;
  }, [termLines]);

  // Pulse counter
  useEffect(() => {
    if (!scanActive) return;
    const id = setInterval(() => setPulseCount(p => p + 1), 3000);
    return () => clearInterval(id);
  }, [scanActive]);

  const copy = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  const CodePanel = ({ code, id, lang = "bash" }) => (
    <div style={{ background: "#020810", border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden", marginBottom: 20 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 16px", background: C.card, borderBottom: `1px solid ${C.border}` }}>
        <span style={{ color: C.muted, fontSize: 11, fontFamily: "'JetBrains Mono', monospace", textTransform: "uppercase", letterSpacing: 1 }}>{lang}</span>
        <button onClick={() => copy(code, id)} style={{
          background: copied === id ? `${C.green}22` : "transparent",
          border: `1px solid ${copied === id ? C.green : C.border}`,
          color: copied === id ? C.green : C.mutedHi,
          borderRadius: 6, padding: "4px 14px", cursor: "pointer", fontSize: 11,
          fontFamily: "'JetBrains Mono', monospace", transition: "all 0.2s"
        }}>
          {copied === id ? "✓ copiado" : "copiar"}
        </button>
      </div>
      <pre style={{
        margin: 0, padding: "20px 20px", color: C.text, fontSize: 12, lineHeight: 1.75,
        fontFamily: "'JetBrains Mono', 'Fira Code', monospace", overflowX: "auto", maxHeight: 420
      }}>{code}</pre>
    </div>
  );

  return (
    <div style={{ minHeight: "100vh", background: C.bg, color: C.text, fontFamily: "'IBM Plex Mono', 'JetBrains Mono', monospace" }}>

      {/* ── SCAN LINE EFFECT ── */}
      <div style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, pointerEvents: "none", zIndex: 0,
        background: "repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,255,136,0.015) 2px, rgba(0,255,136,0.015) 4px)"
      }} />

      {/* ── HEADER ── */}
      <div style={{ position: "relative", zIndex: 1, borderBottom: `1px solid ${C.border}`, padding: "28px 36px", background: `linear-gradient(180deg, ${C.surface} 0%, ${C.bg} 100%)` }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 16 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
            <div style={{ position: "relative" }}>
              <div style={{ width: 56, height: 56, background: `${C.green}15`, border: `1px solid ${C.green}40`, borderRadius: 12, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 26 }}>🛡️</div>
              {scanActive && (
                <div style={{ position: "absolute", top: -4, right: -4, width: 12, height: 12, background: C.green, borderRadius: "50%", animation: "pulse 2s infinite" }} />
              )}
            </div>
            <div>
              <div style={{ fontSize: 22, fontWeight: 700, letterSpacing: 3, color: C.green }}>SENTINEL MIND</div>
              <div style={{ fontSize: 11, color: C.muted, letterSpacing: 2, marginTop: 2 }}>GOD MODE DEPLOY // v2.0</div>
            </div>
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {["Zero Trust", "Learning Loop", "Auto-Patch", "Docker"].map(tag => (
              <span key={tag} style={{ background: `${C.green}10`, border: `1px solid ${C.green}30`, color: C.greenDim, borderRadius: 4, padding: "4px 10px", fontSize: 10, letterSpacing: 1 }}>{tag}</span>
            ))}
          </div>
        </div>
      </div>

      {/* ── NAV TABS ── */}
      <div style={{ position: "relative", zIndex: 1, display: "flex", borderBottom: `1px solid ${C.border}`, background: C.surface, padding: "0 36px", overflowX: "auto" }}>
        {SECTIONS.map(s => (
          <button key={s} onClick={() => setActiveSection(s)} style={{
            background: "none", border: "none", padding: "16px 24px",
            color: activeSection === s ? C.green : C.muted,
            borderBottom: activeSection === s ? `2px solid ${C.green}` : "2px solid transparent",
            cursor: "pointer", fontSize: 12, letterSpacing: 2, textTransform: "uppercase",
            fontFamily: "inherit", transition: "color 0.2s", whiteSpace: "nowrap"
          }}>{s}</button>
        ))}
      </div>

      {/* ── MAIN CONTENT ── */}
      <div style={{ position: "relative", zIndex: 1, padding: "32px 36px", maxWidth: 1000, margin: "0 auto" }}>

        {/* ── BUNKER TAB ── */}
        {activeSection === "Bunker" && (
          <div>
            {/* Live terminal */}
            <div style={{ marginBottom: 28 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
                <span style={{ color: C.green, fontSize: 11, letterSpacing: 2 }}>// TERMINAL</span>
                {scanActive && (
                  <span style={{ color: C.amber, fontSize: 10, letterSpacing: 1 }}>
                    ● LIVE — scan #{pulseCount} completados
                  </span>
                )}
              </div>
              <div ref={termRef} style={{
                background: "#01080F", border: `1px solid ${C.green}30`, borderRadius: 8,
                padding: 20, height: 260, overflowY: "auto", fontFamily: "'JetBrains Mono', monospace"
              }}>
                {termLines.map((line, i) => (
                  <div key={i} style={{ color: line.color || C.text, fontSize: 12, lineHeight: 1.8, opacity: 0.9 }}>
                    {line.text || "\u00A0"}
                  </div>
                ))}
                {termLines.length > 0 && termLines.length < bootLines.length && (
                  <span style={{ color: C.green, animation: "blink 1s infinite" }}>█</span>
                )}
              </div>
            </div>

            <div style={{ color: C.green, fontSize: 11, letterSpacing: 2, marginBottom: 12 }}>// docker-compose.yml — HARDENED</div>
            <CodePanel code={DOCKER_COMPOSE} id="docker" lang="yaml" />

            <div style={{ color: C.green, fontSize: 11, letterSpacing: 2, marginBottom: 12 }}>// Dockerfile — Multi-Stage (sin root)</div>
            <CodePanel code={DOCKERFILE} id="dockerfile" lang="dockerfile" />

            {/* Zero Trust Architecture callout */}
            <div style={{ background: `${C.red}08`, border: `1px solid ${C.red}30`, borderRadius: 8, padding: 20 }}>
              <div style={{ color: C.red, fontSize: 11, letterSpacing: 2, marginBottom: 12 }}>// ZERO TRUST — QUÉ CAMBIA VS EL ORIGINAL</div>
              {[
                ["N8N solo en localhost:5678", "Nginx hace el reverse proxy con TLS — nunca expuesto directo"],
                ["Red sentinel_internal: internal=true", "DB y scanner sin acceso a internet — se comunican solo entre sí"],
                ["Scanner sin puertos externos", "Solo N8N puede llamarlo por red interna con token"],
                ["Dockerfile multi-stage + usuario sentinel", "Imagen mínima, sin root, sin herramientas de build en runtime"],
                ["healthcheck en Postgres", "Scanner espera que DB esté healthy antes de arrancar"],
              ].map(([feat, desc]) => (
                <div key={feat} style={{ display: "flex", gap: 16, marginBottom: 10, alignItems: "flex-start" }}>
                  <span style={{ color: C.green, fontSize: 12, minWidth: 8 }}>›</span>
                  <div>
                    <span style={{ color: C.text, fontSize: 12, fontWeight: 600 }}>{feat}</span>
                    <span style={{ color: C.mutedHi, fontSize: 12 }}> — {desc}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── LEARNING LOOP TAB ── */}
        {activeSection === "Learning Loop" && (
          <div>
            {/* Flow diagram */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 16, marginBottom: 28 }}>
              {[
                { icon: "🧠", label: "Git Push", sub: "Trigger inicial", color: C.blue },
                { icon: "📚", label: "Consultar historial", sub: "Supabase PATCHED/DISMISSED", color: C.cyan },
                { icon: "⚡", label: "Super Prompt", sub: "Claude + contexto", color: C.green },
                { icon: "🔍", label: "¿Falso positivo?", sub: "Confidence > 85%", color: C.amber },
                { icon: "🔀", label: "PR en draft", sub: "Revisión humana", color: C.purple },
                { icon: "✅", label: "Feedback humano", sub: "Cierra el loop", color: C.green },
              ].map((node, i) => (
                <div key={i} style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: 16, textAlign: "center", position: "relative" }}>
                  <div style={{ fontSize: 24, marginBottom: 8 }}>{node.icon}</div>
                  <div style={{ color: node.color, fontSize: 11, fontWeight: 700, letterSpacing: 1, marginBottom: 4 }}>{node.label}</div>
                  <div style={{ color: C.muted, fontSize: 10 }}>{node.sub}</div>
                  {i < 5 && (
                    <div style={{ position: "absolute", right: -10, top: "50%", transform: "translateY(-50%)", color: C.muted, fontSize: 16, zIndex: 2 }}>›</div>
                  )}
                </div>
              ))}
            </div>

            <div style={{ color: C.green, fontSize: 11, letterSpacing: 2, marginBottom: 12 }}>// learning_loop.py — Módulo de Metacognición</div>
            <CodePanel code={LEARNING_LOOP} id="learning" lang="python" />

            <div style={{ background: `${C.cyan}08`, border: `1px solid ${C.cyan}30`, borderRadius: 8, padding: 20 }}>
              <div style={{ color: C.cyan, fontSize: 11, letterSpacing: 2, marginBottom: 12 }}>// POR QUÉ ESTO CAMBIA EL JUEGO</div>
              <div style={{ color: C.mutedHi, fontSize: 13, lineHeight: 1.8 }}>
                Sin Learning Loop: el sistema comete los mismos errores repetidamente, generando fatiga de alertas en tu equipo.<br /><br />
                Con Learning Loop: cada vez que un humano acepta o rechaza un PR, esa decisión se almacena en Supabase. La próxima vez que Claude analiza un hallazgo similar, recibe ese historial como contexto y ajusta su razonamiento. El sistema se vuelve más preciso con cada iteración.
              </div>
            </div>
          </div>
        )}

        {/* ── DEPLOY TAB ── */}
        {activeSection === "Deploy" && (
          <div>
            <div style={{ color: C.green, fontSize: 11, letterSpacing: 2, marginBottom: 24 }}>// PLAN DE DEPLOY — 12 MINUTOS</div>
            {DEPLOY_STEPS.map((s) => (
              <div key={s.step} style={{ display: "flex", gap: 20, marginBottom: 24, alignItems: "flex-start" }}>
                <div style={{ minWidth: 52, height: 52, background: `${s.color}15`, border: `1px solid ${s.color}40`, borderRadius: 8, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
                  <span style={{ color: s.color, fontSize: 14, fontWeight: 700 }}>{s.step}</span>
                  <span style={{ color: C.muted, fontSize: 9 }}>{s.time}</span>
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ color: s.color, fontSize: 13, fontWeight: 700, letterSpacing: 1, marginBottom: 10 }}>{s.title}</div>
                  <div style={{ background: "#020810", border: `1px solid ${C.border}`, borderRadius: 6, padding: "14px 16px", marginBottom: 8 }}>
                    {s.commands.map((cmd, i) => (
                      <div key={i} style={{ color: cmd.startsWith("#") ? C.muted : C.green, fontSize: 11, lineHeight: 1.8, fontFamily: "monospace" }}>{cmd}</div>
                    ))}
                  </div>
                  <div style={{ color: C.muted, fontSize: 11 }}>⚑ {s.note}</div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* ── VARIABLES TAB ── */}
        {activeSection === "Variables" && (
          <div>
            <div style={{ background: `${C.amber}10`, border: `1px solid ${C.amber}40`, borderRadius: 8, padding: 16, marginBottom: 24, display: "flex", gap: 12, alignItems: "flex-start" }}>
              <span style={{ fontSize: 18 }}>⚠️</span>
              <div style={{ color: C.amber, fontSize: 13, lineHeight: 1.7 }}>
                <strong>NUNCA</strong> commitear el .env al repositorio. Agregar <code style={{ background: `${C.amber}15`, padding: "1px 6px", borderRadius: 3 }}>.env</code> a tu <code style={{ background: `${C.amber}15`, padding: "1px 6px", borderRadius: 3 }}>.gitignore</code> antes de cualquier push.
              </div>
            </div>
            <div style={{ color: C.green, fontSize: 11, letterSpacing: 2, marginBottom: 12 }}>// .env — Template completo con instrucciones</div>
            <CodePanel code={ENV_FILE} id="env" lang="env" />

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 16, marginTop: 8 }}>
              {[
                { label: "GITHUB_TOKEN", where: "github.com → Settings → Developer settings → Personal access tokens → Classic", perms: "repo (full), workflow" },
                { label: "TELEGRAM_BOT_TOKEN", where: "Hablar con @BotFather en Telegram → /newbot", perms: "Necesitás el chat_id del grupo o canal" },
                { label: "SUPABASE_SERVICE_KEY", where: "Supabase Dashboard → Settings → API → service_role key", perms: "Solo usar en backend — nunca en frontend" },
                { label: "N8N_KEY", where: "Generar con: openssl rand -base64 32", perms: "Encripta credenciales guardadas en N8N" },
              ].map(item => (
                <div key={item.label} style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: 16 }}>
                  <div style={{ color: C.cyan, fontSize: 11, fontWeight: 700, marginBottom: 8, fontFamily: "monospace" }}>{item.label}</div>
                  <div style={{ color: C.mutedHi, fontSize: 11, marginBottom: 6, lineHeight: 1.6 }}>📍 {item.where}</div>
                  <div style={{ color: C.muted, fontSize: 10 }}>🔑 {item.perms}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      <style>{`
        @keyframes pulse { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.4; transform: scale(0.8); } }
        @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0; } }
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: ${C.bg}; }
        ::-webkit-scrollbar-thumb { background: ${C.border}; border-radius: 2px; }
      `}</style>
    </div>
  );
}
