# ═══════════════════════════════════════════════════════════════
# SENTINEL MIND — Dockerfile (Multi-Stage, Non-Root)
# Stage 1: builder  → instala dependencias
# Stage 2: runtime  → imagen mínima de producción
# ═══════════════════════════════════════════════════════════════

# ── Stage 1: Builder ──────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Evitar archivos .pyc y buffering innecesario
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Copiar solo requirements primero (cache de capas)
COPY requirements.txt .

# Instalar en directorio de usuario aislado
RUN pip install --no-cache-dir --user -r requirements.txt


# ── Stage 2: Runtime ──────────────────────────────────────────
FROM python:3.11-slim AS runtime

# Variables de entorno de seguridad
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/home/sentinel/.local/bin:$PATH" \
    HOME="/home/sentinel"

# Crear usuario sin privilegios — NUNCA correr como root
RUN groupadd --system --gid 1001 sentinel \
 && useradd  --system --uid 1001 --gid 1001 \
             --no-create-home --shell /sbin/nologin sentinel \
 && mkdir -p /app /home/sentinel \
 && chown -R sentinel:sentinel /app /home/sentinel

# Copiar dependencias desde builder
COPY --from=builder --chown=sentinel:sentinel \
     /root/.local /home/sentinel/.local

# Copiar código fuente
WORKDIR /app
COPY --chown=sentinel:sentinel . .

# Remover archivos innecesarios en producción
RUN find /app -name "*.pyc" -delete \
 && find /app -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true \
 && rm -rf /app/tests /app/.env.example /app/*.md

# Health check: verifica el endpoint /health del FastAPI
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD python -c "import httpx; httpx.get('http://localhost:8000/health', timeout=8).raise_for_status()"

# Cambiar a usuario sin privilegios
USER sentinel

# Exponer puerto interno (Nginx/N8N hacen el proxy)
EXPOSE 8000

# Arrancar con 2 workers Uvicorn — ajustar según CPU disponible
CMD ["python", "-m", "uvicorn", "main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "2", \
     "--loop", "uvloop", \
     "--no-access-log", \
     "--timeout-keep-alive", "30"]
