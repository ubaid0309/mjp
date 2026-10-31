FROM python:3.12-slim

# Semgrep lives in its own virtualenv so its pinned dependencies never clash with the worker's.
RUN python -m venv /opt/semgrep && /opt/semgrep/bin/pip install --no-cache-dir semgrep==1.183.0
ENV SEMGREP_BIN=/opt/semgrep/bin/semgrep \
    SM_WORK_DIR=/tmp/securematrix \
    SM_KNOWLEDGE_DIR=/app/knowledge \
    PYTHONUNBUFFERED=1

WORKDIR /app/worker
COPY worker/requirements.txt worker/requirements-local.txt ./
ARG LOCAL_EMBEDDINGS=false
RUN pip install --no-cache-dir -r requirements.txt \
 && if [ "$LOCAL_EMBEDDINGS" = "true" ]; then pip install --no-cache-dir -r requirements-local.txt; fi

COPY worker/ /app/worker/
COPY knowledge/ /app/knowledge/

# Scans run untrusted archives through Semgrep: run as an unprivileged user.
RUN useradd --create-home --uid 10001 securematrix && mkdir -p /tmp/securematrix && chown securematrix /tmp/securematrix
USER securematrix

EXPOSE 8787
CMD ["python", "-m", "securematrix_worker", "run"]
