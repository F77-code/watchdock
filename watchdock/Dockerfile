FROM python:3.12-slim

# The process stays root so it can read other containers' cgroup files
# under /host/proc. The daemon socket is not mounted here.

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/tmp

WORKDIR /app

COPY pyproject.toml README.md ./
COPY config.py main.py ./
COPY core ./core
COPY schemas ./schemas

RUN pip install --no-cache-dir .

HEALTHCHECK --interval=60s --timeout=5s --start-period=600s --retries=3 \
  CMD python -c "import os,time,pathlib; p=pathlib.Path(os.environ.get('HEARTBEAT_PATH','/tmp/watchdock-heartbeat')); limit=float(os.environ.get('HEARTBEAT_SEC','300'))*2; ok=p.exists() and time.time()-p.stat().st_mtime < limit; raise SystemExit(0 if ok else 1)"

CMD ["python", "main.py"]
