FROM python:3.12.11-slim

# The process stays root so it can read other containers' cgroup files
# under /host/proc. The daemon socket is not mounted here.

COPY --from=ghcr.io/astral-sh/uv:0.9.28 /uv /uvx /bin/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0 \
    UV_NO_CACHE=1 \
    HOME=/tmp

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project --no-dev

COPY config.py main.py ./
COPY core ./core
COPY schemas ./schemas
RUN uv sync --frozen --no-dev

ENV PATH="/app/.venv/bin:$PATH"

HEALTHCHECK --interval=60s --timeout=5s --start-period=600s --retries=3 \
  CMD python -c "import os,time,pathlib; p=pathlib.Path(os.environ.get('HEARTBEAT_PATH','/tmp/watchdock-heartbeat')); limit=float(os.environ.get('HEARTBEAT_SEC','300'))*2; ok=p.exists() and time.time()-p.stat().st_mtime < limit; raise SystemExit(0 if ok else 1)"

CMD ["python", "main.py"]
