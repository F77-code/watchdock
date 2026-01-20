FROM python:3.12-slim

# docker.sock is often mode 660 and owned by root. Staying root avoids
# a host-specific group id just to read that one socket.

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

CMD ["python", "main.py"]
