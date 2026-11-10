# The API image, used by both the `backend` and `ingest` services.
#
# Two stages, so the image that parses attacker-supplied files carries no
# compiler: dependencies are installed into a virtual environment in the
# first stage and only that directory is copied into the second.
#
# The base image is pinned by digest (the tag is a moving target and was
# re-pulled on every build). scripts/pin-images.sh updates the digest;
# Dependabot proposes the update.

# python:3.12-slim
ARG PYTHON_IMAGE=python@sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d

FROM ${PYTHON_IMAGE} AS build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Every dependency ships a wheel for x86-64 and arm64 today; gcc is here for
# the day one does not, and never reaches the final image.
RUN apt-get update && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt requirements.lock ./

# requirements.lock lists every package with the SHA-256 of each file pip may
# fetch for it; --require-hashes refuses anything else. The second command
# installs nothing (--no-index): it only succeeds when what the lock
# installed satisfies requirements.txt, so a lock that was not regenerated
# after a dependency change stops the build here instead of producing an
# image that fails on import.
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --require-hashes --no-deps -r requirements.lock \
    && { /opt/venv/bin/pip install --no-index --no-deps -r requirements.txt \
         || { echo "requirements.lock is out of date: run scripts/lock-requirements.sh" >&2; exit 1; }; }

# The spaCy model, installed at build time: downloading it at request time
# needs network access and a writable install path inside the container.
# Explosion publishes no checksum for model releases, so the hash below is the
# one observed when this line was written (2026-11-10). It does not prove
# where the file came from; it does guarantee every build gets that same file.
ARG SPACY_MODEL_URL=https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl
ARG SPACY_MODEL_SHA256=1932429db727d4bff3deed6b34cfc05df17794f4a52eeb26cf8928f7c1a0fb85
RUN /opt/venv/bin/pip install --no-deps "en_core_web_sm @ ${SPACY_MODEL_URL}#sha256=${SPACY_MODEL_SHA256}"


FROM ${PYTHON_IMAGE}

# HOME: the user below has no home directory, and libraries that look for
# one get the scratch tmpfs instead of an unwritable path.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH=/opt/venv/bin:$PATH \
    HOME=/tmp

WORKDIR /app
COPY --from=build /opt/venv /opt/venv
# .dockerignore keeps tests, caches, local models and .env files out.
COPY . .

# The code stays owned by root, so the service cannot rewrite itself even
# where the root filesystem is not mounted read-only. It owns three
# directories: models (a volume in every deployment), data and out.
RUN python -m compileall -q app ml alembic \
    && mkdir -p models data out \
    && useradd --system --uid 10001 --no-create-home appuser \
    && chown appuser:appuser models data out
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=4)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# Last, so a new revision rebuilds only this layer. install.sh passes the
# commit and afterwards checks every running container carries the same one;
# the evaluation tools record it in their output.
ARG GIT_REVISION=unknown
ENV GIT_REVISION=${GIT_REVISION}
LABEL org.opencontainers.image.title="HoneySentinel API" \
      org.opencontainers.image.source="https://github.com/mandoof1/honeypot-ui" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.revision="${GIT_REVISION}"
