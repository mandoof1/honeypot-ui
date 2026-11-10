# Build context is the repository root so `honeypot` stays an importable
# package. Building from ./honeypot copied the package *contents* to /app,
# which made `python -m honeypot.main` fail with "No module named honeypot".
#
# The base image is pinned by digest; scripts/pin-images.sh updates it.

# python:3.12-slim
FROM python@sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d

WORKDIR /app

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY honeypot/requirements.txt honeypot/requirements.lock ./
# Hash-checked install from the lock; the second command installs nothing and
# fails when the lock no longer matches requirements.txt (see
# backend/Dockerfile).
RUN pip install --require-hashes --no-deps -r requirements.lock \
    && { pip install --no-index --no-deps -r requirements.txt \
         || { echo "honeypot/requirements.lock is out of date: run scripts/lock-requirements.sh" >&2; exit 1; }; }

# The root .dockerignore keeps the engine's tests and caches out.
COPY honeypot ./honeypot

# The code is root-owned and the engine cannot change it; it owns only its
# data directory, which is a volume in every deployment.
RUN python -m compileall -q honeypot \
    && mkdir -p /app/data/sessions /app/data/uploads \
    && useradd --system --uid 10001 --no-create-home honeypot \
    && chown -R honeypot:honeypot /app/data

# The emulators bind ports above 1024, so root is never needed.
USER honeypot

ENV HONEYPOT_CONTAINER=true \
    HONEYPOT_BIND_ADDRESS=0.0.0.0 \
    HOME=/tmp

EXPOSE 2222 2121 2323 8080 8443

# Liveness: the control API answers /healthz without the token, on loopback
# as well as its management address. No curl in the slim image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD python -c "import os,sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('HONEYPOT_CONTROL_PORT','8000'), timeout=3).status == 200 else 1)"

CMD ["python", "-m", "honeypot.main"]

# Last, so a new revision rebuilds only this layer; see backend/Dockerfile.
ARG GIT_REVISION=unknown
ENV GIT_REVISION=${GIT_REVISION}
LABEL org.opencontainers.image.title="HoneySentinel engine" \
      org.opencontainers.image.source="https://github.com/mandoof1/honeypot-ui" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.revision="${GIT_REVISION}"
