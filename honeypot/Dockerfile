# Build context is the repository root so `honeypot` stays an importable
# package. Building from ./honeypot copied the package *contents* to /app,
# which made `python -m honeypot.main` fail with "No module named honeypot".
FROM python:3.12-slim

WORKDIR /app

COPY honeypot/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY honeypot ./honeypot

RUN mkdir -p /app/data/sessions /app/data/uploads \
    && useradd --system --uid 10001 --no-create-home honeypot \
    && chown -R honeypot:honeypot /app/data

# The emulators bind ports above 1024, so root is never needed.
USER honeypot

ENV HONEYPOT_CONTAINER=true \
    HONEYPOT_BIND_ADDRESS=0.0.0.0 \
    PYTHONUNBUFFERED=1

EXPOSE 2222 2121 8080 8443

# Liveness: the control API answers /healthz without the token, on loopback
# as well as its management address. No curl in the slim image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD python -c "import os,sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('HONEYPOT_CONTROL_PORT','8000'), timeout=3).status == 200 else 1)"

CMD ["python", "-m", "honeypot.main"]
