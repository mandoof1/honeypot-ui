FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    iproute2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p data/sessions data/uploads data/logs

ENV HONEYPOT_CONTAINER=true
ENV HONEYPOT_BIND_ADDRESS=0.0.0.0

EXPOSE 2222 2121 8080 8443

CMD ["python", "-m", "honeypot.main"]
