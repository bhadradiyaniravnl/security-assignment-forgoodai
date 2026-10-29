# One image for all platform services (control-plane, gateway, credproxy, detector, lab).
# The command is chosen per Deployment.
FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends openssl git ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
# Hubble CLI for the detector (pinned release, checksum verified).
ARG HUBBLE_VERSION=v1.20.2
ARG HUBBLE_ARCH=arm64
RUN cd /tmp && f=hubble-linux-${HUBBLE_ARCH}.tar.gz \
    && curl -fsSLO https://github.com/cilium/hubble/releases/download/${HUBBLE_VERSION}/$f \
    && curl -fsSLO https://github.com/cilium/hubble/releases/download/${HUBBLE_VERSION}/$f.sha256sum \
    && sha256sum -c $f.sha256sum && tar -xzf $f -C /usr/local/bin hubble && rm -f $f $f.sha256sum
COPY images/services/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
# Self-signed cert for lab TLS endpoints (lab only, not a platform trust anchor).
RUN mkdir -p /etc/lab-tls && openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
      -subj "/CN=lab-ext" -addext "subjectAltName=DNS:paste-mock.lab-ext.svc,DNS:attacker-sink.lab-ext.svc" \
      -keyout /etc/lab-tls/tls.key -out /etc/lab-tls/tls.crt && chmod 0644 /etc/lab-tls/tls.key
COPY src /app/src
COPY specs /app/specs
COPY demo-repo /app/demo-repo
ENV PYTHONPATH=/app/src PYTHONUNBUFFERED=1
USER 10001
WORKDIR /app
