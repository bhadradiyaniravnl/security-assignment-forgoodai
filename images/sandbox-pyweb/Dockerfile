# Per-repo sandbox image for Python web services (e.g. items-api-sample).
# Dependencies are installed at build time, so the agent never needs egress to PyPI.
# Production: built in CI from the repo's declared environment, signed, and pinned by digest.
FROM sbx/sandbox:dev
USER root
RUN apt-get update && apt-get install -y --no-install-recommends python3-pip && rm -rf /var/lib/apt/lists/* \
    && pip3 install --no-cache-dir --break-system-packages \
         fastapi==0.115.12 uvicorn==0.34.2 httpx==0.28.1 pytest==8.3.5
USER 1000
