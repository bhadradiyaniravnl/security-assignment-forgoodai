# Sandbox image: Claude Code + toolchain for the demo repo. Holds no credentials.
FROM node:24-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      git python3 python3-pytest ca-certificates curl jq ripgrep \
    && rm -rf /var/lib/apt/lists/*
RUN npm install -g @anthropic-ai/claude-code@2.1.1 && npm cache clean --force
COPY entrypoint.sh /usr/local/bin/sbx-entrypoint
RUN chmod 0755 /usr/local/bin/sbx-entrypoint
# uid 1000 = "node" in the base image
USER 1000
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/sbx-entrypoint"]
