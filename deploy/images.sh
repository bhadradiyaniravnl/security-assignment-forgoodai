#!/usr/bin/env bash
# Builds the sandbox and services images and loads them into the kind node.
set -euo pipefail
cd "$(dirname "$0")/.."
CLUSTER="${CLUSTER:-sbx}"
TAG="${TAG:-dev}"

docker build -q -t "sbx/sandbox:$TAG" -f images/sandbox/Dockerfile images/sandbox
docker build -q -t "sbx/sandbox-pyweb:$TAG" -f images/sandbox-pyweb/Dockerfile images/sandbox-pyweb
docker build -q -t "sbx/services:$TAG" -f images/services/Dockerfile .
kind load docker-image --name "$CLUSTER" "sbx/sandbox:$TAG" "sbx/sandbox-pyweb:$TAG" "sbx/services:$TAG"
