#!/usr/bin/env bash
# Publish an immutable, publicly attachable Akto AgentCore Lambda layer version.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

AWS_REGION="${AWS_REGION:-us-east-1}"
LAYER_NAME="${LAYER_NAME:-akto-agentcore}"
BUILD_ZIP="${BUILD_ZIP:-${REPO_ROOT}/dist/akto-agentcore-layer.zip}"

"${SCRIPT_DIR}/build-layer.sh" "${BUILD_ZIP}" >/dev/null

SHA256="$(shasum -a 256 "${BUILD_ZIP}" | awk '{print $1}')"
DESCRIPTION="Akto AgentCore interceptor ${SHA256}"

LAYER_ARN="$(aws lambda publish-layer-version \
  --region "${AWS_REGION}" \
  --layer-name "${LAYER_NAME}" \
  --description "${DESCRIPTION}" \
  --zip-file "fileb://${BUILD_ZIP}" \
  --compatible-runtimes python3.10 python3.11 python3.12 python3.13 \
  --compatible-architectures x86_64 arm64 \
  --query LayerVersionArn \
  --output text)"

VERSION="${LAYER_ARN##*:}"
aws lambda add-layer-version-permission \
  --region "${AWS_REGION}" \
  --layer-name "${LAYER_NAME}" \
  --version-number "${VERSION}" \
  --statement-id public \
  --action lambda:GetLayerVersion \
  --principal '*' >/dev/null

printf '%s\n' "${LAYER_ARN}"
