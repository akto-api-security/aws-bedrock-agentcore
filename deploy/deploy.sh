#!/usr/bin/env bash
#
# Deploy the Akto guardrails interceptor Lambda and attach it to one or more
# AgentCore Gateways as a REQUEST + RESPONSE interceptor.
#
# Config comes from deploy/.env (see .env.example). The script:
#   1. Auto-fetches the AWS account id.
#   2. Creates the Lambda execution role if it doesn't exist.
#   3. Packages and creates/updates the interceptor Lambda.
#   4. For each gateway in GATEWAY_IDS: grants the gateway's role invoke
#      permission and attaches the interceptor (preserving existing config).
#
# Prereqs: awscli v2, jq, zip, and AWS credentials with lambda:*, iam:*
# (PutRolePolicy/CreateRole/PassRole) and bedrock-agentcore-control Get/UpdateGateway.
# Idempotent — safe to re-run.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# --- Load .env --------------------------------------------------------------
ENV_FILE="${ENV_FILE:-${SCRIPT_DIR}/.env}"
if [ -f "${ENV_FILE}" ]; then
  set -a; . "${ENV_FILE}"; set +a
else
  echo "No ${ENV_FILE} found. Copy .env.example to .env and fill it in." >&2
  exit 1
fi

# --- Required config --------------------------------------------------------
: "${AWS_REGION:?set AWS_REGION in .env}"
: "${AKTO_DATA_INGESTION_URL:?set AKTO_DATA_INGESTION_URL in .env}"
: "${AKTO_API_TOKEN:?set AKTO_API_TOKEN in .env}"
: "${GATEWAY_IDS:?set GATEWAY_IDS in .env (one or more, comma/space separated)}"
: "${AKTO_LAYER_ARN:?set AKTO_LAYER_ARN to a versioned public Akto layer ARN}"

# --- Defaults ---------------------------------------------------------------
FUNCTION_NAME="${FUNCTION_NAME:-akto-guardrails-interceptor}"
LAMBDA_ROLE_NAME="${LAMBDA_ROLE_NAME:-akto-interceptor-lambda-role}"
LAMBDA_RUNTIME="${LAMBDA_RUNTIME:-python3.12}"
LAMBDA_TIMEOUT="${LAMBDA_TIMEOUT:-900}"
LAMBDA_MEMORY="${LAMBDA_MEMORY:-256}"
AKTO_APPROVAL_WAIT_SECONDS="${AKTO_APPROVAL_WAIT_SECONDS:-840}"
AKTO_APPROVAL_POLL_SECONDS="${AKTO_APPROVAL_POLL_SECONDS:-2}"
AKTO_TIMEOUT_SECONDS="${AKTO_TIMEOUT_SECONDS:-30}"
AKTO_FAIL_OPEN="${AKTO_FAIL_OPEN:-false}"

SRC_DIR="${REPO_ROOT}/lambda/interceptor"
BUILD_ZIP="$(mktemp -d)/interceptor.zip"

aws_lambda() { aws lambda "$@" --region "${AWS_REGION}"; }

ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
LAMBDA_ARN="arn:aws:lambda:${AWS_REGION}:${ACCOUNT_ID}:function:${FUNCTION_NAME}"
echo "Account: ${ACCOUNT_ID} | Region: ${AWS_REGION} | Function: ${FUNCTION_NAME}"

# ---------------------------------------------------------------------------
# 1. Lambda execution role (create if missing)
# ---------------------------------------------------------------------------
echo "==> 1/4 Ensuring Lambda execution role"
if [ -z "${LAMBDA_ROLE_ARN:-}" ]; then
  if aws iam get-role --role-name "${LAMBDA_ROLE_NAME}" >/dev/null 2>&1; then
    LAMBDA_ROLE_ARN="$(aws iam get-role --role-name "${LAMBDA_ROLE_NAME}" --query Role.Arn --output text)"
    echo "    Using existing role ${LAMBDA_ROLE_NAME}"
  else
    echo "    Creating role ${LAMBDA_ROLE_NAME}"
    LAMBDA_ROLE_ARN="$(aws iam create-role --role-name "${LAMBDA_ROLE_NAME}" \
      --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
      --query Role.Arn --output text)"
    aws iam attach-role-policy --role-name "${LAMBDA_ROLE_NAME}" \
      --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
    aws iam wait role-exists --role-name "${LAMBDA_ROLE_NAME}"
    echo "    Waiting ~10s for role propagation..."
    sleep 10
  fi
fi

# ---------------------------------------------------------------------------
# 2. Package
# ---------------------------------------------------------------------------
echo "==> 2/4 Packaging thin Lambda bootstrap from ${SRC_DIR}"
( cd "${SRC_DIR}" && zip -q -r "${BUILD_ZIP}" handler.py )
LAMBDA_ENV="Variables={AKTO_DATA_INGESTION_URL=${AKTO_DATA_INGESTION_URL},AKTO_API_TOKEN=${AKTO_API_TOKEN},AKTO_APPROVAL_WAIT_SECONDS=${AKTO_APPROVAL_WAIT_SECONDS},AKTO_APPROVAL_POLL_SECONDS=${AKTO_APPROVAL_POLL_SECONDS},AKTO_TIMEOUT_SECONDS=${AKTO_TIMEOUT_SECONDS},AKTO_FAIL_OPEN=${AKTO_FAIL_OPEN}}"

# ---------------------------------------------------------------------------
# 3. Create / update the function
# ---------------------------------------------------------------------------
echo "==> 3/4 Creating/updating Lambda function ${FUNCTION_NAME}"
if aws_lambda get-function --function-name "${FUNCTION_NAME}" >/dev/null 2>&1; then
  aws_lambda update-function-code --function-name "${FUNCTION_NAME}" \
    --zip-file "fileb://${BUILD_ZIP}" >/dev/null
  aws_lambda wait function-updated-v2 --function-name "${FUNCTION_NAME}"
  aws_lambda update-function-configuration --function-name "${FUNCTION_NAME}" \
    --timeout "${LAMBDA_TIMEOUT}" --memory-size "${LAMBDA_MEMORY}" \
    --environment "${LAMBDA_ENV}" --layers "${AKTO_LAYER_ARN}" >/dev/null
  aws_lambda wait function-updated-v2 --function-name "${FUNCTION_NAME}"
else
  aws_lambda create-function --function-name "${FUNCTION_NAME}" \
    --runtime "${LAMBDA_RUNTIME}" --handler "handler.lambda_handler" \
    --role "${LAMBDA_ROLE_ARN}" --zip-file "fileb://${BUILD_ZIP}" \
    --timeout "${LAMBDA_TIMEOUT}" --memory-size "${LAMBDA_MEMORY}" \
    --environment "${LAMBDA_ENV}" --layers "${AKTO_LAYER_ARN}" >/dev/null
  aws_lambda wait function-active-v2 --function-name "${FUNCTION_NAME}"
fi

INTERCEPTOR_CONFIG="$(jq --arg arn "${LAMBDA_ARN}" \
  '.[0].interceptor.lambda.arn = $arn' "${SCRIPT_DIR}/interceptor-config.json")"

# ---------------------------------------------------------------------------
# 4. Attach to each gateway
#    update-gateway is a FULL REPLACE, so we read the current gateway and
#    re-supply every field it already has plus the interceptor.
# ---------------------------------------------------------------------------
attach_to_gateway() {
  local gw="$1"
  echo "==> 4/4 Attaching to gateway ${gw}"
  local current
  current="$(aws bedrock-agentcore-control get-gateway \
    --gateway-identifier "${gw}" --region "${AWS_REGION}" 2>/dev/null)" || true
  if [ -z "${current}" ]; then
    echo "    could not read gateway ${gw} (check id/region/permissions)" >&2
    return 1
  fi

  local gw_role_arn name role_arn authorizer_type authorizer_config
  gw_role_arn="$(echo "${current}" | jq -r '.roleArn')"
  name="$(echo "${current}" | jq -r '.name')"
  role_arn="${gw_role_arn}"
  authorizer_type="$(echo "${current}" | jq -r '.authorizerType')"
  authorizer_config="$(echo "${current}" | jq -c '.authorizerConfiguration')"

  # Grant this gateway's execution role permission to invoke the Lambda.
  echo "    Granting ${gw_role_arn##*/} lambda:InvokeFunction"
  aws iam put-role-policy \
    --role-name "${gw_role_arn##*/}" \
    --policy-name "invoke-${FUNCTION_NAME}" \
    --policy-document "$(jq -n --arg arn "${LAMBDA_ARN}" '{
      Version: "2012-10-17",
      Statement: [{ Effect: "Allow", Action: "lambda:InvokeFunction", Resource: $arn }]
    }')" >/dev/null

  # Build update args, re-supplying optional fields only when present.
  # --protocol-type is intentionally omitted (immutable on an existing gateway).
  local args=(
    --gateway-identifier "${gw}"
    --region "${AWS_REGION}"
    --name "${name}"
    --role-arn "${role_arn}"
    --authorizer-type "${authorizer_type}"
    --authorizer-configuration "${authorizer_config}"
    --interceptor-configurations "${INTERCEPTOR_CONFIG}"
  )
  local add
  add() { # $1=jq-path  $2=cli-flag  ($3="raw" for scalars)
    local val; val="$(echo "${current}" | jq -c "${1} // empty")"
    [ -n "${val}" ] && [ "${val}" != "null" ] || return 0
    if [ "${3:-}" = "raw" ]; then val="$(echo "${current}" | jq -r "${1}")"; fi
    args+=("${2}" "${val}")
  }
  add '.description'                  --description           raw
  add '.kmsKeyArn'                    --kms-key-arn           raw
  add '.exceptionLevel'              --exception-level        raw
  add '.protocolConfiguration'       --protocol-configuration
  add '.customTransformConfiguration' --custom-transform-configuration
  add '.policyEngineConfiguration'   --policy-engine-configuration
  add '.wafConfiguration'            --waf-configuration

  aws bedrock-agentcore-control update-gateway "${args[@]}" >/dev/null
  echo "    ✓ ${gw} attached"
}

# Split GATEWAY_IDS on commas and spaces.
IFS=', ' read -r -a GATEWAYS <<< "${GATEWAY_IDS}"
failed=0
for gw in "${GATEWAYS[@]}"; do
  [ -n "${gw}" ] || continue
  if ! attach_to_gateway "${gw}"; then
    echo "    ✗ ${gw} FAILED" >&2
    failed=$((failed + 1))
  fi
done

if [ "${failed}" -gt 0 ]; then
  echo "==> Done with ${failed} gateway failure(s). Lambda: ${LAMBDA_ARN}" >&2
  exit 1
fi
echo "==> Done. Interceptor ${LAMBDA_ARN} attached to: ${GATEWAYS[*]}"
