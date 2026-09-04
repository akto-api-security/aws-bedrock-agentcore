# AWS console deployment: Akto for Amazon Bedrock AgentCore Gateway

Do this entirely in the AWS Management Console. Do not use `deploy.sh` or the AWS CLI.

A gateway can have **at most one REQUEST interceptor and one RESPONSE interceptor**. Choose one path:

| Path | Use when |
| --- | --- |
| [New Lambda](#path-a-new-lambda) | The gateway has **no** interceptor yet. You create an Akto interceptor function and attach it in the AgentCore console. |
| [Existing Lambda](#path-b-existing-lambda) | The gateway **already** calls a Python interceptor. You add Akto to that same function. Do not attach a second interceptor Lambda — that replaces the current one. |

Stay in the **same AWS region** as the gateway for every console you open (top-right region selector).

---

## What to have open

| Item | Where in the console |
| --- | --- |
| Gateway | [Amazon Bedrock AgentCore](https://console.aws.amazon.com/bedrock-agentcore/home#) → **Gateways** → your gateway |
| Gateway IAM role name | That gateway’s details page, **IAM role** / **Permissions** |
| Akto data-ingestion URL | Akto dashboard |
| Akto API token | Akto dashboard (raw token, no `Bearer ` prefix) |
| Akto layer ARN for this region | See [Layer ARN](#layer-arn) |

The Lambda runtime must be **Python 3.10, 3.11, 3.12, or 3.13**. The Akto layer is Python-only.

---

## Layer ARN

Paste a **versioned** ARN (it ends in `:N`). Do not use an unversioned layer name.

Current public layer for **US East (N. Virginia) `us-east-1`**:

```text
arn:aws:lambda:us-east-1:041877753357:layer:akto-agentcore:3
```

Compatible with Python 3.10–3.13 and both `x86_64` and `arm64`.

If the gateway is in another region, use the versioned Akto layer ARN published for **that** region. The layer and the Lambda must be in the same region.

---

## Environment variables (both paths)

On the interceptor Lambda, **Configuration** → **Environment variables** → **Edit** → **Add environment variable**.

Required:

| Key | Value |
| --- | --- |
| `AKTO_DATA_INGESTION_URL` | Your Akto base URL |
| `AKTO_API_TOKEN` | Your Akto API token |

Optional (defaults match the deploy scripts):

| Key | Value |
| --- | --- |
| `AKTO_FAIL_OPEN` | `false` |
| `AKTO_TIMEOUT_SECONDS` | `30` |
| `AKTO_APPROVAL_WAIT_SECONDS` | `840` |
| `AKTO_APPROVAL_POLL_SECONDS` | `2` |

Then **Save**.

---

## Path A: New Lambda

Use this when the gateway does not already have an interceptor.

### A1. Create the Lambda function

1. Open [Lambda](https://console.aws.amazon.com/lambda/home) in the gateway’s region.
2. **Create function**.
3. **Author from scratch**.
4. **Function name:** `akto-guardrails-interceptor`.
5. **Runtime:** Python 3.12.
6. **Architecture:** x86_64 (or arm64 if that is what you use).
7. **Permissions:** **Create a new role with basic Lambda permissions** (or **Use an existing role** if you already have one).
8. **Create function**.

Wait until the function page loads.

### A2. Put in the handler code

1. On the **Code** tab, open `lambda_function.py` (or create `handler.py`).
2. Replace the file contents with:

```python
from akto_agentcore import lambda_handler
```

3. If the file is still named `lambda_function.py`, either:
   - rename it to `handler.py` in the editor, or
   - keep the filename and use handler `lambda_function.lambda_handler` in the next step.
4. **Deploy**.

Recommended: filename `handler.py`, handler `handler.lambda_handler`.

To set the handler:

1. Scroll to **Runtime settings** → **Edit**.
2. **Handler:** `handler.lambda_handler` (or `lambda_function.lambda_handler` if you kept that filename).
3. **Save**.

Do not paste `core.py` into the function. That code comes from the layer.

### A3. Attach the Akto layer

1. On the function page, scroll to **Layers**.
2. **Add a layer**.
3. **Specify an ARN**.
4. Paste the versioned layer ARN for this region.
5. **Add**.
6. Confirm the layer is listed under **Layers**.

### A4. Timeout, memory, and environment variables

1. **Configuration** → **General configuration** → **Edit**.
2. **Timeout:** 15 min 0 sec.
3. **Memory:** 256 MB.
4. **Save**.
5. Add the environment variables in [Environment variables](#environment-variables-both-paths).

Copy the **Function ARN** from the function overview (copy icon at the top). You will paste it on the gateway and in IAM.

### A5. Allow the gateway to invoke the function

The gateway’s **service role** (not the Lambda execution role) needs `lambda:InvokeFunction`.

1. Open [Amazon Bedrock AgentCore](https://console.aws.amazon.com/bedrock-agentcore/home#) → **Gateways** → your gateway.
2. Copy the **IAM role** name.
3. Open [IAM → Roles](https://console.aws.amazon.com/iam/home#/roles), search that name, open it.
4. **Add permissions** → **Create inline policy**.
5. **Visual** editor:
   - **Service:** Lambda
   - **Actions:** under **Write**, check **InvokeFunction**
   - **Resources:** **Specific** → **Add ARNs**
   - Paste the Lambda function ARN, or fill Region / Account / Function name (`akto-guardrails-interceptor`)
6. **Next**.
7. **Policy name:** `invoke-akto-guardrails-interceptor`.
8. **Create policy**.

### A6. Attach the interceptor on the gateway (AgentCore console)

1. Open [Amazon Bedrock AgentCore](https://console.aws.amazon.com/bedrock-agentcore/home#) → **Gateways**.
2. Select your gateway.
3. **Edit** (or open **Interceptors** if that tab is shown).
4. Find **Interceptors** (sometimes under **Additional configurations**).
5. Add / configure **one** interceptor:
   - **Lambda function:** `akto-guardrails-interceptor` (same region), or paste the Function ARN.
   - **Interception points:** **REQUEST** and **RESPONSE** (both).
   - **Pass request headers:** **true** / enabled.
6. Do not change inbound auth, IAM role, targets, KMS, WAF, or policy engine unless you intend to.
7. **Save** / **Update gateway**.

On the gateway details page, confirm:

- Interceptor Lambda is `akto-guardrails-interceptor`
- Points include REQUEST and RESPONSE
- Pass request headers is enabled

Continue at [Verify](#verify).

---

## Path B: Existing Lambda

Use this when the gateway already invokes a **Python 3.10–3.13** interceptor. Keep that function. Keep the existing gateway attachment.

If the existing interceptor is not Python, stop. Wrapping only works for Python. Attaching a new Akto Lambda would replace the current interceptor.

### B1. Attach the Akto layer

1. Open [Lambda](https://console.aws.amazon.com/lambda/home) in the gateway’s region.
2. Open the existing interceptor function.
3. Scroll to **Layers** → **Add a layer**.
4. **Specify an ARN** → paste the versioned Akto layer ARN for this region → **Add**.
5. Leave any other layers in place.

### B2. Environment variables and timeout

1. **Configuration** → **Environment variables** → **Edit**.
2. **Add environment variable** for each Akto key in [Environment variables](#environment-variables-both-paths). Do not delete keys the function already uses.
3. **Save**.
4. **Configuration** → **General configuration** → **Edit**.
5. **Timeout:** 15 min 0 sec if you use human approval.
6. **Save**.

If you cannot set 15 minutes, set `AKTO_APPROVAL_WAIT_SECONDS` lower than the function timeout.

### B3. Wrap the handler in the Lambda code editor

1. On the **Code** tab, open the file that AWS invokes. That name is under **Runtime settings** → **Handler** (for example `handler.lambda_handler` → file `handler.py`, function `lambda_handler`).
2. At the top of the file, add:

```python
from akto_agentcore import wrap_interceptor
```

3. After the existing handler is defined, wrap it. Do not change the interceptor body:

```python
def lambda_handler(event, context):
    # existing interceptor logic unchanged
    ...


lambda_handler = wrap_interceptor(lambda_handler)
```

If the handler is named `handler`, wrap `handler` instead and leave **Runtime settings → Handler** as it is.

4. **Deploy**.

If the Code tab will not open the source (package too large, or a container image):

1. Change the source the way you already ship this function.
2. Add the same import and wrap.
3. In the Lambda console, **Upload from** → **.zip file** (or a new image URI) → **Save**.

The existing handler must still return `interceptorOutputVersion` `"1.0"` and a top-level `mcp` or `http` object.

The wrapper runs your interceptor first, then Akto on the effective payload, then merges the result. Your headers and unrelated fields are kept. Akto’s allow / block / modify decision wins.

### B4. Confirm the gateway attachment in the AgentCore console

Do **not** point the gateway at a new function.

1. Open [Amazon Bedrock AgentCore](https://console.aws.amazon.com/bedrock-agentcore/home#) → **Gateways** → your gateway.
2. Check **Interceptors**:
   - Lambda is still this existing function.
   - Interception points are **REQUEST** and **RESPONSE**.
   - **Pass request headers** is enabled.
3. If either point is missing, or pass-request-headers is off: **Edit** the gateway, keep the **same** Lambda, set both points and pass-request-headers, **Save**.

If the gateway already invoked this function successfully, you do not need a new IAM policy. If invokes fail after this change, add the inline policy from [A5](#a5-allow-the-gateway-to-invoke-the-function) on the gateway role, using this function’s ARN.

Continue at [Verify](#verify).

---

## Verify

1. Call a tool through the gateway (MCP `tools/call`, or an HTTP target).
2. In the console: **CloudWatch** → **Log groups** → `/aws/lambda/<function-name>` → latest stream. You should see Akto REQUEST and RESPONSE log lines.
3. In Akto, confirm the call was allowed, blocked, modified, or sent for human approval.

Notes:

- Only MCP `tools/call` is guardrailed. `initialize`, `tools/list`, notifications, and ping pass through.
- AWS does not invoke HTTP interceptors for streaming targets.
- If the gateway excludes `RESPONSE_BODY`, Akto cannot scan that response body.

---

## Troubleshooting

| What you see | What to check in the console |
| --- | --- |
| Layer add fails | Region of the layer ARN matches the function. Runtime is Python 3.10–3.13. ARN ends with `:N`. |
| `Cannot find module akto_agentcore` | **Layers** on the function. Deploy the code **after** the layer is attached. |
| Gateway never calls the Lambda | Gateway role inline policy `InvokeFunction`. Gateway **Interceptors** lists this function for REQUEST and RESPONSE. |
| Existing interceptor stopped running | Gateway **Interceptors** was pointed at a new function. Edit the gateway and select the original function again, then use Path B. |
| Traffic blocked with no matching policy | `AKTO_FAIL_OPEN` is `false`. Check `AKTO_DATA_INGESTION_URL` and CloudWatch logs. |
| Human approval times out | Function timeout is 15 minutes. |
| Headers missing in the interceptor | Gateway interceptor **Pass request headers** is enabled. |
