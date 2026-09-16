#!/usr/bin/env python3
"""Call an AgentCore Gateway directly, as an agent would.

The gateway is SigV4-authorized (authorizerType AWS_IAM), so a plain curl cannot
reach it — the request has to be signed. Stdlib only: credentials come from the
AWS CLI, so there is nothing to install.

  python3 scripts/mcp_call.py tools/list
  python3 scripts/mcp_call.py tools/call <namespaced-tool> '{"arg":"value"}'

Override the gateway with AKTO_GATEWAY_URL; the protocol version AWS accepts
differs per gateway and is reported in the error when it is wrong.
"""
import datetime, hashlib, hmac, json, os, subprocess, sys, urllib.request, urllib.error, urllib.parse

GATEWAY_URL = os.getenv("AKTO_GATEWAY_URL",
    "https://asl-gateway-demo-9lzr1onrx9.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp")
REGION  = os.getenv("AWS_REGION", "us-east-1")
SERVICE = "bedrock-agentcore"
MCP_VERSION = os.getenv("AKTO_MCP_VERSION", "2025-03-26")

def creds():
    c = json.loads(subprocess.run(["aws","configure","export-credentials","--format","process"],
                                  capture_output=True, text=True, check=True).stdout)
    return c["AccessKeyId"], c["SecretAccessKey"], c.get("SessionToken")

def sign(key, msg): return hmac.new(key, msg.encode(), hashlib.sha256).digest()

method = sys.argv[1] if len(sys.argv) > 1 else "tools/list"
body = {"jsonrpc":"2.0","id":1,"method":method,"params":{}}
if method == "tools/call":
    body["params"] = {"name": sys.argv[2], "arguments": json.loads(sys.argv[3])}
payload = json.dumps(body)

ak, sk, token = creds()
u = urllib.parse.urlparse(GATEWAY_URL); host, path = u.netloc, (u.path or "/")
now = datetime.datetime.now(datetime.UTC)
amzdate, datestamp = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
ph = hashlib.sha256(payload.encode()).hexdigest()
headers = {"content-type":"application/json","host":host,"mcp-protocol-version":MCP_VERSION,
           "x-amz-content-sha256":ph,"x-amz-date":amzdate}
if token: headers["x-amz-security-token"] = token
signed = ";".join(sorted(headers))
canon = f"POST\n{path}\n\n" + "".join(f"{k}:{headers[k]}\n" for k in sorted(headers)) + f"\n{signed}\n{ph}"
scope = f"{datestamp}/{REGION}/{SERVICE}/aws4_request"
sts = f"AWS4-HMAC-SHA256\n{amzdate}\n{scope}\n{hashlib.sha256(canon.encode()).hexdigest()}"
k = sign(sign(sign(sign(("AWS4"+sk).encode(), datestamp), REGION), SERVICE), "aws4_request")
headers["authorization"] = (f"AWS4-HMAC-SHA256 Credential={ak}/{scope}, "
                            f"SignedHeaders={signed}, Signature={hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()}")
headers["accept"] = "application/json, text/event-stream"
try:
    with urllib.request.urlopen(urllib.request.Request(GATEWAY_URL, data=payload.encode(), headers=headers), timeout=60) as r:
        print(f"HTTP {r.status}"); print(r.read().decode()[:20000])
except urllib.error.HTTPError as e:
    print(f"HTTP {e.code}"); print(e.read().decode()[:400])
