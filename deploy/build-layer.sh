#!/usr/bin/env bash
# Build a byte-for-byte reproducible Akto AgentCore Lambda layer.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SOURCE_DIR="${REPO_ROOT}/lambda/layer"
OUTPUT="${1:-${REPO_ROOT}/dist/akto-agentcore-layer.zip}"

mkdir -p "$(dirname "${OUTPUT}")"

python3 - "${SOURCE_DIR}" "${OUTPUT}" <<'PY'
import stat
import sys
import zipfile
from pathlib import Path

source = Path(sys.argv[1])
output = Path(sys.argv[2])
files = sorted(
    path for path in source.rglob("*")
    if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
)

with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for path in files:
        relative = path.relative_to(source).as_posix()
        info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        archive.writestr(info, path.read_bytes(), compresslevel=9)

print(output)
PY
