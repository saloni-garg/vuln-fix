#!/bin/bash
# Pod bootstrap for the VulnFix-RL Phase 3 pilot. Run ON the pod,
# from the project root (the rsync target), after the project tree
# has been copied. Idempotent-ish; logs to stdout for the run sheet.
#
# - System python (image: torch 2.4.0) gets the training stack:
#   transformers + pyyaml (tokenizers/safetensors come as deps).
# - The grading environments are recreated to match the local ones:
#   project .venv and the two dependency-specific aiohttp venvs
#   (.venv-aiohttp39 and .venv-aiohttp313) all use CPython 3.12,
#   matching the verified local interpreters, with packages from
#   their respective freezes in pilot/pod_env/. The directory names
#   are historical labels only; they do not indicate the local
#   interpreter versions. uv supplies a standalone CPython 3.12
#   build because the image ships only Python 3.11.
set -euo pipefail
cd "$(dirname "$0")/../.."
echo "[bootstrap] project root: $PWD"

python3 -m pip install --quiet transformers==4.46.3 pyyaml==6.0.3
python3 -c "import torch, transformers; print('[bootstrap] torch', torch.__version__, 'transformers', transformers.__version__, 'cuda', torch.cuda.is_available())"

python3 -m pip install --quiet uv
export PATH="$HOME/.local/bin:$PATH"
uv python install 3.12

uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r pilot/pod_env/requirements_project.txt
uv venv --python 3.12 .venv-aiohttp39
uv pip install --python .venv-aiohttp39/bin/python -r pilot/pod_env/requirements_aiohttp39.txt
uv venv --python 3.12 .venv-aiohttp313
uv pip install --python .venv-aiohttp313/bin/python -r pilot/pod_env/requirements_aiohttp313.txt

.venv/bin/python -c "import pytest; print('[bootstrap] project venv pytest', pytest.__version__)"
.venv-aiohttp39/bin/python --version
.venv-aiohttp313/bin/python --version
nvidia-smi --query-gpu=name,memory.total --format=csv
echo "[bootstrap] done"
