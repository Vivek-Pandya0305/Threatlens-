#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
python3 - <<'PY'
import sys
if sys.version_info < (3,10): raise SystemExit("Python 3.10+ required")
PY
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python run.py
