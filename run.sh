#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

# Check for Homebrew (Mac only) and install if missing
if [[ "$(uname)" == "Darwin" ]]; then
  if ! command -v brew &>/dev/null; then
    echo "==> Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  fi

  if ! command -v python3 &>/dev/null || ! python3 -c "import sys; assert sys.version_info >= (3,11)" &>/dev/null; then
    echo "==> Installing Python 3 via Homebrew..."
    brew install python
  fi
fi

# Linux: just check python3 exists
if [[ "$(uname)" == "Linux" ]]; then
  if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 not found. Install it with: sudo apt install python3 python3-venv" >&2
    exit 1
  fi
fi

if [ ! -d ".venv" ]; then
  echo "==> Creating virtual environment..."
  python3 -m venv .venv
fi

source .venv/bin/activate

echo "==> Installing/updating dependencies..."
pip install -q -r requirements.txt

echo "==> Starting nym maestro..."
python app.py
