#!/data/data/com.termux/files/usr/bin/bash

set -eu

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

echo "==> Updating Termux package lists"
pkg update -y

echo "==> Installing system tools"
pkg install -y \
    python \
    git \
    curl \
    nmap \
    netcat-openbsd \
    dnsutils \
    iproute2 \
    net-tools \
    openssh

echo "==> Creating Python virtual environment"
if [ ! -d ".venv" ]; then
    python -m venv .venv
fi

echo "==> Installing NetProbe and development dependencies"
.venv/bin/python -m pip install -e ".[dev]"

echo
echo "Installation completed."
echo
echo "Activate the environment with:"
echo "  source .venv/bin/activate"
echo
echo "Run tests with:"
echo "  pytest -v"
