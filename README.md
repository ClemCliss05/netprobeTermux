# NetProbe

A lightweight network diagnostics CLI tool written in Python.

Designed for Termux and Linux environments.

## Current Features

- TCP port scanning
- Connection status detection
- Connection latency measurement
- Automated tests

## Planned Features

- DNS resolution
- HTTP diagnostics
- TLS certificate inspection
- Network diagnostics reports

## Requirements

- Termux or Linux
- Python 3.10+
- Git

## Installation on Termux

Clone the repository:

    git clone REPOSITORY_URL
    cd networkTermux

Run the installation script:

    bash toolInstall.sh

Activate the Python environment:

    source .venv/bin/activate

## Development

Run the tests:

    pytest -v

Check Python syntax:

    python -m compileall -q src tests

Install the project in editable mode:

    python -m pip install -e ".[dev]"

## Project Structure

    src/netprobe/    Application source code
    tests/           Automated tests
    logs/            Runtime logs
    toolInstall.sh   Termux environment installer

## Development Environment

The project uses a Python virtual environment (.venv).

Development dependencies are defined in pyproject.toml.

## Project Status

Under active development.
