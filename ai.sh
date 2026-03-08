#!/bin/bash

# ==============================================================================
# Code Analysis Agent Runner
# Made by Macowen Keru
# Contact: macowenkeru@gmail.com
# ==============================================================================

# Script Directory
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="$1"

show_help() {
    echo "=============================================================================="
    echo "                      Code Analysis Agent                                     "
    echo "=============================================================================="
    echo "Made by: Macowen Keru"
    echo "Contact: macowenkeru@gmail.com"
    echo ""
    echo "Description:"
    echo "  A LangGraph-based cybersecurity agent that analyzes source code files for"
    echo "  vulnerabilities, logic flows, and potential threats."
    echo ""
    echo "System Requirements:"
    echo "  - Python 3.10+"
    echo "  - uv (Fast Python Package Installer & Resolver)"
    echo "  - Ollama (running locally)"
    echo "  - Model: 'deepseek-v3.2:cloud' pulled via Ollama"
    echo "    (Note: The model can be changed in agent.py -> llm configuration)"
    echo ""
    echo "Usage:"
    echo "  ./ai.sh [path/to/analyze]"
    echo "  If no path is provided, you will be prompted to enter one interactively."
    echo ""
    echo "Options:"
    echo "  --help, -h      Show this help message and exit"
    echo "=============================================================================="
}

if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
    show_help
    exit 0
fi

# Check for uv
if ! command -v uv &> /dev/null; then
    echo "[!] Error: 'uv' is not installed or not in PATH."
    echo "    Please install: curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
fi

# Setup Virtual Environment if neither .venv nor venv exists
if [ ! -d "$DIR/.venv" ] && [ ! -d "$DIR/venv" ]; then
    echo "[*] No virtual environment found. Creating one with 'uv'..."
    cd "$DIR" || exit 1
    uv venv
    echo "[*] Syncing dependencies..."
    uv sync
else
    # Always sync to ensure dependencies are up to date
    echo "[*] Virtual environment found. Ensuring dependencies are synced..."
    cd "$DIR" || exit 1
    uv sync
fi

# Run the agent using uv run 
echo "[*] Starting Code Analysis Agent..."
if [ -n "$TARGET_DIR" ]; then
    uv run agent.py "$TARGET_DIR"
else
    uv run agent.py
fi
