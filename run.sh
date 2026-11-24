#!/usr/bin/env bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

echo "=================================================="
echo "🛡️ Starting Agentic AI Multi-Language Compiler & Debugger..."
echo "=================================================="

# 1. Check Docker (instant fallback to local mode if not running or if updating)
if [[ "${1:-}" == "--no-docker" || "${1:-}" == "--local" || "${DISABLE_DOCKER:-}" == "1" ]]; then
    export DISABLE_DOCKER=1
    echo "⚡ Local Isolated Sandbox mode forced (--no-docker). Skipping Docker."
elif docker info >/dev/null 2>&1; then
    echo "✅ Docker is running!"
else
    export DISABLE_DOCKER=1
    echo "⚡ Docker is not running or is updating. Fast-launching in Local Isolated Sandbox mode!"
fi

# 2. Check Ollama
if ! curl -sf http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
    echo "🧠 Ollama is not responding on 11434. Starting Ollama in background..."
    if command -v ollama >/dev/null 2>&1; then
        ollama serve >/dev/null 2>&1 &
        sleep 3
    else
        echo "⚠️ Ollama CLI not found in PATH. Make sure Ollama Desktop is running."
    fi
else
    echo "✅ Ollama is running!"
fi

# 3. Start Streamlit App
echo "🚀 Launching Web Interface..."
if [ -f "$DIR/.venv/bin/streamlit" ]; then
    "$DIR/.venv/bin/streamlit" run "$DIR/app.py"
elif [ -f "$DIR/.venv/bin/python3" ]; then
    "$DIR/.venv/bin/python3" -m streamlit run "$DIR/app.py"
elif command -v streamlit >/dev/null 2>&1; then
    streamlit run "$DIR/app.py"
else
    echo "❌ Error: Could not locate streamlit. Please run: pip install -r requirements.txt"
    exit 1
fi

