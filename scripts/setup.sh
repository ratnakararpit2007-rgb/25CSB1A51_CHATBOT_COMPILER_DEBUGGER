#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> Checking Docker"
if ! docker info >/dev/null 2>&1; then
  echo "Docker is not running. Start Docker Desktop and retry."
  exit 1
fi

echo "==> Building sandbox image cpp-debug-sandbox:latest"
docker build -t cpp-debug-sandbox:latest .

echo "==> Starting Ollama on localhost:11434"
docker compose up -d ollama

echo "==> Waiting for Ollama"
for i in {1..40}; do
  if curl -sf http://127.0.0.1:11434/api/tags >/dev/null; then
    break
  fi
  sleep 1
done

if ! curl -sf http://127.0.0.1:11434/api/tags >/dev/null; then
  echo "Ollama did not become ready. Check: docker compose logs ollama"
  exit 1
fi

echo "==> Pulling llama3 (this can take a while)"
docker compose exec ollama ollama pull llama3

echo "==> Installing Python deps"
python3 -m pip install -r requirements.txt

echo
echo "Setup complete."
echo "  make doctor     # check docker + image + ollama"
echo "  make app        # streamlit run app.py"
echo "If you use native Ollama instead of Compose, run: ollama serve && ollama pull llama3"
