.PHONY: setup sandbox ollama pull-model app doctor

IMAGE ?= cpp-debug-sandbox:latest

setup: sandbox ollama pull-model
	python3 -m pip install -r requirements.txt

sandbox:
	docker build -t $(IMAGE) .

ollama:
	docker compose up -d ollama

pull-model:
	docker compose exec ollama ollama pull llama3

app:
	streamlit run app.py

doctor:
	@docker info >/dev/null 2>&1 && echo "docker: ok" || echo "docker: NOT RUNNING"
	@docker image inspect $(IMAGE) >/dev/null 2>&1 && echo "sandbox image: ok" || echo "sandbox image: MISSING (make sandbox)"
	@curl -sf http://127.0.0.1:11434/api/tags >/dev/null && echo "ollama: ok" || echo "ollama: NOT REACHABLE on :11434"

prod-up:
	docker compose -f docker-compose.prod.yml up -d --build

prod-down:
	docker compose -f docker-compose.prod.yml down

prod-logs:
	docker compose -f docker-compose.prod.yml logs -f app
