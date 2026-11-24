# Production Deployment Guide: Secure Agentic C++ Debugger

This guide covers deploying the Secure Agentic C++ Debugging Assistant to a production server (AWS EC2, DigitalOcean, GCP, Azure, or On-Premise Linux Server).

---

## 1. System Requirements

| Specification | Minimum (CPU-only) | Recommended (with GPU) |
|---|---|---|
| **OS** | Ubuntu 22.04 / 24.04 LTS, Debian 12 | Ubuntu 22.04 / 24.04 LTS |
| **CPU** | 4 vCPUs | 4+ vCPUs |
| **RAM** | 8 GB RAM (for Llama 3 8B Q4) | 16 GB RAM |
| **GPU** | Not required | NVIDIA GPU with 8GB+ VRAM (CUDA 12+) |
| **Disk** | 30 GB SSD | 50 GB NVMe SSD |
| **Software** | Docker Engine & Docker Compose | Docker Engine + NVIDIA Container Toolkit |

---

## 2. Quick One-Command Deployment (Docker Compose)

The repository includes a self-contained production stack in `docker-compose.prod.yml`:

```bash
# 1. Clone the repository on your server
git clone <your-repo-url> cpp-debugger
cd cpp-debugger

# 2. Launch the full production stack
make prod-up
# (or: docker compose -f docker-compose.prod.yml up -d --build)
```

### What happens automatically:
1. **Ollama Service** starts with persistent model storage (`ollama_data`).
2. **Model Initializer** automatically pulls `llama3` into Ollama.
3. **Sandbox Builder** automatically compiles the isolated `cpp-debug-sandbox:latest` image on the host Docker daemon.
4. **Web App** builds and launches Streamlit on port `8501`.

Check service logs:
```bash
make prod-logs
# or
docker compose -f docker-compose.prod.yml logs -f app
```

To stop the services:
```bash
make prod-down
```

---

## 3. GPU Acceleration (Optional, for 5x faster inference)

If deploying to a server with an NVIDIA GPU (e.g. AWS `g4dn.xlarge` or GCP `g2-standard-4`):

1. Install the [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html).
2. In `docker-compose.prod.yml`, add the `deploy` block under `ollama`:

```yaml
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]
```

---

## 4. Domain & SSL / HTTPS Setup (Nginx Reverse Proxy)

Streamlit uses WebSockets for interactive updates. Use the provided [nginx.conf](file:///Users/arpit/Downloads/24CSB0A58_CD_Final_Codes%202/nginx.conf) with Certbot:

```bash
# 1. Install Nginx and Certbot
sudo apt update && sudo apt install -y nginx certbot python3-certbot-nginx

# 2. Copy configuration
sudo cp nginx.conf /etc/nginx/sites-available/cpp-debugger
sudo ln -s /etc/nginx/sites-available/cpp-debugger /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# 3. Obtain free Let's Encrypt SSL certificate
sudo certbot --nginx -d yourdomain.com
```

---

## 5. Security & Isolation in Production

* **Per-Job Isolation:** Student code executes inside ephemeral containers with:
  * Non-root user `UID 65534` (`nobody`)
  * Network disabled (`--network none`)
  * Read-only root filesystem
  * Memory ceiling: `256m`
  * Dropped capabilities (`--cap-drop ALL`, only `SYS_PTRACE` added for debugger attachment)
* **Audit Logging:** If local audit logging is enabled in the UI, sanitized excerpts are stored in `system_interactions.json` mounted on the host.
