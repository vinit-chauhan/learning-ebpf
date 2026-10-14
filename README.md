# KernelPulse — Interactive eBPF & Linux Kernel Academy

[![Docker Image](https://github.com/vinit-chauhan/learning-ebpf/actions/workflows/docker-build-publish.yml/badge.svg)](https://github.com/vinit-chauhan/learning-ebpf/actions/workflows/docker-build-publish.yml)
[![Version](https://img.shields.io/badge/version-1.0.1-blue.svg)](.version)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

An interactive systems programming academy for mastering **Linux eBPF**, **Kernel C**, and **Go (`cilium/ebpf`)**. Features an animated in-browser kernel execution pipeline simulator, interactive verifier checks, 15 guided lab tutorials, and comprehensive reference encyclopedias for Linux syscalls, BPF helpers, and `SEC()` macros.

---

## 🚀 Running with Docker (Recommended)

Pre-built Docker images are published to the **GitHub Container Registry (GHCR)** automatically on every release.

### 1. Pull the Image

Pull the latest release from GHCR:

```bash
docker pull ghcr.io/vinit-chauhan/learning-ebpf:latest
```

Or pull a specific pinned version:

```bash
docker pull ghcr.io/vinit-chauhan/learning-ebpf:1.0.1
```

> **Note:** If pulling from a private GitHub repository, log in to GHCR first:
> ```bash
> echo "$CR_PAT" | docker login ghcr.io -u <your-github-username> --password-stdin
> ```

---

### 2. Run the Container

Run the container locally and map port `8080` (or any available port) on your host to port `80` in the container:

```bash
docker run -d \
  --name learning-ebpf \
  -p 8080:80 \
  --restart unless-stopped \
  ghcr.io/vinit-chauhan/learning-ebpf:latest
```

Open your browser and navigate to:

👉 **[http://localhost:8080](http://localhost:8080)**

---

### 3. Useful Docker Commands

```bash
# View container logs
docker logs -f learning-ebpf

# Check health status
docker inspect --format='{{json .State.Health}}' learning-ebpf

# Stop the container
docker stop learning-ebpf

# Restart the container
docker start learning-ebpf

# Remove the container
docker rm -f learning-ebpf
```

---

### 4. Running with Docker Compose

Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  learning-ebpf:
    image: ghcr.io/vinit-chauhan/learning-ebpf:latest
    container_name: learning-ebpf
    ports:
      - "8080:80"
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://localhost/healthz"]
      interval: 30s
      timeout: 5s
      retries: 3
```

Start with:

```bash
docker compose up -d
```

---

## 🛠️ Building the Docker Image Locally

To build the image locally from source:

```bash
# Clone the repository
git clone https://github.com/vinit-chauhan/learning-ebpf.git
cd learning-ebpf

# Build Docker image
docker build -t learning-ebpf:local .

# Run the local image
docker run -d --name learning-ebpf-local -p 8080:80 learning-ebpf:local
```

---

## 💻 Local Development (Without Docker)

### Prerequisites

- **Node.js**: v20 or v22
- **npm**: v10+

### Steps

```bash
# 1. Install dependencies
npm install

# 2. Run the Vite development server (starts on http://localhost:3000)
npm run dev

# 3. Type check & lint
npm run lint

# 4. Build for production
npm run build

# 5. Preview the production build locally
npm run preview
```

---

## 📚 What's Inside

| Module | Description |
| :--- | :--- |
| **Concepts & Flows** | Deep dives into eBPF architecture, BPF verifier constraints, JIT compilation, BPF maps, ring buffers, and CO-RE (Compile Once – Run Everywhere). |
| **Lab Tutorials** | 15 hands-on tutorials organized by Beginner, Intermediate, and Advanced tiers using Go (`cilium/ebpf`) and modern kernel C (`vmlinux.h`). |
| **Linux Syscalls Reference** | Detailed reference for traceable Linux system calls with kernel source explanations, signatures, and tracepoints (`sys_enter_execve`, `sys_enter_openat`, etc.). |
| **BPF Helpers & Kfuncs** | Catalog of BPF helper functions (`bpf_probe_read_user`, `bpf_ringbuf_output`, etc.) and modern kernel functions (`kfuncs`). |
| **eBPF Macros & `SEC()`** | Reference guide for section definitions (`SEC("kprobe")`, `SEC("xdp")`, `SEC("tracepoint")`), map definition macros, and CO-RE helpers. |
| **Kernel Simulator** | Interactive real-time visualizer simulating event arrival, hook execution, verifier checks, BPF map updates, and ring buffer userspace consumption. |
| **Project Templates** | Production-ready boilerplate repositories for Go + C eBPF projects, XDP packet filters, TC ingress schedulers, and tracepoint loggers. |

---

## 🔄 Automated CI/CD & Versioning

This project uses GitHub Actions to automate image builds:

1. Update the version number in `.version` (e.g., `1.0.2`).
2. Commit and merge the changes into `main` or `master`.
3. The workflow (`.github/workflows/docker-build-publish.yml`):
   - Reads the new version.
   - Builds the multi-stage Docker image with layer caching.
   - Pushes tags `:<version>`, `:latest`, and `:sha-<commit>` to `ghcr.io/vinit-chauhan/learning-ebpf`.
   - Creates a matching Git release tag (e.g. `v1.0.2`).

---

## 📄 License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.
