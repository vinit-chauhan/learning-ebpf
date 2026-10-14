# ==============================================================================
# Multi-stage Dockerfile for KernelPulse eBPF Academy
# ==============================================================================

# Stage 1: Build the Vite + React application
FROM node:22-alpine AS builder

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm install

# Copy source files and configuration
COPY . .

# Run production build
RUN npm run build

# Stage 2: Serve static files with high-performance Nginx Alpine
FROM nginx:1.27-alpine AS runner

LABEL maintainer="KernelPulse Maintainers"
LABEL org.opencontainers.image.title="KernelPulse eBPF Academy"
LABEL org.opencontainers.image.description="Interactive eBPF & Linux Kernel Systems Programming Academy"

# Remove default nginx static assets
RUN rm -rf /usr/share/nginx/html/*

# Copy custom nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy built artifacts from the builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Expose HTTP port 80
EXPOSE 80

# Container healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost/healthz || exit 1

# Launch nginx
CMD ["nginx", "-g", "daemon off;"]
