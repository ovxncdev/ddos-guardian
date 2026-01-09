# DDoS Guardian Dockerfile
# Multi-stage build for smaller image

# === Build Stage ===
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies (production only)
RUN npm install --omit=dev

# === Production Stage ===
FROM node:20-alpine

# Security: run as non-root user with docker group access
# Group 113 is typically the docker group on the host
RUN addgroup -g 113 docker && \
    addgroup -g 1001 guardian && \
    adduser -u 1001 -G guardian -s /bin/sh -D guardian && \
    addgroup guardian docker

WORKDIR /app

# Copy from builder
COPY --from=builder /app/node_modules ./node_modules

# Copy source code
COPY src ./src
COPY package.json ./

# Create directories for logs/data
RUN mkdir -p /var/log/ddos-guardian /var/lib/ddos-guardian && \
    chown -R guardian:guardian /var/log/ddos-guardian /var/lib/ddos-guardian /app

# Switch to non-root user
USER guardian

# Environment defaults
ENV NODE_ENV=production \
    PORT=3000 \
    HOST=0.0.0.0 \
    LOG_LEVEL=info \
    LOG_FORMAT=json

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

# Start
CMD ["node", "src/index.js"]
