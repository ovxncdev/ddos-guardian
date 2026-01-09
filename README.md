# DDoS Guardian

Standalone DDoS protection layer for any web application.

## Features

- **Rate Limiting** - Configurable requests per time window
- **Bot Detection** - Behavioral analysis with scoring
- **IP Blocking** - Automatic and manual blocking
- **Stealth Mode** - Hide server fingerprints
- **Request Logging** - Structured JSON logs
- **Health Checks** - Built-in endpoints
- **Docker Ready** - Multi-stage build, non-root user

## Quick Start

### Protect any service

```bash
# Clone the repo
git clone https://github.com/ovxncdev/ddos-guardian.git
cd ddos-guardian

# Protect a service running on port 8080
UPSTREAM_HOSTS=http://host.docker.internal:8080 docker-compose up -d

# Now access your service through port 80 (protected)
curl http://localhost/
```

### Using .env file

```bash
# Create .env
cat > .env << EOF
UPSTREAM_HOSTS=http://host.docker.internal:8080
RATE_LIMIT_MAX_REQUESTS=100
BOT_DETECTION_ENABLED=true
EOF

# Start
docker-compose up -d
```

### Without Docker

```bash
npm install
UPSTREAM_HOSTS=http://localhost:8080 npm start
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `GUARDIAN_PORT` | 80 | Port guardian listens on |
| `UPSTREAM_HOSTS` | - | Backend service URL(s), comma-separated |
| `RATE_LIMIT_WINDOW_MS` | 60000 | Rate limit window (ms) |
| `RATE_LIMIT_MAX_REQUESTS` | 100 | Max requests per window |
| `RATE_LIMIT_BLOCK_DURATION_MS` | 300000 | Block duration (ms) |
| `BOT_DETECTION_ENABLED` | true | Enable bot detection |
| `BOT_SCORE_THRESHOLD` | 70 | Bot score threshold (0-100) |
| `LOG_LEVEL` | info | Log level (error/warn/info/debug) |
| `STEALTH_MODE` | true | Hide server fingerprints |

## Architecture

```
Internet → DDoS Guardian (port 80) → Your Service (any port)
                ↓
           • Rate Limiting
           • Bot Detection
           • Security Headers
           • Request Logging
```

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `/health` | Health check |
| `/ready` | Readiness check |
| `/metrics` | Stats and metrics (JSON) |
| `/*` | Proxied to upstream |

## Integration Examples

### With any Docker service

```yaml
# your-app/docker-compose.yml
services:
  ddos-guardian:
    image: ddos-guardian
    ports:
      - "80:3000"
    environment:
      - UPSTREAM_HOSTS=http://myapp:3000
    depends_on:
      - myapp

  myapp:
    image: your-app
    expose:
      - "3000"
```

### With external service

```bash
# Protect a service running on the host
UPSTREAM_HOSTS=http://host.docker.internal:8080 docker-compose up -d
```

### Multiple upstreams (load balancing)

```bash
UPSTREAM_HOSTS=http://app1:3000,http://app2:3000 docker-compose up -d
```

## API Responses

### Rate Limited (429)
```json
{
  "error": "Too Many Requests",
  "retryAfter": 300
}
```

### Bot Blocked (403)
```json
{
  "error": "Forbidden",
  "message": "Request blocked"
}
```

### Metrics
```json
{
  "rateLimit": {
    "totalIps": 150,
    "blockedIps": 3,
    "totalRequests": 10000
  },
  "botDetection": {
    "enabled": true,
    "threshold": 70
  },
  "uptime": 3600
}
```

## License

MIT
