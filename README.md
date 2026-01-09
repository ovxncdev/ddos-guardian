# DDoS Guardian

Standalone DDoS protection layer for containerized applications.

## Architecture

```
Internet → DDoS Guardian → Nginx → Your Services
                ↓
           • Rate Limiting
           • Bot Detection
           • Request Logging
           • Security Headers
```

## Features

- **Rate Limiting** - Configurable requests per time window
- **Bot Detection** - Behavioral analysis with scoring
- **IP Blocking** - Automatic and manual blocking
- **Stealth Mode** - Hide server fingerprints
- **Request Logging** - Structured JSON logs
- **Health Checks** - Built-in endpoints
- **Docker Ready** - Multi-stage build, non-root user

## Quick Start

### With Docker Compose

```bash
# Production
docker-compose up -d

# Development (with mock services)
docker-compose -f docker-compose.dev.yml up
```

### Without Docker

```bash
# Install dependencies
npm install

# Configure
cp .env.example .env
# Edit .env with your settings

# Start
npm start
```

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | 3000 | Server port |
| `HOST` | 0.0.0.0 | Bind address |
| `UPSTREAM_HOSTS` | - | Comma-separated upstream URLs |
| `RATE_LIMIT_WINDOW_MS` | 60000 | Rate limit window (ms) |
| `RATE_LIMIT_MAX_REQUESTS` | 100 | Max requests per window |
| `RATE_LIMIT_BLOCK_DURATION_MS` | 300000 | Block duration (ms) |
| `BOT_DETECTION_ENABLED` | true | Enable bot detection |
| `BOT_SCORE_THRESHOLD` | 70 | Bot score threshold (0-100) |
| `LOG_LEVEL` | info | Log level (error/warn/info/debug) |
| `LOG_FORMAT` | json | Log format (json/pretty) |
| `TRUST_PROXY` | true | Trust X-Forwarded-For |
| `STEALTH_MODE` | true | Hide server fingerprints |

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `/health` | Health check |
| `/ready` | Readiness check |
| `/metrics` | Stats and metrics |
| `/*` | Proxied to upstream |

## Testing

```bash
# Run all tests
npm test

# Test specific module
npm run test:config
npm run test:env
npm run test:logging
npm run test:core

# Run test server
node tests/test-server.js
```

## API

### Rate Limit Headers

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 60
```

### Blocked Response (429)

```json
{
  "error": "Too Many Requests",
  "retryAfter": 300
}
```

### Bot Blocked Response (403)

```json
{
  "error": "Forbidden",
  "message": "Request blocked"
}
```

## Integration

### With Existing Nginx

```yaml
# docker-compose.yml
services:
  guardian:
    image: ddos-guardian
    ports:
      - "80:3000"
    environment:
      - UPSTREAM_HOSTS=http://your-nginx:80
    
  your-nginx:
    image: nginx
    expose:
      - "80"
```

### With Multiple Services

```yaml
environment:
  - UPSTREAM_HOSTS=http://service-a:3000,http://service-b:8080
```

## Bot Detection Signals

| Signal | Score | Description |
|--------|-------|-------------|
| Missing User-Agent | +30 | No or short UA |
| Known Bot | +20 | Googlebot, etc. |
| Suspicious UA | +15 | curl, wget, python |
| Bad Pattern | +50 | sqlmap, nikto |
| Missing Accept | +10 | No Accept header |
| Missing Accept-Language | +10 | No language |
| Rapid Requests | +15-35 | Too fast |

Score ≥ 70 = blocked (configurable)

## License

MIT
