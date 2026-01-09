/**
 * Test Server
 * 
 * A real HTTP server to test rate limiting with actual requests.
 * 
 * Run: node tests/test-server.js
 * 
 * Then test with:
 *   curl http://localhost:3333/api/test
 *   curl http://localhost:3333/health
 *   curl http://localhost:3333/stats
 */

const http = require('http');
const { RateLimiter } = require('../src/core');
const logger = require('../src/logging');

// Config
const PORT = 3333;
const HOST = '0.0.0.0';

// Create rate limiter
const limiter = new RateLimiter({
    windowMs: 60000,        // 1 minute window
    maxRequests: 10,        // 10 requests per minute (low for testing)
    blockDurationMs: 30000, // 30 second block
    trustProxy: true,
    skipPaths: ['/health', '/ready', '/stats'],
});

/**
 * Parse URL path
 */
const parsePath = (url) => {
    return url.split('?')[0];
};

/**
 * Send JSON response
 */
const sendJson = (res, statusCode, data) => {
    res.writeHead(statusCode, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data, null, 2));
};

/**
 * Request handler
 */
const handleRequest = (req, res) => {
    const path = parsePath(req.url);
    const startTime = Date.now();
    
    // Check rate limit
    const result = limiter.check(req);
    
    // Add rate limit headers
    res.setHeader('X-RateLimit-Limit', limiter.tracker.maxRequests);
    res.setHeader('X-RateLimit-Remaining', result.remaining);
    res.setHeader('X-RateLimit-Reset', Math.ceil(result.resetMs / 1000));
    
    // If blocked, return 429
    if (!result.allowed) {
        logger.warn('Request blocked', {
            ip: result.ip,
            path,
            reason: result.reason,
        });
        
        res.setHeader('Retry-After', Math.ceil(result.resetMs / 1000));
        return sendJson(res, 429, {
            error: 'Too Many Requests',
            reason: result.reason,
            retryAfter: Math.ceil(result.resetMs / 1000),
            ip: result.ip,
        });
    }
    
    // Route handling
    switch (path) {
        case '/':
            return sendJson(res, 200, {
                message: 'DDoS Guardian Test Server',
                endpoints: [
                    'GET /api/test - Test endpoint (rate limited)',
                    'GET /health - Health check (not rate limited)',
                    'GET /stats - Rate limiter stats',
                    'GET /block/:ip - Block an IP',
                    'GET /unblock/:ip - Unblock an IP',
                ],
            });
        
        case '/api/test':
            return sendJson(res, 200, {
                success: true,
                message: 'Request allowed',
                remaining: result.remaining,
                ip: result.ip,
                timestamp: new Date().toISOString(),
            });
        
        case '/health':
            return sendJson(res, 200, {
                status: 'healthy',
                uptime: process.uptime(),
            });
        
        case '/ready':
            return sendJson(res, 200, { ready: true });
        
        case '/stats':
            const stats = limiter.getStats();
            return sendJson(res, 200, {
                rateLimit: {
                    windowMs: limiter.tracker.windowMs,
                    maxRequests: limiter.tracker.maxRequests,
                    blockDurationMs: limiter.tracker.blockDurationMs,
                },
                current: stats,
            });
        
        default:
            // Handle /block/:ip and /unblock/:ip
            if (path.startsWith('/block/')) {
                const ip = path.replace('/block/', '');
                limiter.blockIp(ip, 60000, 'manual_test');
                return sendJson(res, 200, { blocked: ip });
            }
            
            if (path.startsWith('/unblock/')) {
                const ip = path.replace('/unblock/', '');
                limiter.unblockIp(ip);
                return sendJson(res, 200, { unblocked: ip });
            }
            
            return sendJson(res, 404, { error: 'Not Found' });
    }
};

// Create server
const server = http.createServer(handleRequest);

// Start server
server.listen(PORT, HOST, () => {
    console.log('');
    console.log('╔════════════════════════════════════════════════════════╗');
    console.log('║         DDoS Guardian - Test Server Running            ║');
    console.log('╠════════════════════════════════════════════════════════╣');
    console.log(`║  URL: http://${HOST}:${PORT}                             ║`);
    console.log('║                                                        ║');
    console.log('║  Rate Limit: 10 requests per minute                    ║');
    console.log('║  Block Duration: 30 seconds                            ║');
    console.log('╠════════════════════════════════════════════════════════╣');
    console.log('║  Test Commands:                                        ║');
    console.log('║                                                        ║');
    console.log('║  # Single request                                      ║');
    console.log(`║  curl http://localhost:${PORT}/api/test                  ║`);
    console.log('║                                                        ║');
    console.log('║  # Spam requests (will get blocked)                    ║');
    console.log(`║  for i in {1..15}; do curl -s http://localhost:${PORT}/api/test | head -1; done  ║`);
    console.log('║                                                        ║');
    console.log('║  # Check stats                                         ║');
    console.log(`║  curl http://localhost:${PORT}/stats                     ║`);
    console.log('║                                                        ║');
    console.log('║  # Health check (bypasses rate limit)                  ║');
    console.log(`║  curl http://localhost:${PORT}/health                    ║`);
    console.log('║                                                        ║');
    console.log('║  Press Ctrl+C to stop                                  ║');
    console.log('╚════════════════════════════════════════════════════════╝');
    console.log('');
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\nShutting down...');
    limiter.destroy();
    server.close(() => {
        console.log('Server stopped');
        process.exit(0);
    });
});
