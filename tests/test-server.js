/**
 * Test Server with Mock Upstream
 * 
 * Starts both ddos-guardian and a mock upstream service.
 * 
 * Run: node tests/test-server.js
 */

const http = require('http');
const { Proxy } = require('../src/core');
const {
    rateLimitMiddleware,
    requestIdMiddleware,
    securityHeadersMiddleware,
    loggerMiddleware,
    botDetectionMiddleware,
} = require('../src/middleware');

// Ports
const GUARDIAN_PORT = 3333;
const UPSTREAM_PORT = 3334;

/**
 * Create mock upstream server (simulates your Nginx/services)
 */
const createUpstream = () => {
    const server = http.createServer((req, res) => {
        const path = req.url.split('?')[0];
        
        res.setHeader('Content-Type', 'application/json');
        
        switch (path) {
            case '/health':
                res.end(JSON.stringify({ status: 'upstream healthy' }));
                break;
            
            case '/api/users':
                res.end(JSON.stringify({
                    users: [
                        { id: 1, name: 'Alice' },
                        { id: 2, name: 'Bob' },
                    ],
                    servedBy: 'upstream',
                    requestId: req.headers['x-request-id'],
                }));
                break;
            
            case '/api/data':
                res.end(JSON.stringify({
                    data: { message: 'Hello from upstream!' },
                    headers: {
                        'x-forwarded-for': req.headers['x-forwarded-for'],
                        'x-request-id': req.headers['x-request-id'],
                    },
                }));
                break;
            
            default:
                res.end(JSON.stringify({
                    path,
                    method: req.method,
                    message: 'Upstream received request',
                    requestId: req.headers['x-request-id'],
                }));
        }
    });
    
    return server;
};

/**
 * Create guardian proxy server
 */
const createGuardian = () => {
    // Middleware
    const rateLimit = rateLimitMiddleware({
        windowMs: 60000,
        maxRequests: 10,
        blockDurationMs: 30000,
        skipPaths: ['/health', '/ready', '/metrics'],
    });
    
    const botDetection = botDetectionMiddleware({
        threshold: 70,
        blockBots: true,
    });
    
    const requestId = requestIdMiddleware();
    const securityHeaders = securityHeadersMiddleware({ stealth: false });
    const requestLogger = loggerMiddleware({ skipPaths: ['/health'] });
    
    // Proxy to upstream
    const proxy = new Proxy({
        targets: [`http://localhost:${UPSTREAM_PORT}`],
        timeout: 5000,
    });
    
    // Middleware runner
    const runMiddleware = (middlewares, req, res, callback) => {
        let index = 0;
        const next = (err) => {
            if (err || res.writableEnded) return;
            const mw = middlewares[index++];
            if (mw) mw(req, res, next);
            else callback();
        };
        next();
    };
    
    // Send JSON
    const sendJson = (res, code, data) => {
        res.statusCode = code;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify(data, null, 2));
    };
    
    // Request handler
    const server = http.createServer((req, res) => {
        const middlewares = [
            requestId,
            securityHeaders,
            botDetection,
            rateLimit,
            requestLogger,
        ];
        
        runMiddleware(middlewares, req, res, () => {
            const path = req.url.split('?')[0];
            
            // Guardian endpoints
            switch (path) {
                case '/health':
                    return sendJson(res, 200, { status: 'guardian healthy' });
                
                case '/metrics':
                    return sendJson(res, 200, {
                        rateLimit: rateLimit.limiter.getStats(),
                        botDetection: botDetection.detector.getStats(),
                        proxy: proxy.getStats(),
                    });
                
                default:
                    // Forward to upstream
                    proxy.forward(req, res);
            }
        });
    });
    
    server.cleanup = () => {
        rateLimit.destroy();
        botDetection.destroy();
    };
    
    return server;
};

/**
 * Start both servers
 */
const start = () => {
    const upstream = createUpstream();
    const guardian = createGuardian();
    
    upstream.listen(UPSTREAM_PORT, () => {
        guardian.listen(GUARDIAN_PORT, () => {
            console.log('');
            console.log('╔════════════════════════════════════════════════════════╗');
            console.log('║         DDoS Guardian - Full Test Environment          ║');
            console.log('╠════════════════════════════════════════════════════════╣');
            console.log(`║  Guardian: http://localhost:${GUARDIAN_PORT}                      ║`);
            console.log(`║  Upstream: http://localhost:${UPSTREAM_PORT} (mock service)       ║`);
            console.log('╠════════════════════════════════════════════════════════╣');
            console.log('║  Test Commands:                                        ║');
            console.log('║                                                        ║');
            console.log('║  # Request through guardian → upstream                 ║');
            console.log(`║  curl http://localhost:${GUARDIAN_PORT}/api/data                  ║`);
            console.log(`║  curl http://localhost:${GUARDIAN_PORT}/api/users                 ║`);
            console.log('║                                                        ║');
            console.log('║  # Check metrics                                       ║');
            console.log(`║  curl http://localhost:${GUARDIAN_PORT}/metrics                   ║`);
            console.log('║                                                        ║');
            console.log('║  # Test rate limiting (spam requests)                  ║');
            console.log(`║  for i in {1..15}; do curl -s localhost:${GUARDIAN_PORT}/api/data; done ║`);
            console.log('║                                                        ║');
            console.log('║  # Test bot blocking                                   ║');
            console.log(`║  curl -A "sqlmap" http://localhost:${GUARDIAN_PORT}/api/data      ║`);
            console.log('║                                                        ║');
            console.log('║  Press Ctrl+C to stop                                  ║');
            console.log('╚════════════════════════════════════════════════════════╝');
            console.log('');
        });
    });
    
    // Graceful shutdown
    process.on('SIGINT', () => {
        console.log('\nShutting down...');
        guardian.cleanup();
        guardian.close();
        upstream.close();
        process.exit(0);
    });
};

start();
