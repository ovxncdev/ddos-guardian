/**
 * Test Server
 * 
 * Tests ddos-guardian with real HTTP requests.
 * 
 * Run: node tests/test-server.js
 * 
 * Test with:
 *   curl http://localhost:3333/api/test
 *   curl -A "Googlebot" http://localhost:3333/api/test
 *   curl -A "" http://localhost:3333/api/test
 */

const http = require('http');
const {
    rateLimitMiddleware,
    requestIdMiddleware,
    securityHeadersMiddleware,
    loggerMiddleware,
    botDetectionMiddleware,
} = require('../src/middleware');

// Config
const PORT = 3333;
const HOST = '0.0.0.0';

// Create middleware
const rateLimit = rateLimitMiddleware({
    windowMs: 60000,
    maxRequests: 10,
    blockDurationMs: 30000,
    trustProxy: true,
    skipPaths: ['/health', '/ready', '/stats'],
});

const botDetection = botDetectionMiddleware({
    threshold: 70,
    blockBots: true,
    allowGoodBots: true,
});

const requestId = requestIdMiddleware();
const securityHeaders = securityHeadersMiddleware({ stealth: true });
const requestLogger = loggerMiddleware({ skipPaths: ['/health', '/ready'] });

/**
 * Run middleware chain
 */
const runMiddleware = (middlewares, req, res, callback) => {
    let index = 0;
    
    const next = (err) => {
        if (err) {
            res.statusCode = 500;
            res.end(JSON.stringify({ error: err.message }));
            return;
        }
        
        if (res.writableEnded) return;
        
        const middleware = middlewares[index++];
        if (middleware) {
            middleware(req, res, next);
        } else {
            callback();
        }
    };
    
    next();
};

/**
 * Send JSON response
 */
const sendJson = (res, statusCode, data) => {
    res.statusCode = statusCode;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(data, null, 2));
};

/**
 * Route handler
 */
const handleRoutes = (req, res) => {
    const path = req.url.split('?')[0];
    
    switch (path) {
        case '/':
            return sendJson(res, 200, {
                message: 'DDoS Guardian Test Server',
                requestId: req.id,
            });
        
        case '/api/test':
            return sendJson(res, 200, {
                success: true,
                requestId: req.id,
                rateLimit: {
                    remaining: req.rateLimit?.remaining,
                },
                botDetection: {
                    score: req.botDetection?.score,
                    isBot: req.botDetection?.isBot,
                },
            });
        
        case '/health':
            return sendJson(res, 200, { status: 'healthy' });
        
        case '/stats':
            return sendJson(res, 200, {
                rateLimit: rateLimit.limiter.getStats(),
                botDetection: botDetection.detector.getStats(),
            });
        
        default:
            return sendJson(res, 404, { error: 'Not Found' });
    }
};

/**
 * Request handler
 */
const handleRequest = (req, res) => {
    const middlewares = [
        requestId,
        securityHeaders,
        botDetection,
        rateLimit,
        requestLogger,
    ];
    
    runMiddleware(middlewares, req, res, () => {
        handleRoutes(req, res);
    });
};

// Create server
const server = http.createServer(handleRequest);

// Start
server.listen(PORT, HOST, () => {
    console.log('');
    console.log('╔════════════════════════════════════════════════════════╗');
    console.log('║         DDoS Guardian - Test Server                    ║');
    console.log('╠════════════════════════════════════════════════════════╣');
    console.log(`║  URL: http://localhost:${PORT}                            ║`);
    console.log('║                                                        ║');
    console.log('║  Middleware:                                           ║');
    console.log('║    ✓ Request ID                                        ║');
    console.log('║    ✓ Security Headers                                  ║');
    console.log('║    ✓ Bot Detection (threshold: 70)                     ║');
    console.log('║    ✓ Rate Limiting (10 req/min)                        ║');
    console.log('║    ✓ Request Logger                                    ║');
    console.log('╠════════════════════════════════════════════════════════╣');
    console.log('║  Test Bot Detection:                                   ║');
    console.log('║    curl http://localhost:3333/api/test                 ║');
    console.log('║    curl -A "Googlebot" http://localhost:3333/api/test  ║');
    console.log('║    curl -A "" http://localhost:3333/api/test           ║');
    console.log('║    curl -A "sqlmap" http://localhost:3333/api/test     ║');
    console.log('║                                                        ║');
    console.log('║  Press Ctrl+C to stop                                  ║');
    console.log('╚════════════════════════════════════════════════════════╝');
    console.log('');
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\nShutting down...');
    rateLimit.destroy();
    botDetection.destroy();
    server.close(() => {
        console.log('Server stopped');
        process.exit(0);
    });
});
