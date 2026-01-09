/**
 * DDoS Guardian
 * 
 * Main entry point. Starts the protection proxy server.
 * Supports auto-discovery of Docker containers.
 * 
 * Run: node src/index.js
 */

const http = require('http');
const config = require('./config');
const logger = require('./logging');
const { Proxy, DockerDiscovery } = require('./core');
const {
    rateLimitMiddleware,
    requestIdMiddleware,
    securityHeadersMiddleware,
    loggerMiddleware,
    botDetectionMiddleware,
} = require('./middleware');

/**
 * Initialize middleware
 */
const initMiddleware = () => {
    const requestId = requestIdMiddleware();
    
    const securityHeaders = securityHeadersMiddleware({
        stealth: config.security.stealthMode,
    });
    
    const botDetection = botDetectionMiddleware({
        threshold: config.botDetection.scoreThreshold,
        enabled: config.botDetection.enabled,
        blockBots: true,
        allowGoodBots: true,
    });
    
    const rateLimit = rateLimitMiddleware({
        windowMs: config.rateLimit.windowMs,
        maxRequests: config.rateLimit.maxRequests,
        blockDurationMs: config.rateLimit.blockDurationMs,
        trustProxy: config.security.trustProxy,
        skipPaths: ['/health', '/ready', '/metrics'],
        stealth: config.security.stealthMode,
    });
    
    const requestLogger = loggerMiddleware({
        skipPaths: ['/health', '/ready'],
    });
    
    return {
        requestId,
        securityHeaders,
        botDetection,
        rateLimit,
        requestLogger,
        
        // Cleanup function
        destroy: () => {
            rateLimit.destroy();
            botDetection.destroy();
        },
    };
};

/**
 * Run middleware chain
 */
const runMiddleware = (middlewares, req, res) => {
    return new Promise((resolve, reject) => {
        let index = 0;
        
        const next = (err) => {
            if (err) {
                reject(err);
                return;
            }
            
            if (res.writableEnded) {
                resolve(false); // Response already sent
                return;
            }
            
            const middleware = middlewares[index++];
            if (middleware) {
                try {
                    middleware(req, res, next);
                } catch (e) {
                    reject(e);
                }
            } else {
                resolve(true); // All middleware passed
            }
        };
        
        next();
    });
};

/**
 * Send JSON response
 */
const sendJson = (res, statusCode, data) => {
    res.statusCode = statusCode;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(data));
};

/**
 * Create and start server
 */
const startServer = async () => {
    // Initialize components
    const middleware = initMiddleware();
    
    // Auto-discovery or manual upstreams
    const autoDiscover = process.env.AUTO_DISCOVER !== 'false';
    let discovery = null;
    let upstreamHosts = config.upstream.hosts;

    if (autoDiscover) {
        logger.info('Auto-discovery enabled, scanning for containers...');
        discovery = new DockerDiscovery();
        
        try {
            await discovery.discoverUpstreams();
            const discovered = discovery.getAllUpstreams();
            
            if (discovered.length > 0) {
                upstreamHosts = discovered.map(u => u.url);
                logger.info('Auto-discovered upstreams', { upstreams: upstreamHosts });
            } else {
                logger.warn('No containers discovered, using manual config');
            }
        } catch (e) {
            logger.error('Auto-discovery failed', { error: e.message });
            logger.info('Falling back to manual config');
        }
    }

    const proxy = new Proxy({
        targets: upstreamHosts,
        timeout: 30000,
    });
    
    // Middleware order
    const middlewareStack = [
        middleware.requestId,
        middleware.securityHeaders,
        middleware.botDetection,
        middleware.rateLimit,
        middleware.requestLogger,
    ];
    
    /**
     * Request handler
     */
    const handleRequest = async (req, res) => {
        const path = req.url.split('?')[0];
        
        try {
            // Run middleware
            const passed = await runMiddleware(middlewareStack, req, res);
            
            if (!passed) {
                return; // Blocked by middleware
            }
            
            // Built-in routes
            switch (path) {
                case '/health':
                    return sendJson(res, 200, {
                        status: 'healthy',
                        timestamp: new Date().toISOString(),
                    });
                
                case '/ready':
                    const hasUpstream = upstreamHosts.length > 0;
                    return sendJson(res, hasUpstream ? 200 : 503, {
                        ready: hasUpstream,
                        upstreams: upstreamHosts.length,
                    });
                
                case '/metrics':
                    return sendJson(res, 200, {
                        rateLimit: middleware.rateLimit.limiter.getStats(),
                        botDetection: middleware.botDetection.detector.getStats(),
                        proxy: proxy.getStats(),
                        discovery: discovery ? discovery.getStats() : null,
                        uptime: process.uptime(),
                        memory: process.memoryUsage(),
                    });
                
                default:
                    // Forward to upstream
                    if (upstreamHosts.length > 0) {
                        proxy.forward(req, res);
                    } else {
                        sendJson(res, 503, {
                            error: 'Service Unavailable',
                            message: 'No upstream configured',
                        });
                    }
            }
        } catch (err) {
            logger.error('Request handler error', { error: err.message });
            if (!res.headersSent) {
                sendJson(res, 500, { error: 'Internal Server Error' });
            }
        }
    };
    
    // Create server
    const server = http.createServer(handleRequest);
    
    // Start listening
    server.listen(config.server.port, config.server.host, () => {
        logger.info('DDoS Guardian started', {
            host: config.server.host,
            port: config.server.port,
            upstreams: upstreamHosts,
            autoDiscover: autoDiscover,
            env: config.env,
        });
        
        console.log('');
        console.log('╔════════════════════════════════════════════════════════╗');
        console.log('║              DDoS Guardian Started                     ║');
        console.log('╠════════════════════════════════════════════════════════╣');
        console.log(`║  Listening: http://${config.server.host}:${config.server.port}                    ║`);
        console.log(`║  Environment: ${config.env.padEnd(39)}║`);
        console.log(`║  Auto-Discover: ${autoDiscover ? 'enabled' : 'disabled'}                              ║`);
        console.log(`║  Upstreams: ${upstreamHosts.length.toString().padEnd(41)}║`);
        console.log('╠════════════════════════════════════════════════════════╣');
        console.log('║  Protection:                                           ║');
        console.log(`║    • Rate Limit: ${config.rateLimit.maxRequests} req/${Math.round(config.rateLimit.windowMs/1000)}s                          ║`);
        console.log(`║    • Bot Detection: ${config.botDetection.enabled ? 'enabled' : 'disabled'}                           ║`);
        console.log(`║    • Stealth Mode: ${config.security.stealthMode ? 'enabled' : 'disabled'}                            ║`);
        console.log('╠════════════════════════════════════════════════════════╣');
        console.log('║  Endpoints:                                            ║');
        console.log('║    /health  - Health check                             ║');
        console.log('║    /ready   - Readiness check                          ║');
        console.log('║    /metrics - Stats and metrics                        ║');
        console.log('╚════════════════════════════════════════════════════════╝');
        
        if (upstreamHosts.length > 0) {
            console.log('');
            console.log('  Protected services:');
            upstreamHosts.forEach((u, i) => {
                console.log(`    ${i + 1}. ${u}`);
            });
        }
        
        console.log('');
    });
    
    // Start auto-refresh if discovery is enabled
    if (discovery) {
        discovery.startAutoRefresh((newUpstreams) => {
            const newHosts = discovery.getAllUpstreams().map(u => u.url);
            if (JSON.stringify(newHosts) !== JSON.stringify(upstreamHosts)) {
                upstreamHosts = newHosts;
                proxy.updateTargets(newHosts);
                logger.info('Upstreams updated', { upstreams: newHosts });
            }
        });
    }
    
    // Graceful shutdown
    const shutdown = (signal) => {
        logger.info(`Received ${signal}, shutting down...`);
        
        if (discovery) {
            discovery.stopAutoRefresh();
        }
        
        server.close(() => {
            middleware.destroy();
            logger.info('Server stopped');
            process.exit(0);
        });
        
        // Force exit after 10 seconds
        setTimeout(() => {
            logger.warn('Forced shutdown');
            process.exit(1);
        }, 10000);
    };
    
    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    
    return server;
};

// Start if run directly
if (require.main === module) {
    startServer();
}

module.exports = { startServer };
