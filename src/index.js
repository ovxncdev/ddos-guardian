/**
 * DDoS Guardian
 * 
 * Main entry point. Starts the protection proxy server.
 * Supports auto-discovery of Docker containers.
 * Includes Admin API for whitelist/blacklist management.
 * Supports SSL/HTTPS termination.
 * 
 * Run: node src/index.js
 */

const http = require('http');
const https = require('https');
const config = require('./config');
const logger = require('./logging');
const { Proxy, DockerDiscovery } = require('./core');
const SSLManager = require('./core/ssl-manager');
const {
    rateLimitMiddleware,
    requestIdMiddleware,
    securityHeadersMiddleware,
    loggerMiddleware,
    botDetectionMiddleware,
} = require('./middleware');

// Track current upstreams for dynamic updates
let currentUpstreams = [];

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
        skipPaths: ['/health', '/ready', '/metrics', '/api/'],
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
 * Parse JSON body from request
 */
const parseBody = (req) => {
    return new Promise((resolve, reject) => {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            if (!body) {
                resolve({});
                return;
            }
            try {
                resolve(JSON.parse(body));
            } catch (e) {
                reject(new Error('Invalid JSON body'));
            }
        });
        req.on('error', reject);
    });
};

/**
 * Validate IP address format
 */
const isValidIp = (ip) => {
    if (!ip || typeof ip !== 'string') return false;
    
    // IPv4
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Regex.test(ip)) {
        const parts = ip.split('.').map(Number);
        return parts.every(p => p >= 0 && p <= 255);
    }
    
    // IPv6 (simplified check)
    const ipv6Regex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
    return ipv6Regex.test(ip);
};

/**
 * Initialize upstreams from config or discovery
 */
const initUpstreams = async (discovery) => {
    // Manual config takes priority if specified
    if (config.upstream.hosts.length > 0) {
        logger.info('Using manually configured upstreams', {
            count: config.upstream.hosts.length,
            upstreams: config.upstream.hosts,
        });
        return config.upstream.hosts;
    }
    
    // Try auto-discovery
    if (config.discovery.enabled && discovery && discovery.isAvailable) {
        logger.info('Auto-discovery enabled, scanning for containers...');
        
        try {
            await discovery.discoverUpstreams();
            const discovered = discovery.getUpstreamUrls();
            
            if (discovered.length > 0) {
                logger.info('Auto-discovered upstreams', { 
                    count: discovered.length,
                    upstreams: discovered,
                });
                return discovered;
            } else {
                logger.warn('No containers discovered');
            }
        } catch (e) {
            logger.error('Auto-discovery failed', { error: e.message });
        }
    } else if (config.discovery.enabled) {
        logger.warn('Auto-discovery enabled but Docker socket not available');
    }
    
    // No upstreams found
    logger.warn('No upstreams configured - requests will return 503');
    return [];
};

/**
 * Handle Admin API requests
 */
const handleAdminApi = async (req, res, path, middleware, sslManager) => {
    const method = req.method;
    const limiter = middleware.rateLimit.limiter;
    
    try {
        // GET /api/whitelist - List whitelisted IPs
        if (path === '/api/whitelist' && method === 'GET') {
            return sendJson(res, 200, {
                success: true,
                whitelist: Array.from(limiter.whitelist),
                count: limiter.whitelist.size,
            });
        }
        
        // POST /api/whitelist - Add IP to whitelist
        if (path === '/api/whitelist' && method === 'POST') {
            const body = await parseBody(req);
            const ip = body.ip?.trim();
            
            if (!ip) {
                return sendJson(res, 400, { success: false, error: 'IP address required' });
            }
            
            if (!isValidIp(ip)) {
                return sendJson(res, 400, { success: false, error: 'Invalid IP address format' });
            }
            
            limiter.addToWhitelist(ip);
            return sendJson(res, 200, { 
                success: true, 
                message: `IP ${ip} added to whitelist`,
                whitelist: Array.from(limiter.whitelist),
            });
        }
        
        // DELETE /api/whitelist/:ip - Remove IP from whitelist
        if (path.startsWith('/api/whitelist/') && method === 'DELETE') {
            const ip = decodeURIComponent(path.replace('/api/whitelist/', ''));
            
            if (!ip) {
                return sendJson(res, 400, { success: false, error: 'IP address required' });
            }
            
            if (!limiter.whitelist.has(ip)) {
                return sendJson(res, 404, { success: false, error: 'IP not in whitelist' });
            }
            
            limiter.removeFromWhitelist(ip);
            return sendJson(res, 200, { 
                success: true, 
                message: `IP ${ip} removed from whitelist`,
            });
        }
        
        // GET /api/blacklist - List blacklisted IPs
        if (path === '/api/blacklist' && method === 'GET') {
            return sendJson(res, 200, {
                success: true,
                blacklist: Array.from(limiter.blacklist),
                count: limiter.blacklist.size,
            });
        }
        
        // POST /api/blacklist - Add IP to blacklist
        if (path === '/api/blacklist' && method === 'POST') {
            const body = await parseBody(req);
            const ip = body.ip?.trim();
            
            if (!ip) {
                return sendJson(res, 400, { success: false, error: 'IP address required' });
            }
            
            if (!isValidIp(ip)) {
                return sendJson(res, 400, { success: false, error: 'Invalid IP address format' });
            }
            
            limiter.addToBlacklist(ip);
            return sendJson(res, 200, { 
                success: true, 
                message: `IP ${ip} added to blacklist`,
                blacklist: Array.from(limiter.blacklist),
            });
        }
        
        // DELETE /api/blacklist/:ip - Remove IP from blacklist
        if (path.startsWith('/api/blacklist/') && method === 'DELETE') {
            const ip = decodeURIComponent(path.replace('/api/blacklist/', ''));
            
            if (!ip) {
                return sendJson(res, 400, { success: false, error: 'IP address required' });
            }
            
            if (!limiter.blacklist.has(ip)) {
                return sendJson(res, 404, { success: false, error: 'IP not in blacklist' });
            }
            
            limiter.removeFromBlacklist(ip);
            return sendJson(res, 200, { 
                success: true, 
                message: `IP ${ip} removed from blacklist`,
            });
        }
        
        // GET /api/blocked - List currently blocked IPs (rate limited)
        if (path === '/api/blocked' && method === 'GET') {
            const stats = limiter.tracker.getGlobalStats();
            return sendJson(res, 200, {
                success: true,
                blockedCount: stats.blockedIps,
                totalRequests: stats.totalRequests,
                totalBlocks: stats.totalBlocks,
            });
        }
        
        // POST /api/block - Manually block an IP
        if (path === '/api/block' && method === 'POST') {
            const body = await parseBody(req);
            const ip = body.ip?.trim();
            const duration = body.duration || config.rateLimit.blockDurationMs;
            const reason = body.reason || 'Manual block via API';
            
            if (!ip) {
                return sendJson(res, 400, { success: false, error: 'IP address required' });
            }
            
            if (!isValidIp(ip)) {
                return sendJson(res, 400, { success: false, error: 'Invalid IP address format' });
            }
            
            limiter.blockIp(ip, duration, reason);
            return sendJson(res, 200, { 
                success: true, 
                message: `IP ${ip} blocked for ${Math.round(duration / 1000)}s`,
                reason,
            });
        }
        
        // POST /api/unblock - Manually unblock an IP
        if (path === '/api/unblock' && method === 'POST') {
            const body = await parseBody(req);
            const ip = body.ip?.trim();
            
            if (!ip) {
                return sendJson(res, 400, { success: false, error: 'IP address required' });
            }
            
            limiter.unblockIp(ip);
            return sendJson(res, 200, { 
                success: true, 
                message: `IP ${ip} unblocked`,
            });
        }
        
        // GET /api/ssl - Get SSL status
        if (path === '/api/ssl' && method === 'GET') {
            return sendJson(res, 200, {
                success: true,
                ssl: sslManager ? sslManager.getStatus() : { enabled: false, available: false },
            });
        }
        
        // GET /api/config - Get current configuration
        if (path === '/api/config' && method === 'GET') {
            return sendJson(res, 200, {
                success: true,
                config: {
                    rateLimit: {
                        windowMs: config.rateLimit.windowMs,
                        maxRequests: config.rateLimit.maxRequests,
                        blockDurationMs: config.rateLimit.blockDurationMs,
                    },
                    botDetection: {
                        enabled: config.botDetection.enabled,
                        threshold: config.botDetection.scoreThreshold,
                    },
                    security: {
                        stealthMode: config.security.stealthMode,
                        trustProxy: config.security.trustProxy,
                    },
                    ssl: sslManager ? sslManager.getStatus() : { enabled: false },
                },
            });
        }
        
        // GET /api/stats - Get detailed stats
        if (path === '/api/stats' && method === 'GET') {
            return sendJson(res, 200, {
                success: true,
                rateLimit: limiter.getStats(),
                botDetection: middleware.botDetection.detector.getStats(),
                ssl: sslManager ? sslManager.getStats() : { enabled: false },
                upstreams: currentUpstreams.length,
                uptime: process.uptime(),
                memory: process.memoryUsage(),
            });
        }
        
        // Unknown API endpoint
        return sendJson(res, 404, { 
            success: false, 
            error: 'API endpoint not found',
            availableEndpoints: [
                'GET  /api/whitelist',
                'POST /api/whitelist',
                'DELETE /api/whitelist/:ip',
                'GET  /api/blacklist',
                'POST /api/blacklist',
                'DELETE /api/blacklist/:ip',
                'GET  /api/blocked',
                'POST /api/block',
                'POST /api/unblock',
                'GET  /api/ssl',
                'GET  /api/config',
                'GET  /api/stats',
            ],
        });
        
    } catch (err) {
        logger.error('Admin API error', { path, method, error: err.message });
        return sendJson(res, 500, { success: false, error: err.message });
    }
};

/**
 * Create and start server
 */
const startServer = async () => {
    // Initialize components
    const middleware = initMiddleware();
    
    // Initialize SSL manager
    const sslManager = new SSLManager({
        enabled: config.ssl?.enabled !== false,
        domain: config.ssl?.domain || process.env.SSL_DOMAIN,
        certDir: config.ssl?.certDir || '/certs',
        letsencryptDir: config.ssl?.letsencryptDir || '/etc/letsencrypt/live',
        phishproxyCertDir: config.ssl?.phishproxyCertDir || '/phishproxy-certs',
    });
    
    // Initialize discovery (may not be available)
    let discovery = null;
    if (config.discovery.enabled) {
        discovery = new DockerDiscovery();
    }
    
    // Get initial upstreams
    currentUpstreams = await initUpstreams(discovery);
    
    // Initialize proxy
    const proxy = new Proxy({
        targets: currentUpstreams,
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
            // Admin API endpoints (skip full middleware for these)
            if (path.startsWith('/api/')) {
                // Only run requestId and securityHeaders for API
                middleware.requestId(req, res, () => {});
                middleware.securityHeaders(req, res, () => {});
                return handleAdminApi(req, res, path, middleware, sslManager);
            }
            
            // Run middleware for all other requests
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
                    const hasUpstream = currentUpstreams.length > 0;
                    return sendJson(res, hasUpstream ? 200 : 503, {
                        ready: hasUpstream,
                        upstreams: currentUpstreams.length,
                    });
                
                case '/metrics':
                    return sendJson(res, 200, {
                        rateLimit: middleware.rateLimit.limiter.getStats(),
                        botDetection: middleware.botDetection.detector.getStats(),
                        proxy: proxy.getStats(),
                        ssl: sslManager.getStats(),
                        discovery: discovery ? discovery.getStats() : { available: false },
                        uptime: process.uptime(),
                        memory: process.memoryUsage(),
                    });
                
                default:
                    // Forward to upstream
                    if (currentUpstreams.length > 0) {
                        proxy.forward(req, res);
                    } else {
                        sendJson(res, 503, {
                            error: 'Service Unavailable',
                            message: 'No upstream configured',
                        });
                    }
            }
        } catch (err) {
            logger.error('Request handler error', { error: err.message, stack: err.stack });
            if (!res.headersSent) {
                sendJson(res, 500, { error: 'Internal Server Error' });
            }
        }
    };
    
    // Create HTTP server
    const httpServer = http.createServer(handleRequest);
    
    // Create HTTPS server if SSL is available
    let httpsServer = null;
    let httpsServer8443 = null;
    
    if (sslManager.credentials) {
        httpsServer = sslManager.createServer(handleRequest);
        httpsServer8443 = sslManager.createServer(handleRequest);
        
        // Watch for cert changes and reload
        sslManager.startWatching(60000);
        sslManager.onReload(() => {
            if (httpsServer) {
                sslManager.updateServerCredentials(httpsServer);
            }
            if (httpsServer8443) {
                sslManager.updateServerCredentials(httpsServer8443);
            }
        });
    }
    
    // Handle server errors
    const handleServerError = (err, serverType, port) => {
        if (err.code === 'EADDRINUSE') {
            logger.error(`${serverType} port ${port} is already in use`);
        } else if (err.code === 'EACCES') {
            logger.error(`Permission denied for ${serverType} port ${port}`);
        } else {
            logger.error(`${serverType} server error`, { error: err.message });
        }
    };
    
    httpServer.on('error', (err) => handleServerError(err, 'HTTP', config.server.port));
    if (httpsServer) {
        httpsServer.on('error', (err) => handleServerError(err, 'HTTPS', 443));
    }
    if (httpsServer8443) {
        httpsServer8443.on('error', (err) => handleServerError(err, 'HTTPS', 8443));
    }
    
    // Start listening
    httpServer.listen(config.server.port, config.server.host, () => {
        logger.info('HTTP server started', {
            host: config.server.host,
            port: config.server.port,
        });
    });
    
    if (httpsServer) {
        httpsServer.listen(443, config.server.host, () => {
            logger.info('HTTPS server started', {
                host: config.server.host,
                port: 443,
                certSource: sslManager.certSource,
            });
        });
    }
    
    if (httpsServer8443) {
        httpsServer8443.listen(8443, config.server.host, () => {
            logger.info('HTTPS server started', {
                host: config.server.host,
                port: 8443,
                certSource: sslManager.certSource,
            });
        });
    }
    
    // Print startup banner
    printBanner(currentUpstreams, sslManager);
    
    // Start auto-refresh if discovery is enabled and available
    if (discovery && discovery.isAvailable) {
        discovery.startAutoRefresh(() => {
            const newUpstreams = discovery.getUpstreamUrls();
            
            // Check if upstreams changed
            const oldSorted = [...currentUpstreams].sort().join(',');
            const newSorted = [...newUpstreams].sort().join(',');
            
            if (oldSorted !== newSorted) {
                currentUpstreams = newUpstreams;
                proxy.updateTargets(newUpstreams);
                logger.info('Upstreams updated via auto-discovery', { 
                    count: newUpstreams.length,
                    upstreams: newUpstreams,
                });
            }
        });
    }
    
    // Graceful shutdown
    const shutdown = (signal) => {
        logger.info(`Received ${signal}, shutting down...`);
        
        if (discovery) {
            discovery.destroy();
        }
        
        sslManager.destroy();
        
        const closeServers = [];
        closeServers.push(new Promise(r => httpServer.close(r)));
        if (httpsServer) closeServers.push(new Promise(r => httpsServer.close(r)));
        if (httpsServer8443) closeServers.push(new Promise(r => httpsServer8443.close(r)));
        
        Promise.all(closeServers).then(() => {
            middleware.destroy();
            logger.info('Servers stopped');
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
    
    return { httpServer, httpsServer, httpsServer8443 };
};

/**
 * Print startup banner
 */
const printBanner = (upstreams, sslManager) => {
    const autoDiscover = config.discovery.enabled ? 'enabled' : 'disabled';
    const sslStatus = sslManager.credentials ? `enabled (${sslManager.certSource})` : 'disabled';
    
    console.log('');
    console.log('╔════════════════════════════════════════════════════════╗');
    console.log('║              DDoS Guardian Started                     ║');
    console.log('╠════════════════════════════════════════════════════════╣');
    console.log(`║  HTTP:  http://${config.server.host}:${config.server.port}`.padEnd(57) + '║');
    if (sslManager.credentials) {
        console.log(`║  HTTPS: https://${config.server.host}:443`.padEnd(57) + '║');
        console.log(`║  HTTPS: https://${config.server.host}:8443`.padEnd(57) + '║');
    }
    console.log(`║  Environment: ${config.env}`.padEnd(57) + '║');
    console.log(`║  Auto-Discover: ${autoDiscover}`.padEnd(57) + '║');
    console.log(`║  SSL/TLS: ${sslStatus}`.padEnd(57) + '║');
    console.log(`║  Upstreams: ${upstreams.length}`.padEnd(57) + '║');
    console.log('╠════════════════════════════════════════════════════════╣');
    console.log('║  Protection:                                           ║');
    console.log(`║    • Rate Limit: ${config.rateLimit.maxRequests} req/${Math.round(config.rateLimit.windowMs/1000)}s`.padEnd(57) + '║');
    console.log(`║    • Bot Detection: ${config.botDetection.enabled ? 'enabled' : 'disabled'}`.padEnd(57) + '║');
    console.log(`║    • Stealth Mode: ${config.security.stealthMode ? 'enabled' : 'disabled'}`.padEnd(57) + '║');
    console.log('╠════════════════════════════════════════════════════════╣');
    console.log('║  Endpoints:                                            ║');
    console.log('║    /health  - Health check                             ║');
    console.log('║    /ready   - Readiness check                          ║');
    console.log('║    /metrics - Stats and metrics                        ║');
    console.log('║    /api/*   - Admin API                                ║');
    console.log('╚════════════════════════════════════════════════════════╝');
    
    if (upstreams.length > 0) {
        console.log('');
        console.log('  Protected services:');
        upstreams.forEach((u, i) => {
            console.log(`    ${i + 1}. ${u}`);
        });
    } else {
        console.log('');
        console.log('  ⚠ No upstreams configured - waiting for containers...');
    }
    
    console.log('');
};

// Start if run directly
if (require.main === module) {
    startServer().catch((err) => {
        logger.error('Failed to start server', { error: err.message, stack: err.stack });
        process.exit(1);
    });
}

module.exports = { startServer };
