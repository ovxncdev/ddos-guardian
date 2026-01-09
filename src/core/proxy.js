/**
 * HTTP Proxy
 * 
 * Forwards clean traffic to upstream services (Nginx, etc.)
 * 
 * Usage:
 *   const proxy = new Proxy({ target: 'http://nginx:8080' });
 *   proxy.forward(req, res);
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');
const logger = require('../logging');

/**
 * Proxy class
 */
class Proxy {
    constructor(options = {}) {
        this.targets = this.parseTargets(options.targets || options.target);
        this.timeout = options.timeout || 30000;
        this.retries = options.retries || 1;
        this.currentTarget = 0;
        
        // Headers to remove when forwarding
        this.removeHeaders = [
            'host',
            'connection',
            'keep-alive',
            'proxy-authenticate',
            'proxy-authorization',
            'te',
            'trailers',
            'transfer-encoding',
            'upgrade',
        ];
        
        // Headers to add
        this.addHeaders = options.addHeaders || {};
        
        logger.info('Proxy initialized', {
            targets: this.targets.map(t => t.host),
            timeout: this.timeout,
        });
    }
    
    /**
     * Parse target URLs
     */
    parseTargets(targets) {
        if (!targets) {
            return [];
        }
        
        const list = Array.isArray(targets) ? targets : [targets];
        
        return list.map(target => {
            const url = new URL(target);
            return {
                protocol: url.protocol,
                host: url.hostname,
                port: url.port || (url.protocol === 'https:' ? 443 : 80),
                path: url.pathname,
                original: target,
            };
        });
    }
    
    /**
     * Get next target (round-robin load balancing)
     */
    getTarget() {
        if (this.targets.length === 0) {
            return null;
        }
        
        const target = this.targets[this.currentTarget];
        this.currentTarget = (this.currentTarget + 1) % this.targets.length;
        return target;
    }
    
    /**
     * Forward request to upstream
     */
    forward(req, res, options = {}) {
        const target = options.target || this.getTarget();
        
        if (!target) {
            logger.error('No upstream target configured');
            res.statusCode = 502;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ error: 'Bad Gateway', message: 'No upstream configured' }));
            return;
        }
        
        const startTime = Date.now();
        
        // Build request options
        const proxyOptions = {
            hostname: target.host,
            port: target.port,
            path: req.url,
            method: req.method,
            headers: this.buildHeaders(req, target),
            timeout: this.timeout,
        };
        
        // Choose http or https
        const transport = target.protocol === 'https:' ? https : http;
        
        // Create proxy request
        const proxyReq = transport.request(proxyOptions, (proxyRes) => {
            const duration = Date.now() - startTime;
            
            logger.debug('Upstream response', {
                target: target.host,
                statusCode: proxyRes.statusCode,
                duration,
            });
            
            // Copy response headers
            const responseHeaders = { ...proxyRes.headers };
            
            // Add proxy headers
            responseHeaders['X-Proxy-By'] = 'ddos-guardian';
            responseHeaders['X-Response-Time'] = `${duration}ms`;
            
            // Remove hop-by-hop headers
            for (const header of this.removeHeaders) {
                delete responseHeaders[header];
            }
            
            // Send response
            res.writeHead(proxyRes.statusCode, responseHeaders);
            proxyRes.pipe(res);
        });
        
        // Handle errors
        proxyReq.on('error', (err) => {
            const duration = Date.now() - startTime;
            
            logger.error('Proxy error', {
                target: target.host,
                error: err.message,
                duration,
            });
            
            if (!res.headersSent) {
                res.statusCode = 502;
                res.setHeader('Content-Type', 'application/json');
                res.end(JSON.stringify({
                    error: 'Bad Gateway',
                    message: 'Upstream connection failed',
                }));
            }
        });
        
        // Handle timeout
        proxyReq.on('timeout', () => {
            logger.error('Proxy timeout', {
                target: target.host,
                timeout: this.timeout,
            });
            
            proxyReq.destroy();
            
            if (!res.headersSent) {
                res.statusCode = 504;
                res.setHeader('Content-Type', 'application/json');
                res.end(JSON.stringify({
                    error: 'Gateway Timeout',
                    message: 'Upstream request timed out',
                }));
            }
        });
        
        // Forward request body
        req.pipe(proxyReq);
    }
    
    /**
     * Build headers for upstream request
     */
    buildHeaders(req, target) {
        const headers = {};
        
        // Copy original headers
        for (const [key, value] of Object.entries(req.headers)) {
            const lowerKey = key.toLowerCase();
            if (!this.removeHeaders.includes(lowerKey)) {
                headers[key] = value;
            }
        }
        
        // Set Host header
        headers['Host'] = target.port === 80 || target.port === 443
            ? target.host
            : `${target.host}:${target.port}`;
        
        // Add X-Forwarded headers
        const clientIp = req.headers['x-forwarded-for'] ||
                         req.socket?.remoteAddress ||
                         'unknown';
        
        headers['X-Forwarded-For'] = clientIp;
        headers['X-Forwarded-Proto'] = req.socket?.encrypted ? 'https' : 'http';
        headers['X-Forwarded-Host'] = req.headers['host'] || '';
        
        // Add request ID if present
        if (req.id) {
            headers['X-Request-ID'] = req.id;
        }
        
        // Add custom headers
        for (const [key, value] of Object.entries(this.addHeaders)) {
            headers[key] = value;
        }
        
        return headers;
    }
    
    /**
     * Health check upstream
     */
    async healthCheck(target) {
        return new Promise((resolve) => {
            const t = target || this.getTarget();
            if (!t) {
                resolve({ healthy: false, error: 'No target' });
                return;
            }
            
            const transport = t.protocol === 'https:' ? https : http;
            const startTime = Date.now();
            
            const req = transport.request({
                hostname: t.host,
                port: t.port,
                path: '/health',
                method: 'GET',
                timeout: 5000,
            }, (res) => {
                const duration = Date.now() - startTime;
                resolve({
                    healthy: res.statusCode >= 200 && res.statusCode < 400,
                    statusCode: res.statusCode,
                    duration,
                    target: t.original,
                });
            });
            
            req.on('error', (err) => {
                resolve({
                    healthy: false,
                    error: err.message,
                    target: t.original,
                });
            });
            
            req.on('timeout', () => {
                req.destroy();
                resolve({
                    healthy: false,
                    error: 'Timeout',
                    target: t.original,
                });
            });
            
            req.end();
        });
    }
    
    /**
     * Get stats
     */
    getStats() {
        return {
            targets: this.targets.map(t => t.original),
            targetCount: this.targets.length,
            currentTarget: this.currentTarget,
            timeout: this.timeout,
        };
    }
}

module.exports = Proxy;
