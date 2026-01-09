/**
 * Rate Limit Middleware
 * 
 * Express-style middleware for rate limiting.
 * 
 * Usage:
 *   const { rateLimitMiddleware } = require('./middleware');
 *   app.use(rateLimitMiddleware());
 */

const { RateLimiter } = require('../core');
const logger = require('../logging');

/**
 * Create rate limit middleware
 */
const createRateLimitMiddleware = (options = {}) => {
    const limiter = new RateLimiter(options);
    
    /**
     * Middleware function
     */
    const middleware = (req, res, next) => {
        const result = limiter.check(req);
        
        // Attach result to request for later use
        req.rateLimit = result;
        
        // Add headers (unless stealth mode)
        if (!options.stealth) {
            res.setHeader('X-RateLimit-Limit', limiter.tracker.maxRequests);
            res.setHeader('X-RateLimit-Remaining', Math.max(0, result.remaining));
            res.setHeader('X-RateLimit-Reset', Math.ceil(result.resetMs / 1000));
        }
        
        // If allowed, continue
        if (result.allowed) {
            return next();
        }
        
        // Blocked - send 429
        logger.warn('Request blocked by rate limit', {
            ip: result.ip,
            path: req.url,
            reason: result.reason,
        });
        
        if (!options.stealth) {
            res.setHeader('Retry-After', Math.ceil(result.resetMs / 1000));
        }
        
        res.statusCode = 429;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({
            error: 'Too Many Requests',
            retryAfter: Math.ceil(result.resetMs / 1000),
        }));
    };
    
    // Attach limiter for direct access
    middleware.limiter = limiter;
    
    // Cleanup method
    middleware.destroy = () => limiter.destroy();
    
    return middleware;
};

module.exports = createRateLimitMiddleware;
