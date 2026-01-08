/**
 * Rate Limiter
 * 
 * Main rate limiting engine.
 * Wraps IpTracker with additional features.
 * 
 * Usage:
 *   const limiter = new RateLimiter(config);
 *   const result = limiter.check(req);
 *   if (!result.allowed) { // reject }
 */

const IpTracker = require('./ip-tracker');
const logger = require('../logging');

/**
 * Extract IP from request
 */
const extractIp = (req, trustProxy = true) => {
    if (trustProxy) {
        // Check common proxy headers
        const forwarded = req.headers?.['x-forwarded-for'];
        if (forwarded) {
            // Take first IP (client IP)
            return forwarded.split(',')[0].trim();
        }
        
        const realIp = req.headers?.['x-real-ip'];
        if (realIp) {
            return realIp.trim();
        }
    }
    
    // Direct connection
    return req.socket?.remoteAddress || 
           req.connection?.remoteAddress || 
           req.ip ||
           'unknown';
};

/**
 * Rate Limiter class
 */
class RateLimiter {
    constructor(options = {}) {
        this.trustProxy = options.trustProxy !== false;
        this.enabled = options.enabled !== false;
        
        // Whitelist/blacklist
        this.whitelist = new Set(options.whitelist || []);
        this.blacklist = new Set(options.blacklist || []);
        
        // Create IP tracker
        this.tracker = new IpTracker({
            windowMs: options.windowMs || 60000,
            maxRequests: options.maxRequests || 100,
            blockDurationMs: options.blockDurationMs || 300000,
        });
        
        // Skip paths (don't rate limit these)
        this.skipPaths = options.skipPaths || ['/health', '/ready', '/metrics'];
        
        // Custom key extractor (optional)
        this.keyExtractor = options.keyExtractor || null;
        
        logger.info('RateLimiter initialized', {
            enabled: this.enabled,
            trustProxy: this.trustProxy,
            whitelistSize: this.whitelist.size,
            blacklistSize: this.blacklist.size,
            skipPaths: this.skipPaths,
        });
    }
    
    /**
     * Get rate limit key for request
     * Default is IP, but can be customized
     */
    getKey(req) {
        if (this.keyExtractor) {
            const customKey = this.keyExtractor(req);
            if (customKey) return customKey;
        }
        
        return extractIp(req, this.trustProxy);
    }
    
    /**
     * Check if path should skip rate limiting
     */
    shouldSkip(req) {
        const path = req.url?.split('?')[0] || req.path || '';
        return this.skipPaths.some(skip => path.startsWith(skip));
    }
    
    /**
     * Check request against rate limit
     * Returns: { allowed, blocked, remaining, resetMs, ip, reason }
     */
    check(req) {
        // Disabled = allow all
        if (!this.enabled) {
            return {
                allowed: true,
                blocked: false,
                remaining: Infinity,
                resetMs: 0,
                ip: null,
                reason: 'disabled',
            };
        }
        
        // Skip certain paths
        if (this.shouldSkip(req)) {
            return {
                allowed: true,
                blocked: false,
                remaining: Infinity,
                resetMs: 0,
                ip: null,
                reason: 'skipped',
            };
        }
        
        const ip = this.getKey(req);
        
        // Check whitelist
        if (this.whitelist.has(ip)) {
            return {
                allowed: true,
                blocked: false,
                remaining: Infinity,
                resetMs: 0,
                ip,
                reason: 'whitelisted',
            };
        }
        
        // Check blacklist
        if (this.blacklist.has(ip)) {
            logger.warn('Blacklisted IP attempted access', {
                ip: this.tracker.maskIp(ip),
            });
            
            return {
                allowed: false,
                blocked: true,
                remaining: 0,
                resetMs: Infinity,
                ip,
                reason: 'blacklisted',
            };
        }
        
        // Track and check
        const result = this.tracker.track(ip);
        
        return {
            ...result,
            ip,
        };
    }
    
    /**
     * Add IP to whitelist
     */
    addToWhitelist(ip) {
        this.whitelist.add(ip);
        this.blacklist.delete(ip); // Remove from blacklist if present
        logger.info('IP added to whitelist', { ip: this.tracker.maskIp(ip) });
    }
    
    /**
     * Remove IP from whitelist
     */
    removeFromWhitelist(ip) {
        this.whitelist.delete(ip);
        logger.info('IP removed from whitelist', { ip: this.tracker.maskIp(ip) });
    }
    
    /**
     * Add IP to blacklist
     */
    addToBlacklist(ip) {
        this.blacklist.add(ip);
        this.whitelist.delete(ip); // Remove from whitelist if present
        logger.info('IP added to blacklist', { ip: this.tracker.maskIp(ip) });
    }
    
    /**
     * Remove IP from blacklist
     */
    removeFromBlacklist(ip) {
        this.blacklist.delete(ip);
        logger.info('IP removed from blacklist', { ip: this.tracker.maskIp(ip) });
    }
    
    /**
     * Manually block an IP
     */
    blockIp(ip, durationMs, reason) {
        this.tracker.block(ip, durationMs, reason);
    }
    
    /**
     * Manually unblock an IP
     */
    unblockIp(ip) {
        this.tracker.unblock(ip);
    }
    
    /**
     * Get stats for an IP
     */
    getIpStats(ip) {
        return this.tracker.getStats(ip);
    }
    
    /**
     * Get global stats
     */
    getStats() {
        return {
            ...this.tracker.getGlobalStats(),
            whitelistSize: this.whitelist.size,
            blacklistSize: this.blacklist.size,
            enabled: this.enabled,
        };
    }
    
    /**
     * Reset all tracking
     */
    reset() {
        this.tracker.reset();
    }
    
    /**
     * Cleanup
     */
    destroy() {
        this.tracker.destroy();
    }
}

// Export class and helper
module.exports = RateLimiter;
module.exports.extractIp = extractIp;
