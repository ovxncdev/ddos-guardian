/**
 * IP Tracker
 * 
 * Tracks request counts and blocks per IP address.
 * Uses in-memory storage with automatic cleanup.
 * 
 * Usage:
 *   const tracker = new IpTracker({ windowMs: 60000, maxRequests: 100 });
 *   const result = tracker.track('192.168.1.1');
 *   if (result.blocked) { // reject request }
 */

const logger = require('../logging');

/**
 * Single IP record
 */
class IpRecord {
    constructor() {
        this.requests = [];      // Timestamps of requests
        this.blocked = false;    // Currently blocked?
        this.blockedUntil = 0;   // Block expiry timestamp
        this.totalRequests = 0;  // Lifetime request count
        this.totalBlocks = 0;    // Lifetime block count
    }
}

/**
 * IP Tracker class
 */
class IpTracker {
    constructor(options = {}) {
        this.windowMs = options.windowMs || 60000;           // 1 minute
        this.maxRequests = options.maxRequests || 100;       // 100 requests per window
        this.blockDurationMs = options.blockDurationMs || 300000; // 5 minutes
        this.cleanupIntervalMs = options.cleanupIntervalMs || 60000; // Cleanup every minute
        
        // Storage: Map<ip, IpRecord>
        this.records = new Map();
        
        // Start cleanup timer
        this.cleanupTimer = setInterval(() => this.cleanup(), this.cleanupIntervalMs);
        
        // Allow garbage collection of timer
        if (this.cleanupTimer.unref) {
            this.cleanupTimer.unref();
        }
        
        logger.debug('IpTracker initialized', {
            windowMs: this.windowMs,
            maxRequests: this.maxRequests,
            blockDurationMs: this.blockDurationMs,
        });
    }
    
    /**
     * Get or create record for IP
     */
    getRecord(ip) {
        if (!this.records.has(ip)) {
            this.records.set(ip, new IpRecord());
        }
        return this.records.get(ip);
    }
    
    /**
     * Track a request from IP
     * Returns: { allowed, blocked, remaining, resetMs, totalRequests }
     */
    track(ip) {
        const now = Date.now();
        const record = this.getRecord(ip);
        
        // Check if currently blocked
        if (record.blocked) {
            if (now < record.blockedUntil) {
                // Still blocked
                return {
                    allowed: false,
                    blocked: true,
                    remaining: 0,
                    resetMs: record.blockedUntil - now,
                    totalRequests: record.totalRequests,
                    reason: 'blocked',
                };
            } else {
                // Block expired, unblock
                record.blocked = false;
                record.blockedUntil = 0;
                record.requests = [];
            }
        }
        
        // Remove old requests outside window
        const windowStart = now - this.windowMs;
        record.requests = record.requests.filter(ts => ts > windowStart);
        
        // Add current request
        record.requests.push(now);
        record.totalRequests++;
        
        // Check if over limit
        if (record.requests.length > this.maxRequests) {
            // Block the IP
            record.blocked = true;
            record.blockedUntil = now + this.blockDurationMs;
            record.totalBlocks++;
            
            logger.warn('IP blocked for rate limit', {
                ip: this.maskIp(ip),
                requests: record.requests.length,
                maxRequests: this.maxRequests,
                blockDurationMs: this.blockDurationMs,
            });
            
            return {
                allowed: false,
                blocked: true,
                remaining: 0,
                resetMs: this.blockDurationMs,
                totalRequests: record.totalRequests,
                reason: 'rate_limit_exceeded',
            };
        }
        
        // Allowed
        const remaining = this.maxRequests - record.requests.length;
        const oldestRequest = record.requests[0];
        const resetMs = oldestRequest ? (oldestRequest + this.windowMs) - now : this.windowMs;
        
        return {
            allowed: true,
            blocked: false,
            remaining,
            resetMs: Math.max(0, resetMs),
            totalRequests: record.totalRequests,
            reason: null,
        };
    }
    
    /**
     * Manually block an IP
     */
    block(ip, durationMs = this.blockDurationMs, reason = 'manual') {
        const record = this.getRecord(ip);
        record.blocked = true;
        record.blockedUntil = Date.now() + durationMs;
        record.totalBlocks++;
        
        logger.info('IP manually blocked', {
            ip: this.maskIp(ip),
            durationMs,
            reason,
        });
    }
    
    /**
     * Manually unblock an IP
     */
    unblock(ip) {
        const record = this.records.get(ip);
        if (record) {
            record.blocked = false;
            record.blockedUntil = 0;
            
            logger.info('IP unblocked', {
                ip: this.maskIp(ip),
            });
        }
    }
    
    /**
     * Check if IP is blocked (without tracking)
     */
    isBlocked(ip) {
        const record = this.records.get(ip);
        if (!record) return false;
        
        if (record.blocked && Date.now() < record.blockedUntil) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Get stats for an IP
     */
    getStats(ip) {
        const record = this.records.get(ip);
        if (!record) {
            return null;
        }
        
        const now = Date.now();
        const windowStart = now - this.windowMs;
        const recentRequests = record.requests.filter(ts => ts > windowStart).length;
        
        return {
            recentRequests,
            totalRequests: record.totalRequests,
            totalBlocks: record.totalBlocks,
            blocked: record.blocked && now < record.blockedUntil,
            blockedUntil: record.blocked ? record.blockedUntil : null,
        };
    }
    
    /**
     * Get global stats
     */
    getGlobalStats() {
        let totalIps = 0;
        let blockedIps = 0;
        let totalRequests = 0;
        let totalBlocks = 0;
        
        const now = Date.now();
        
        for (const [ip, record] of this.records) {
            totalIps++;
            totalRequests += record.totalRequests;
            totalBlocks += record.totalBlocks;
            
            if (record.blocked && now < record.blockedUntil) {
                blockedIps++;
            }
        }
        
        return {
            totalIps,
            blockedIps,
            totalRequests,
            totalBlocks,
            memoryUsage: this.records.size,
        };
    }
    
    /**
     * Clean up old records
     */
    cleanup() {
        const now = Date.now();
        const windowStart = now - this.windowMs;
        let cleaned = 0;
        
        for (const [ip, record] of this.records) {
            // Remove if not blocked and no recent requests
            const hasRecentRequests = record.requests.some(ts => ts > windowStart);
            const isBlocked = record.blocked && now < record.blockedUntil;
            
            if (!hasRecentRequests && !isBlocked) {
                this.records.delete(ip);
                cleaned++;
            }
        }
        
        if (cleaned > 0) {
            logger.debug('IpTracker cleanup', {
                cleaned,
                remaining: this.records.size,
            });
        }
    }
    
    /**
     * Mask IP for logging (privacy)
     */
    maskIp(ip) {
        if (!ip) return 'unknown';
        
        // IPv4: show first two octets
        if (ip.includes('.')) {
            const parts = ip.split('.');
            return `${parts[0]}.${parts[1]}.xxx.xxx`;
        }
        
        // IPv6: show first two groups
        if (ip.includes(':')) {
            const parts = ip.split(':');
            return `${parts[0]}:${parts[1]}:xxxx:xxxx`;
        }
        
        return 'masked';
    }
    
    /**
     * Reset all records
     */
    reset() {
        this.records.clear();
        logger.info('IpTracker reset');
    }
    
    /**
     * Stop cleanup timer
     */
    destroy() {
        if (this.cleanupTimer) {
            clearInterval(this.cleanupTimer);
            this.cleanupTimer = null;
        }
    }
}

module.exports = IpTracker;
