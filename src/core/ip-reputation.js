/**
 * IP Reputation Module
 * 
 * Checks IP addresses against AbuseIPDB and other threat intelligence sources.
 * Automatically blocks IPs with high abuse confidence scores.
 * 
 * Features:
 * - AbuseIPDB integration
 * - Local cache to minimize API calls
 * - Configurable threshold for auto-blocking
 * - Report abusive IPs back to AbuseIPDB
 * - Whitelist bypass
 */

const https = require('https');
const fs = require('fs');
const path = require('path');
const logger = require('../logging');

class IPReputation {
    constructor(options = {}) {
        // AbuseIPDB API key (required for lookups)
        this.apiKey = options.apiKey || process.env.ABUSEIPDB_API_KEY || null;
        
        // Thresholds
        this.blockThreshold = options.blockThreshold || 80;
        this.warnThreshold = options.warnThreshold || 50;
        
        // Cache settings
        this.cacheEnabled = options.cacheEnabled !== false;
        this.cacheTTL = options.cacheTTL || 3600000; // 1 hour
        this.cacheMaxSize = options.cacheMaxSize || 10000;
        
        // Rate limiting for API calls
        this.apiRateLimit = options.apiRateLimit || 1000;
        this.apiCallsToday = 0;
        this.apiResetTime = this._getNextMidnight();
        
        // Local cache
        this.cache = new Map();
        
        // Whitelist
        this.whitelist = new Set(options.whitelist || []);
        
        // Stats
        this.stats = {
            totalChecks: 0,
            cacheHits: 0,
            apiCalls: 0,
            blockedByReputation: 0,
            reportsSent: 0,
        };
        
        // Persistence
        this.dataDir = options.dataDir || '/var/lib/ddos-guardian';
        this.cacheFile = path.join(this.dataDir, 'ip-reputation-cache.json');
        
        this._loadCache();
        
        this.cleanupInterval = setInterval(() => this._cleanupCache(), 300000);
        if (this.cleanupInterval.unref) this.cleanupInterval.unref();
        
        logger.info('IPReputation initialized', {
            enabled: !!this.apiKey,
            blockThreshold: this.blockThreshold,
            cacheEnabled: this.cacheEnabled,
        });
    }
    
    /**
     * Check IP reputation
     */
    async check(ip) {
        this.stats.totalChecks++;
        
        if (this._isPrivateIp(ip)) {
            return { blocked: false, score: 0, reason: 'private_ip', cached: false };
        }
        
        if (this.whitelist.has(ip)) {
            return { blocked: false, score: 0, reason: 'whitelisted', cached: false };
        }
        
        const cached = this._getFromCache(ip);
        if (cached) {
            this.stats.cacheHits++;
            return {
                blocked: cached.score >= this.blockThreshold,
                score: cached.score,
                reason: cached.score >= this.blockThreshold ? 'reputation_block' : 'ok',
                cached: true,
                reports: cached.reports,
                categories: cached.categories,
            };
        }
        
        if (!this.apiKey) {
            return { blocked: false, score: 0, reason: 'no_api_key', cached: false };
        }
        
        this._checkRateReset();
        if (this.apiCallsToday >= this.apiRateLimit) {
            logger.warn('AbuseIPDB API rate limit reached');
            return { blocked: false, score: 0, reason: 'rate_limited', cached: false };
        }
        
        try {
            const result = await this._queryAbuseIPDB(ip);
            this.stats.apiCalls++;
            this.apiCallsToday++;
            
            this._addToCache(ip, result);
            
            const blocked = result.score >= this.blockThreshold;
            
            if (blocked) {
                this.stats.blockedByReputation++;
                logger.warn('IP blocked by reputation', {
                    ip,
                    score: result.score,
                    reports: result.reports,
                    categories: result.categories,
                });
            } else if (result.score >= this.warnThreshold) {
                logger.info('IP has moderate abuse score', {
                    ip,
                    score: result.score,
                    reports: result.reports,
                });
            }
            
            return {
                blocked,
                score: result.score,
                reason: blocked ? 'reputation_block' : 'ok',
                cached: false,
                reports: result.reports,
                categories: result.categories,
                country: result.country,
                isp: result.isp,
            };
            
        } catch (e) {
            logger.error('AbuseIPDB check failed', { ip, error: e.message });
            return { blocked: false, score: 0, reason: 'api_error', cached: false, error: e.message };
        }
    }
    
    /**
     * Report an abusive IP to AbuseIPDB
     */
    async report(ip, categories, comment) {
        if (!this.apiKey) {
            return { success: false, error: 'No API key configured' };
        }
        
        if (this._isPrivateIp(ip)) {
            return { success: false, error: 'Cannot report private IP' };
        }
        
        try {
            const result = await this._reportToAbuseIPDB(ip, categories, comment);
            this.stats.reportsSent++;
            logger.info('IP reported to AbuseIPDB', { ip, categories, result });
            return { success: true, result };
        } catch (e) {
            logger.error('Failed to report IP', { ip, error: e.message });
            return { success: false, error: e.message };
        }
    }
    
    /**
     * Query AbuseIPDB API
     */
    _queryAbuseIPDB(ip) {
        return new Promise((resolve, reject) => {
            const options = {
                hostname: 'api.abuseipdb.com',
                port: 443,
                path: `/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`,
                method: 'GET',
                headers: {
                    'Key': this.apiKey,
                    'Accept': 'application/json',
                },
                timeout: 10000,
            };
            
            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        const json = JSON.parse(data);
                        
                        if (json.errors) {
                            reject(new Error(json.errors[0]?.detail || 'API error'));
                            return;
                        }
                        
                        const d = json.data || {};
                        resolve({
                            score: d.abuseConfidenceScore || 0,
                            reports: d.totalReports || 0,
                            country: d.countryCode || null,
                            isp: d.isp || null,
                            domain: d.domain || null,
                            categories: this._parseCategories(d.reports || []),
                            lastReported: d.lastReportedAt || null,
                            isWhitelisted: d.isWhitelisted || false,
                        });
                    } catch (e) {
                        reject(new Error('Invalid API response'));
                    }
                });
            });
            
            req.on('error', reject);
            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });
            
            req.end();
        });
    }
    
    /**
     * Report IP to AbuseIPDB
     */
    _reportToAbuseIPDB(ip, categories, comment) {
        return new Promise((resolve, reject) => {
            const postData = new URLSearchParams({
                ip: ip,
                categories: Array.isArray(categories) ? categories.join(',') : categories,
                comment: comment || 'Reported by DDoS Guardian',
            }).toString();
            
            const options = {
                hostname: 'api.abuseipdb.com',
                port: 443,
                path: '/api/v2/report',
                method: 'POST',
                headers: {
                    'Key': this.apiKey,
                    'Accept': 'application/json',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Content-Length': Buffer.byteLength(postData),
                },
                timeout: 10000,
            };
            
            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        const json = JSON.parse(data);
                        if (json.errors) {
                            reject(new Error(json.errors[0]?.detail || 'Report failed'));
                            return;
                        }
                        resolve(json.data || {});
                    } catch (e) {
                        reject(new Error('Invalid API response'));
                    }
                });
            });
            
            req.on('error', reject);
            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });
            
            req.write(postData);
            req.end();
        });
    }
    
    _parseCategories(reports) {
        const categories = new Set();
        for (const report of reports.slice(0, 10)) {
            if (report.categories) {
                for (const cat of report.categories) {
                    categories.add(cat);
                }
            }
        }
        return Array.from(categories);
    }
    
    _isPrivateIp(ip) {
        if (!ip) return true;
        
        if (ip.startsWith('10.') ||
            ip.startsWith('172.16.') || ip.startsWith('172.17.') || ip.startsWith('172.18.') ||
            ip.startsWith('172.19.') || ip.startsWith('172.20.') || ip.startsWith('172.21.') ||
            ip.startsWith('172.22.') || ip.startsWith('172.23.') || ip.startsWith('172.24.') ||
            ip.startsWith('172.25.') || ip.startsWith('172.26.') || ip.startsWith('172.27.') ||
            ip.startsWith('172.28.') || ip.startsWith('172.29.') || ip.startsWith('172.30.') ||
            ip.startsWith('172.31.') ||
            ip.startsWith('192.168.') ||
            ip.startsWith('127.') ||
            ip.startsWith('169.254.') ||
            ip === '::1' ||
            ip.startsWith('fc') || ip.startsWith('fd') || ip.startsWith('fe80')) {
            return true;
        }
        
        return false;
    }
    
    _getFromCache(ip) {
        if (!this.cacheEnabled) return null;
        
        const entry = this.cache.get(ip);
        if (!entry) return null;
        
        if (Date.now() - entry.lastChecked > this.cacheTTL) {
            this.cache.delete(ip);
            return null;
        }
        
        return entry;
    }
    
    _addToCache(ip, data) {
        if (!this.cacheEnabled) return;
        
        if (this.cache.size >= this.cacheMaxSize) {
            const entries = Array.from(this.cache.entries());
            entries.sort((a, b) => a[1].lastChecked - b[1].lastChecked);
            for (let i = 0; i < entries.length / 4; i++) {
                this.cache.delete(entries[i][0]);
            }
        }
        
        this.cache.set(ip, {
            ...data,
            lastChecked: Date.now(),
        });
    }
    
    _cleanupCache() {
        const now = Date.now();
        let removed = 0;
        
        for (const [ip, entry] of this.cache) {
            if (now - entry.lastChecked > this.cacheTTL) {
                this.cache.delete(ip);
                removed++;
            }
        }
        
        if (removed > 0) {
            logger.debug('Cleaned up reputation cache', { removed, remaining: this.cache.size });
        }
        
        this._saveCache();
    }
    
    _checkRateReset() {
        const now = Date.now();
        if (now >= this.apiResetTime) {
            this.apiCallsToday = 0;
            this.apiResetTime = this._getNextMidnight();
            logger.info('AbuseIPDB API rate limit reset');
        }
    }
    
    _getNextMidnight() {
        const now = new Date();
        const tomorrow = new Date(now);
        tomorrow.setDate(tomorrow.getDate() + 1);
        tomorrow.setHours(0, 0, 0, 0);
        return tomorrow.getTime();
    }
    
    _loadCache() {
        try {
            if (fs.existsSync(this.cacheFile)) {
                const data = JSON.parse(fs.readFileSync(this.cacheFile, 'utf8'));
                
                const now = Date.now();
                for (const [ip, entry] of Object.entries(data.cache || {})) {
                    if (now - entry.lastChecked < this.cacheTTL) {
                        this.cache.set(ip, entry);
                    }
                }
                
                if (data.apiResetTime && Date.now() < data.apiResetTime) {
                    this.apiCallsToday = data.apiCallsToday || 0;
                    this.apiResetTime = data.apiResetTime;
                }
                
                logger.debug('Loaded reputation cache', { entries: this.cache.size });
            }
        } catch (e) {
            logger.debug('Could not load reputation cache', { error: e.message });
        }
    }
    
    _saveCache() {
        try {
            if (!fs.existsSync(this.dataDir)) {
                fs.mkdirSync(this.dataDir, { recursive: true });
            }
            
            const data = {
                cache: Object.fromEntries(this.cache),
                apiCallsToday: this.apiCallsToday,
                apiResetTime: this.apiResetTime,
                savedAt: Date.now(),
            };
            
            fs.writeFileSync(this.cacheFile, JSON.stringify(data));
        } catch (e) {
            logger.debug('Could not save reputation cache', { error: e.message });
        }
    }
    
    addToWhitelist(ip) {
        this.whitelist.add(ip);
        this.cache.delete(ip);
    }
    
    removeFromWhitelist(ip) {
        this.whitelist.delete(ip);
    }
    
    getStats() {
        return {
            ...this.stats,
            cacheSize: this.cache.size,
            whitelistSize: this.whitelist.size,
            apiCallsRemaining: Math.max(0, this.apiRateLimit - this.apiCallsToday),
            enabled: !!this.apiKey,
            blockThreshold: this.blockThreshold,
        };
    }
    
    getStatus() {
        return {
            enabled: !!this.apiKey,
            blockThreshold: this.blockThreshold,
            warnThreshold: this.warnThreshold,
            cacheSize: this.cache.size,
            apiCallsToday: this.apiCallsToday,
            apiRateLimit: this.apiRateLimit,
        };
    }
    
    destroy() {
        if (this.cleanupInterval) {
            clearInterval(this.cleanupInterval);
            this.cleanupInterval = null;
        }
        this._saveCache();
    }
}

// AbuseIPDB category codes
IPReputation.Categories = {
    DNS_COMPROMISE: 1,
    DNS_POISONING: 2,
    FRAUD_ORDERS: 3,
    DDOS_ATTACK: 4,
    FTP_BRUTE_FORCE: 5,
    PING_OF_DEATH: 6,
    PHISHING: 7,
    FRAUD_VOIP: 8,
    OPEN_PROXY: 9,
    WEB_SPAM: 10,
    EMAIL_SPAM: 11,
    BLOG_SPAM: 12,
    VPN_IP: 13,
    PORT_SCAN: 14,
    HACKING: 15,
    SQL_INJECTION: 16,
    SPOOFING: 17,
    BRUTE_FORCE: 18,
    BAD_WEB_BOT: 19,
    EXPLOITED_HOST: 20,
    WEB_APP_ATTACK: 21,
    SSH: 22,
    IOT_TARGETED: 23,
};

module.exports = IPReputation;
