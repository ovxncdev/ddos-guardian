/**
 * Bot Detector
 * 
 * Analyzes requests to detect bots and suspicious traffic.
 * Uses multiple signals to calculate a "bot score".
 * 
 * Usage:
 *   const detector = new BotDetector({ threshold: 70 });
 *   const result = detector.analyze(req);
 *   if (result.isBot) { // handle bot }
 */

const logger = require('../logging');

// Known bot user agents (partial matches)
const KNOWN_BOTS = [
    'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider',
    'yandexbot', 'sogou', 'facebot', 'ia_archiver', 'semrushbot',
    'ahrefsbot', 'mj12bot', 'dotbot', 'petalbot', 'bytespider',
];

// Suspicious user agents
const SUSPICIOUS_UA = [
    'python-requests', 'python-urllib', 'curl', 'wget', 'httpie',
    'postman', 'insomnia', 'axios', 'node-fetch', 'go-http-client',
    'java', 'libwww', 'lwp-trivial', 'php', 'ruby',
];

// Known bad patterns
const BAD_PATTERNS = [
    'sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab',
    'nessus', 'openvas', 'burp', 'owasp', 'acunetix',
    'dirbuster', 'gobuster', 'wfuzz', 'hydra', 'medusa',
];

/**
 * Bot Detector class
 */
class BotDetector {
    constructor(options = {}) {
        this.threshold = options.threshold || 70;
        this.enabled = options.enabled !== false;
        
        // Track request patterns per IP
        this.patterns = new Map();
        this.cleanupInterval = setInterval(() => this.cleanup(), 60000);
        
        if (this.cleanupInterval.unref) {
            this.cleanupInterval.unref();
        }
        
        logger.debug('BotDetector initialized', { threshold: this.threshold });
    }
    
    /**
     * Analyze request and return bot score
     */
    analyze(req) {
        if (!this.enabled) {
            return { isBot: false, score: 0, reasons: [], allowed: true };
        }
        
        const signals = [];
        let score = 0;
        
        const ip = this.extractIp(req);
        const ua = req.headers?.['user-agent'] || '';
        const uaLower = ua.toLowerCase();
        
        // === Signal 1: Missing User-Agent ===
        if (!ua || ua.length < 10) {
            score += 30;
            signals.push('missing_or_short_ua');
        }
        
        // === Signal 2: Known Bot UA ===
        for (const bot of KNOWN_BOTS) {
            if (uaLower.includes(bot)) {
                score += 20;
                signals.push(`known_bot:${bot}`);
                break;
            }
        }
        
        // === Signal 3: Suspicious UA (scripts/tools) ===
        for (const sus of SUSPICIOUS_UA) {
            if (uaLower.includes(sus)) {
                score += 15;
                signals.push(`suspicious_ua:${sus}`);
                break;
            }
        }
        
        // === Signal 4: Bad patterns (security scanners) ===
        for (const bad of BAD_PATTERNS) {
            if (uaLower.includes(bad)) {
                score += 50;
                signals.push(`bad_pattern:${bad}`);
                break;
            }
        }
        
        // === Signal 5: Missing common headers ===
        if (!req.headers?.['accept']) {
            score += 10;
            signals.push('missing_accept');
        }
        
        if (!req.headers?.['accept-language']) {
            score += 10;
            signals.push('missing_accept_language');
        }
        
        if (!req.headers?.['accept-encoding']) {
            score += 5;
            signals.push('missing_accept_encoding');
        }
        
        // === Signal 6: Suspicious header combinations ===
        if (req.headers?.['x-forwarded-for'] && !req.headers?.['via']) {
            // Proxy without Via header is suspicious
            score += 5;
            signals.push('proxy_without_via');
        }
        
        // === Signal 7: Request patterns (rapid requests) ===
        const patternScore = this.analyzePatterns(ip);
        if (patternScore > 0) {
            score += patternScore;
            signals.push(`rapid_requests:${patternScore}`);
        }
        
        // === Signal 8: Connection header ===
        const connection = req.headers?.['connection']?.toLowerCase();
        if (connection === 'close') {
            // Bots often use Connection: close
            score += 5;
            signals.push('connection_close');
        }
        
        // Cap score at 100
        score = Math.min(100, score);
        
        const isBot = score >= this.threshold;
        
        if (isBot) {
            logger.warn('Bot detected', {
                ip: this.maskIp(ip),
                score,
                threshold: this.threshold,
                signals,
                ua: ua.substring(0, 100),
            });
        }
        
        return {
            isBot,
            score,
            threshold: this.threshold,
            reasons: signals,
            allowed: !isBot,
            ip,
        };
    }
    
    /**
     * Track and analyze request patterns
     */
    analyzePatterns(ip) {
        const now = Date.now();
        
        if (!this.patterns.has(ip)) {
            this.patterns.set(ip, {
                requests: [],
                lastRequest: now,
            });
        }
        
        const pattern = this.patterns.get(ip);
        
        // Calculate time since last request
        const timeSinceLast = now - pattern.lastRequest;
        pattern.lastRequest = now;
        
        // Track request timestamps (last 10 seconds)
        pattern.requests.push(now);
        pattern.requests = pattern.requests.filter(ts => now - ts < 10000);
        
        let patternScore = 0;
        
        // Very rapid requests (< 100ms apart)
        if (timeSinceLast < 100 && timeSinceLast > 0) {
            patternScore += 15;
        }
        
        // Many requests in short window
        if (pattern.requests.length > 20) {
            patternScore += 20;
        } else if (pattern.requests.length > 10) {
            patternScore += 10;
        }
        
        return patternScore;
    }
    
    /**
     * Extract IP from request
     */
    extractIp(req) {
        return req.headers?.['x-forwarded-for']?.split(',')[0]?.trim() ||
               req.headers?.['x-real-ip'] ||
               req.socket?.remoteAddress ||
               req.connection?.remoteAddress ||
               'unknown';
    }
    
    /**
     * Mask IP for logging
     */
    maskIp(ip) {
        if (!ip) return 'unknown';
        if (ip.includes('.')) {
            const parts = ip.split('.');
            return `${parts[0]}.${parts[1]}.xxx.xxx`;
        }
        return 'masked';
    }
    
    /**
     * Check if UA is a known good bot
     */
    isKnownGoodBot(req) {
        const ua = req.headers?.['user-agent']?.toLowerCase() || '';
        const goodBots = ['googlebot', 'bingbot', 'duckduckbot'];
        return goodBots.some(bot => ua.includes(bot));
    }
    
    /**
     * Cleanup old patterns
     */
    cleanup() {
        const now = Date.now();
        let cleaned = 0;
        
        for (const [ip, pattern] of this.patterns) {
            if (now - pattern.lastRequest > 60000) {
                this.patterns.delete(ip);
                cleaned++;
            }
        }
        
        if (cleaned > 0) {
            logger.debug('BotDetector cleanup', { cleaned });
        }
    }
    
    /**
     * Get stats
     */
    getStats() {
        return {
            enabled: this.enabled,
            threshold: this.threshold,
            trackedIps: this.patterns.size,
        };
    }
    
    /**
     * Destroy
     */
    destroy() {
        if (this.cleanupInterval) {
            clearInterval(this.cleanupInterval);
            this.cleanupInterval = null;
        }
        this.patterns.clear();
    }
}

module.exports = BotDetector;
