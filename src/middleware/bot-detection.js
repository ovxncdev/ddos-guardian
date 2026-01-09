/**
 * Bot Detection Middleware
 * 
 * Analyzes requests and blocks detected bots.
 * Skips detection for private/internal IPs (Docker networks, localhost, etc.)
 * 
 * Usage:
 *   const { botDetectionMiddleware } = require('./middleware');
 *   app.use(botDetectionMiddleware({ threshold: 70 }));
 */

const { BotDetector } = require('../core');
const logger = require('../logging');

/**
 * Check if IP is private/internal
 */
const isPrivateIp = (ip) => {
    if (!ip || ip === 'unknown') return false;
    
    // Localhost
    if (ip === '127.0.0.1' || ip === '::1' || ip === 'localhost') {
        return true;
    }
    
    // IPv4 private ranges
    if (ip.includes('.')) {
        const parts = ip.split('.').map(Number);
        
        // 10.0.0.0/8
        if (parts[0] === 10) return true;
        
        // 172.16.0.0/12 (172.16.x.x - 172.31.x.x)
        if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
        
        // 192.168.0.0/16
        if (parts[0] === 192 && parts[1] === 168) return true;
        
        // 169.254.0.0/16 (link-local)
        if (parts[0] === 169 && parts[1] === 254) return true;
    }
    
    // IPv6 private ranges
    if (ip.startsWith('fc') || ip.startsWith('fd')) return true; // Unique local
    if (ip.startsWith('fe80')) return true; // Link-local
    
    return false;
};

/**
 * Create bot detection middleware
 */
const createBotDetectionMiddleware = (options = {}) => {
    const detector = new BotDetector({
        threshold: options.threshold || 70,
        enabled: options.enabled !== false,
    });
    
    const blockBots = options.blockBots !== false;
    const allowGoodBots = options.allowGoodBots !== false;
    const skipPrivateIps = options.skipPrivateIps !== false; // Default: skip private IPs
    
    const middleware = (req, res, next) => {
        // Skip if detector disabled
        if (!detector.enabled) {
            return next();
        }
        
        // Extract IP early to check if private
        const ip = req.headers?.['x-forwarded-for']?.split(',')[0]?.trim() ||
                   req.headers?.['x-real-ip'] ||
                   req.socket?.remoteAddress ||
                   req.connection?.remoteAddress ||
                   'unknown';
        
        // Skip bot detection for private/internal IPs (Docker, localhost, etc.)
        if (skipPrivateIps && isPrivateIp(ip)) {
            req.botDetection = {
                isBot: false,
                score: 0,
                reasons: [],
                allowed: true,
                ip,
                skipped: 'private_ip',
            };
            return next();
        }
        
        // Analyze request
        const result = detector.analyze(req);
        
        // Attach to request
        req.botDetection = result;
        
        // Allow known good bots (Google, Bing, etc.)
        if (result.isBot && allowGoodBots && detector.isKnownGoodBot(req)) {
            req.botDetection.allowedGoodBot = true;
            return next();
        }
        
        // Block if bot detected
        if (result.isBot && blockBots) {
            logger.warn('Bot blocked', {
                ip: result.ip,
                score: result.score,
                reasons: result.reasons,
            });
            
            res.statusCode = 403;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({
                error: 'Forbidden',
                message: 'Request blocked',
            }));
            return;
        }
        
        next();
    };
    
    // Attach detector for direct access
    middleware.detector = detector;
    middleware.destroy = () => detector.destroy();
    
    return middleware;
};

module.exports = createBotDetectionMiddleware;
