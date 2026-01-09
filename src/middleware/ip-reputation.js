/**
 * IP Reputation Middleware
 * 
 * Checks incoming requests against IP reputation database.
 * Blocks requests from IPs with high abuse scores.
 */

const IPReputation = require('../core/ip-reputation');
const logger = require('../logging');

const ipReputationMiddleware = (options = {}) => {
    const reputation = new IPReputation({
        apiKey: options.apiKey || process.env.ABUSEIPDB_API_KEY,
        blockThreshold: options.blockThreshold || 80,
        warnThreshold: options.warnThreshold || 50,
        cacheEnabled: options.cacheEnabled !== false,
        cacheTTL: options.cacheTTL || 3600000,
        dataDir: options.dataDir,
    });
    
    const blockEnabled = options.blockEnabled !== false;
    const checkMode = options.checkMode || 'async';
    const stealth = options.stealth !== false;
    
    const getClientIp = (req) => {
        if (options.trustProxy !== false) {
            const forwarded = req.headers['x-forwarded-for'];
            if (forwarded) {
                return forwarded.split(',')[0].trim();
            }
            
            const realIp = req.headers['x-real-ip'];
            if (realIp) {
                return realIp.trim();
            }
        }
        
        return req.socket?.remoteAddress || req.connection?.remoteAddress || 'unknown';
    };
    
    const sendBlockResponse = (res, ip, score) => {
        if (stealth) {
            res.statusCode = 403;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ error: 'Forbidden' }));
        } else {
            res.statusCode = 403;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({
                error: 'Blocked',
                reason: 'IP reputation',
                score: score,
            }));
        }
    };
    
    const middleware = async (req, res, next) => {
        const ip = getClientIp(req);
        
        req.reputation = reputation;
        
        if (checkMode === 'sync') {
            try {
                const result = await reputation.check(ip);
                req.reputationResult = result;
                
                if (result.blocked && blockEnabled) {
                    logger.warn('Request blocked by IP reputation', {
                        ip,
                        score: result.score,
                        reports: result.reports,
                        requestId: req.id,
                    });
                    
                    sendBlockResponse(res, ip, result.score);
                    return;
                }
                
                next();
            } catch (e) {
                logger.error('Reputation check error', { ip, error: e.message });
                next();
            }
        } else {
            // Async mode - check in background
            reputation.check(ip).then(result => {
                req.reputationResult = result;
                
                if (result.blocked && blockEnabled) {
                    logger.warn('IP has bad reputation (async check)', {
                        ip,
                        score: result.score,
                        reports: result.reports,
                    });
                }
            }).catch(e => {
                logger.debug('Async reputation check failed', { ip, error: e.message });
            });
            
            next();
        }
    };
    
    middleware.reputation = reputation;
    middleware.getStats = () => reputation.getStats();
    middleware.getStatus = () => reputation.getStatus();
    middleware.destroy = () => reputation.destroy();
    
    return middleware;
};

module.exports = ipReputationMiddleware;
