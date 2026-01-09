/**
 * Bot Detection Middleware
 * 
 * Analyzes requests and blocks detected bots.
 * 
 * Usage:
 *   const { botDetectionMiddleware } = require('./middleware');
 *   app.use(botDetectionMiddleware({ threshold: 70 }));
 */

const { BotDetector } = require('../core');
const logger = require('../logging');

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
    
    const middleware = (req, res, next) => {
        // Skip if detector disabled
        if (!detector.enabled) {
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
