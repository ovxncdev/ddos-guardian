/**
 * Request Logger Middleware
 * 
 * Logs all incoming requests with timing.
 * 
 * Usage:
 *   const { loggerMiddleware } = require('./middleware');
 *   app.use(loggerMiddleware());
 */

const logger = require('../logging');

/**
 * Create request logger middleware
 */
const createLoggerMiddleware = (options = {}) => {
    const logLevel = options.level || 'info';
    const skipPaths = options.skipPaths || ['/health', '/ready'];
    
    return (req, res, next) => {
        const startTime = Date.now();
        const path = req.url?.split('?')[0] || req.path || '/';
        
        // Skip certain paths
        if (skipPaths.some(skip => path.startsWith(skip))) {
            return next();
        }
        
        // Log on response finish
        res.on('finish', () => {
            const duration = Date.now() - startTime;
            const statusCode = res.statusCode;
            
            // Choose log level based on status
            let level = logLevel;
            if (statusCode >= 500) {
                level = 'error';
            } else if (statusCode >= 400) {
                level = 'warn';
            }
            
            logger[level]('Request completed', {
                requestId: req.id || req.requestId,
                method: req.method,
                path,
                statusCode,
                duration,
                ip: req.rateLimit?.ip || req.ip,
                userAgent: req.headers?.['user-agent']?.substring(0, 100),
            });
        });
        
        next();
    };
};

module.exports = createLoggerMiddleware;
