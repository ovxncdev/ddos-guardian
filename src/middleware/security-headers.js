/**
 * Security Headers Middleware
 * 
 * Adds security headers and hides server fingerprints (stealth mode).
 * 
 * Usage:
 *   const { securityHeadersMiddleware } = require('./middleware');
 *   app.use(securityHeadersMiddleware());
 */

/**
 * Create security headers middleware
 */
const createSecurityHeadersMiddleware = (options = {}) => {
    const stealth = options.stealth !== false;
    
    // Default security headers
    const headers = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        ...options.customHeaders,
    };
    
    // Headers to remove in stealth mode
    const removeHeaders = [
        'X-Powered-By',
        'Server',
    ];
    
    return (req, res, next) => {
        // Add security headers
        for (const [name, value] of Object.entries(headers)) {
            res.setHeader(name, value);
        }
        
        // Stealth mode: remove identifying headers
        if (stealth) {
            // Override res.writeHead to remove headers
            const originalWriteHead = res.writeHead.bind(res);
            res.writeHead = function(statusCode, statusMessage, headers) {
                for (const header of removeHeaders) {
                    res.removeHeader(header);
                }
                return originalWriteHead(statusCode, statusMessage, headers);
            };
        }
        
        next();
    };
};

module.exports = createSecurityHeadersMiddleware;
