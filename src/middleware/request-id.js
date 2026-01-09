/**
 * Request ID Middleware
 * 
 * Adds unique ID to each request for tracking/logging.
 * 
 * Usage:
 *   const { requestIdMiddleware } = require('./middleware');
 *   app.use(requestIdMiddleware());
 */

const { generateRequestId } = require('../logging');

/**
 * Create request ID middleware
 */
const createRequestIdMiddleware = (options = {}) => {
    const headerName = options.headerName || 'X-Request-ID';
    const trustIncoming = options.trustIncoming !== false;
    
    return (req, res, next) => {
        // Use existing ID or generate new one
        let requestId;
        
        if (trustIncoming && req.headers[headerName.toLowerCase()]) {
            requestId = req.headers[headerName.toLowerCase()];
        } else {
            requestId = generateRequestId();
        }
        
        // Attach to request
        req.id = requestId;
        req.requestId = requestId;
        
        // Add to response headers
        res.setHeader(headerName, requestId);
        
        next();
    };
};

module.exports = createRequestIdMiddleware;
