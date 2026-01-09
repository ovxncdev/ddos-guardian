/**
 * Middleware Index
 * 
 * Usage:
 *   const { 
 *     rateLimitMiddleware, 
 *     requestIdMiddleware,
 *     securityHeadersMiddleware,
 *     loggerMiddleware,
 *     botDetectionMiddleware,
 *   } = require('./middleware');
 */

const rateLimitMiddleware = require('./rate-limit');
const requestIdMiddleware = require('./request-id');
const securityHeadersMiddleware = require('./security-headers');
const loggerMiddleware = require('./logger');
const botDetectionMiddleware = require('./bot-detection');

module.exports = {
    rateLimitMiddleware,
    requestIdMiddleware,
    securityHeadersMiddleware,
    loggerMiddleware,
    botDetectionMiddleware,
};
