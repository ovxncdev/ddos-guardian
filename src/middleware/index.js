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
 *     ipReputationMiddleware,
 *   } = require('./middleware');
 */

const rateLimitMiddleware = require('./rate-limit');
const requestIdMiddleware = require('./request-id');
const securityHeadersMiddleware = require('./security-headers');
const loggerMiddleware = require('./logger');
const botDetectionMiddleware = require('./bot-detection');
const ipReputationMiddleware = require('./ip-reputation');

module.exports = {
    rateLimitMiddleware,
    requestIdMiddleware,
    securityHeadersMiddleware,
    loggerMiddleware,
    botDetectionMiddleware,
    ipReputationMiddleware,
};
