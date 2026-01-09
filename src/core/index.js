/**
 * Core Module Index
 * 
 * Usage:
 *   const { RateLimiter, IpTracker, BotDetector } = require('./core');
 */

const IpTracker = require('./ip-tracker');
const RateLimiter = require('./rate-limiter');
const BotDetector = require('./bot-detector');

module.exports = {
    IpTracker,
    RateLimiter,
    BotDetector,
};
