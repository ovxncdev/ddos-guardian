/**
 * Core Module Index
 * 
 * Usage:
 *   const { RateLimiter, IpTracker, BotDetector, Proxy } = require('./core');
 */

const IpTracker = require('./ip-tracker');
const RateLimiter = require('./rate-limiter');
const BotDetector = require('./bot-detector');
const Proxy = require('./proxy');

module.exports = {
    IpTracker,
    RateLimiter,
    BotDetector,
    Proxy,
};
