/**
 * Core Module Index
 * 
 * Usage:
 *   const { RateLimiter, IpTracker } = require('./core');
 */

const IpTracker = require('./ip-tracker');
const RateLimiter = require('./rate-limiter');

module.exports = {
    IpTracker,
    RateLimiter,
};
