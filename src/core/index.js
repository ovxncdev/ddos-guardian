/**
 * Core Module Index
 * 
 * Usage:
 *   const { RateLimiter, IpTracker, BotDetector, Proxy, DockerDiscovery, SSLManager, IPReputation } = require('./core');
 */

const IpTracker = require('./ip-tracker');
const RateLimiter = require('./rate-limiter');
const BotDetector = require('./bot-detector');
const Proxy = require('./proxy');
const DockerDiscovery = require('./docker-discovery');
const SSLManager = require('./ssl-manager');
const IPReputation = require('./ip-reputation');

module.exports = {
    IpTracker,
    RateLimiter,
    BotDetector,
    Proxy,
    DockerDiscovery,
    SSLManager,
    IPReputation,
};
