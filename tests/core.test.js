/**
 * Core Protection Engine Test
 * 
 * Run: node tests/core.test.js
 */

const assert = (condition, message) => {
    if (!condition) {
        console.error(`❌ FAILED: ${message}`);
        process.exit(1);
    }
    console.log(`✅ PASSED: ${message}`);
};

console.log('\n📋 Testing Core Protection Engine\n');

const { IpTracker, RateLimiter } = require('../src/core');

// ===================
// IP Tracker Tests
// ===================
console.log('--- IP Tracker ---\n');

const tracker = new IpTracker({
    windowMs: 1000,      // 1 second window
    maxRequests: 5,      // 5 requests max
    blockDurationMs: 2000, // 2 second block
    cleanupIntervalMs: 60000,
});

assert(tracker !== undefined, 'IpTracker loads');

// Test basic tracking
const result1 = tracker.track('192.168.1.1');
assert(result1.allowed === true, 'First request allowed');
assert(result1.remaining === 4, 'Remaining is 4 after first request');

// Make more requests
tracker.track('192.168.1.1');
tracker.track('192.168.1.1');
tracker.track('192.168.1.1');
const result5 = tracker.track('192.168.1.1');
assert(result5.allowed === true, 'Fifth request allowed');
assert(result5.remaining === 0, 'Remaining is 0 after fifth request');

// Sixth request should be blocked
const result6 = tracker.track('192.168.1.1');
assert(result6.allowed === false, 'Sixth request blocked');
assert(result6.blocked === true, 'IP is blocked');
assert(result6.reason === 'rate_limit_exceeded', 'Reason is rate_limit_exceeded');

// Different IP should be allowed
const resultOther = tracker.track('192.168.1.2');
assert(resultOther.allowed === true, 'Different IP allowed');

// Test isBlocked
assert(tracker.isBlocked('192.168.1.1') === true, 'isBlocked returns true for blocked IP');
assert(tracker.isBlocked('192.168.1.2') === false, 'isBlocked returns false for unblocked IP');

// Test manual block/unblock
tracker.block('192.168.1.3', 5000, 'test');
assert(tracker.isBlocked('192.168.1.3') === true, 'Manual block works');

tracker.unblock('192.168.1.3');
assert(tracker.isBlocked('192.168.1.3') === false, 'Unblock works');

// Test getStats
const stats = tracker.getStats('192.168.1.1');
assert(stats !== null, 'getStats returns data');
assert(stats.totalRequests === 6, 'Total requests tracked');
assert(stats.blocked === true, 'Stats show blocked status');

// Test global stats
const globalStats = tracker.getGlobalStats();
assert(globalStats.totalIps >= 2, 'Global stats track IPs');
assert(globalStats.blockedIps >= 1, 'Global stats track blocked IPs');

// Test IP masking
const masked = tracker.maskIp('192.168.1.100');
assert(masked === '192.168.xxx.xxx', 'IPv4 masking works');

const maskedV6 = tracker.maskIp('2001:0db8:85a3:0000:0000:8a2e:0370:7334');
assert(maskedV6 === '2001:0db8:xxxx:xxxx', 'IPv6 masking works');

// Cleanup tracker
tracker.destroy();

// ===================
// Rate Limiter Tests
// ===================
console.log('\n--- Rate Limiter ---\n');

const limiter = new RateLimiter({
    windowMs: 1000,
    maxRequests: 3,
    blockDurationMs: 2000,
    trustProxy: true,
    whitelist: ['10.0.0.1'],
    blacklist: ['10.0.0.2'],
    skipPaths: ['/health', '/ready'],
});

assert(limiter !== undefined, 'RateLimiter loads');

// Mock request
const mockReq = (ip, path = '/api/test', headers = {}) => ({
    url: path,
    headers: { 'x-forwarded-for': ip, ...headers },
    socket: { remoteAddress: '127.0.0.1' },
});

// Test basic rate limiting
const req1 = mockReq('172.16.0.1');
const check1 = limiter.check(req1);
assert(check1.allowed === true, 'First request allowed');
assert(check1.ip === '172.16.0.1', 'IP extracted correctly');

// Test whitelist
const reqWhite = mockReq('10.0.0.1');
const checkWhite = limiter.check(reqWhite);
assert(checkWhite.allowed === true, 'Whitelisted IP allowed');
assert(checkWhite.reason === 'whitelisted', 'Reason is whitelisted');

// Test blacklist
const reqBlack = mockReq('10.0.0.2');
const checkBlack = limiter.check(reqBlack);
assert(checkBlack.allowed === false, 'Blacklisted IP blocked');
assert(checkBlack.reason === 'blacklisted', 'Reason is blacklisted');

// Test skip paths
const reqHealth = mockReq('172.16.0.5', '/health');
const checkHealth = limiter.check(reqHealth);
assert(checkHealth.allowed === true, 'Health path allowed');
assert(checkHealth.reason === 'skipped', 'Reason is skipped');

// Test rate limit exceeded
const testIp = '172.16.0.10';
limiter.check(mockReq(testIp));
limiter.check(mockReq(testIp));
limiter.check(mockReq(testIp));
const checkExceeded = limiter.check(mockReq(testIp));
assert(checkExceeded.allowed === false, 'Rate limit exceeded blocks');
assert(checkExceeded.reason === 'rate_limit_exceeded', 'Reason is rate_limit_exceeded');

// Test whitelist management
limiter.addToWhitelist('172.16.0.20');
const checkNewWhite = limiter.check(mockReq('172.16.0.20'));
assert(checkNewWhite.reason === 'whitelisted', 'Dynamic whitelist works');

limiter.removeFromWhitelist('172.16.0.20');
const checkRemovedWhite = limiter.check(mockReq('172.16.0.20'));
assert(checkRemovedWhite.reason !== 'whitelisted', 'Remove from whitelist works');

// Test blacklist management
limiter.addToBlacklist('172.16.0.30');
const checkNewBlack = limiter.check(mockReq('172.16.0.30'));
assert(checkNewBlack.reason === 'blacklisted', 'Dynamic blacklist works');

// Test manual block
limiter.blockIp('172.16.0.40', 5000, 'test');
const checkManualBlock = limiter.check(mockReq('172.16.0.40'));
assert(checkManualBlock.allowed === false, 'Manual block works');

// Test stats
const limiterStats = limiter.getStats();
assert(typeof limiterStats.totalIps === 'number', 'Stats have totalIps');
assert(typeof limiterStats.whitelistSize === 'number', 'Stats have whitelistSize');

// Test disabled limiter
const disabledLimiter = new RateLimiter({ enabled: false });
const checkDisabled = disabledLimiter.check(mockReq('1.2.3.4'));
assert(checkDisabled.allowed === true, 'Disabled limiter allows all');
assert(checkDisabled.reason === 'disabled', 'Reason is disabled');
disabledLimiter.destroy();

// Cleanup
limiter.destroy();

// ===================
// IP Extraction Tests
// ===================
console.log('\n--- IP Extraction ---\n');

const { extractIp } = require('../src/core/rate-limiter');

// X-Forwarded-For
const reqXFF = { headers: { 'x-forwarded-for': '1.1.1.1, 2.2.2.2' } };
assert(extractIp(reqXFF, true) === '1.1.1.1', 'X-Forwarded-For extracts first IP');

// X-Real-IP
const reqXRI = { headers: { 'x-real-ip': '3.3.3.3' } };
assert(extractIp(reqXRI, true) === '3.3.3.3', 'X-Real-IP works');

// Direct connection
const reqDirect = { socket: { remoteAddress: '4.4.4.4' }, headers: {} };
assert(extractIp(reqDirect, true) === '4.4.4.4', 'Direct connection works');

// Trust proxy disabled
const reqNoTrust = { headers: { 'x-forwarded-for': '1.1.1.1' }, socket: { remoteAddress: '5.5.5.5' } };
assert(extractIp(reqNoTrust, false) === '5.5.5.5', 'Trust proxy disabled ignores headers');

console.log('\n✅ All core protection tests passed!\n');
