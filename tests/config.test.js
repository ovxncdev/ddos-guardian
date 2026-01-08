/**
 * Configuration System Test
 * 
 * Run: node tests/config.test.js
 */

const assert = (condition, message) => {
    if (!condition) {
        console.error(`❌ FAILED: ${message}`);
        process.exit(1);
    }
    console.log(`✅ PASSED: ${message}`);
};

console.log('\n📋 Testing Configuration System\n');

// Test 1: Config loads without error
let config;
try {
    config = require('../src/config');
    assert(true, 'Config loads without error');
} catch (err) {
    assert(false, `Config failed to load: ${err.message}`);
}

// Test 2: Default values are set
assert(config.server.port === 3000, 'Default PORT is 3000');
assert(config.server.host === '0.0.0.0', 'Default HOST is 0.0.0.0');
assert(config.env === 'development', 'Default NODE_ENV is development');

// Test 3: Rate limit defaults
assert(config.rateLimit.windowMs === 60000, 'Default rate limit window is 60s');
assert(config.rateLimit.maxRequests === 100, 'Default max requests is 100');

// Test 4: Security defaults
assert(config.security.trustProxy === true, 'Trust proxy is true by default');
assert(config.security.stealthMode === true, 'Stealth mode is true by default');

// Test 5: Paths are resolved
assert(config.paths.root.length > 0, 'Root path is resolved');
assert(config.paths.src.includes('src'), 'Src path contains "src"');

// Test 6: Config is frozen (immutable)
try {
    config.server.port = 9999;
    assert(config.server.port === 3000, 'Config is immutable');
} catch (err) {
    assert(true, 'Config is immutable (throws on modification)');
}

// Test 7: get() method works
assert(config.get('PORT') === 3000, 'get() returns correct value');

// Test 8: get() throws on unknown key
try {
    config.get('UNKNOWN_KEY');
    assert(false, 'get() should throw on unknown key');
} catch (err) {
    assert(true, 'get() throws on unknown key');
}

// Test 9: toSafeObject() works
const safe = config.toSafeObject();
assert(typeof safe === 'object', 'toSafeObject() returns object');
assert(safe.env === 'development', 'toSafeObject() includes env');

// Test 10: isEnabled() works
assert(typeof config.isEnabled('botDetection') === 'boolean', 'isEnabled() returns boolean');

console.log('\n✅ All configuration tests passed!\n');
