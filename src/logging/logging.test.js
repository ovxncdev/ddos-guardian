/**
 * Logging System Test
 * 
 * Run: node tests/logging.test.js
 */

const fs = require('fs');
const path = require('path');

const assert = (condition, message) => {
    if (!condition) {
        console.error(`❌ FAILED: ${message}`);
        process.exit(1);
    }
    console.log(`✅ PASSED: ${message}`);
};

const runTests = async () => {
console.log('\n📋 Testing Logging System\n');

// ===================
// Basic Tests
// ===================
console.log('--- Basic Logger ---\n');

const logger = require('../src/logging');
const { Logger, generateRequestId } = require('../src/logging');

assert(logger !== undefined, 'Logger module loads');
assert(typeof logger.info === 'function', 'logger.info exists');
assert(typeof logger.error === 'function', 'logger.error exists');
assert(typeof logger.warn === 'function', 'logger.warn exists');
assert(typeof logger.debug === 'function', 'logger.debug exists');

// Test logging (visual check)
console.log('\n--- Log Output Examples ---\n');
logger.info('Test info message', { test: true });
logger.warn('Test warning', { code: 'W001' });
logger.error('Test error', { error: 'Something went wrong' });

// ===================
// Request ID
// ===================
console.log('\n--- Request ID ---\n');

const reqId1 = generateRequestId();
const reqId2 = generateRequestId();

assert(typeof reqId1 === 'string', 'generateRequestId returns string');
assert(reqId1.startsWith('req_'), 'Request ID has correct prefix');
assert(reqId1 !== reqId2, 'Request IDs are unique');

// ===================
// Child Logger
// ===================
console.log('\n--- Child Logger ---\n');

const childLogger = logger.child({ service: 'test-service' });
assert(childLogger !== undefined, 'child() returns logger');
assert(typeof childLogger.info === 'function', 'Child has info method');

childLogger.info('Child logger message', { extra: 'data' });

// ===================
// Custom Logger Instance
// ===================
console.log('\n--- Custom Logger Instance ---\n');

const customLogger = new Logger({
    level: 'debug',
    format: 'pretty',
    context: { app: 'test' },
});

assert(customLogger instanceof Logger, 'Can create Logger instance');
customLogger.debug('Debug message visible', { detail: 'value' });

// ===================
// Level Filtering
// ===================
console.log('\n--- Level Filtering ---\n');

const warnOnlyLogger = new Logger({
    level: 'warn',
    format: 'pretty',
});

assert(warnOnlyLogger.shouldLog('error') === true, 'Error logged at warn level');
assert(warnOnlyLogger.shouldLog('warn') === true, 'Warn logged at warn level');
assert(warnOnlyLogger.shouldLog('info') === false, 'Info NOT logged at warn level');
assert(warnOnlyLogger.shouldLog('debug') === false, 'Debug NOT logged at warn level');

// ===================
// JSON Format
// ===================
console.log('\n--- JSON Format ---\n');

const jsonLogger = new Logger({
    level: 'info',
    format: 'json',
});

jsonLogger.info('JSON formatted message', { format: 'json' });

// ===================
// File Writing
// ===================
console.log('\n--- File Writing ---\n');

const { paths } = require('../src/utils');
const testLogDir = path.join(paths.root, 'temp-test-logs');

// Ensure directory exists
if (!fs.existsSync(testLogDir)) {
    fs.mkdirSync(testLogDir, { recursive: true });
}

const fileLogger = new Logger({
    level: 'info',
    format: 'json',
    logDir: testLogDir,
});

fileLogger.info('Test file write', { written: true });
fileLogger.close();

// Small delay to allow file write to complete
await new Promise(resolve => setTimeout(resolve, 100));

// Check file was created
const today = new Date().toISOString().split('T')[0];
const expectedFile = path.join(testLogDir, `guardian-${today}.log`);

assert(fs.existsSync(expectedFile), 'Log file was created');

// Read and verify content
const logContent = fs.readFileSync(expectedFile, 'utf8');
assert(logContent.includes('Test file write'), 'Log file contains message');
assert(logContent.includes('"written":true'), 'Log file contains meta');

// Cleanup
fs.unlinkSync(expectedFile);
fs.rmSync(testLogDir, { recursive: true });

// ===================
// Request Logger
// ===================
console.log('\n--- Request Logger ---\n');

const mockRequest = {
    method: 'GET',
    url: '/api/test',
    ip: '127.0.0.1',
};

const reqLogger = logger.forRequest(mockRequest);
assert(reqLogger !== undefined, 'forRequest returns logger');
reqLogger.info('Request logged');

// ===================
// Error Handling
// ===================
console.log('\n--- Error Object Handling ---\n');

const testError = new Error('Test error message');
logger.error('Caught error', { error: testError });

// Circular reference handling
const circular = { name: 'test' };
circular.self = circular;
logger.info('Circular object', { data: circular });

console.log('\n✅ All logging tests passed!\n');
};

runTests().catch(err => {
    console.error('Test failed:', err);
    process.exit(1);
});
