/**
 * Environment & Paths Test
 * 
 * Run: node tests/environment.test.js
 */

const fs = require('fs');

const assert = (condition, message) => {
    if (!condition) {
        console.error(`❌ FAILED: ${message}`);
        process.exit(1);
    }
    console.log(`✅ PASSED: ${message}`);
};

console.log('\n📋 Testing Environment Detection & Path Resolution\n');

// ===================
// Environment Tests
// ===================
console.log('--- Environment Detection ---\n');

const { environment, paths } = require('../src/utils');

assert(environment !== undefined, 'Environment module loads');
assert(typeof environment.isDocker === 'boolean', 'isDocker is boolean');

const validPlatforms = ['docker', 'linux', 'macos', 'windows'];
assert(validPlatforms.includes(environment.platform), `Platform is valid: ${environment.platform}`);

const networkInfo = environment.getNetworkInfo();
assert(typeof networkInfo === 'object', 'getNetworkInfo returns object');
assert('isDocker' in networkInfo, 'networkInfo has isDocker');
assert('serviceDiscovery' in networkInfo, 'networkInfo has serviceDiscovery');

const resources = environment.getSystemResources();
assert(typeof resources === 'object', 'getSystemResources returns object');
assert(resources.cpuCount > 0, `CPU count valid: ${resources.cpuCount}`);
assert(resources.totalMemoryMB > 0, `Memory valid: ${resources.totalMemoryMB}MB`);

const summary = environment.getSummary();
assert(typeof summary === 'object', 'getSummary returns object');
assert('hostname' in summary, 'summary has hostname');

// ===================
// Path Tests
// ===================
console.log('\n--- Path Resolution ---\n');

assert(paths !== undefined, 'Paths module loads');
assert(typeof paths.root === 'string', 'Root path is string');
assert(paths.root.length > 0, 'Root path not empty');

const resolved = paths.resolve('test', 'path');
assert(resolved.includes('test'), 'resolve() includes segments');
assert(resolved.startsWith(paths.root), 'resolve() relative to root');

const srcPath = paths.src('config');
assert(srcPath.includes('src'), 'src() includes src directory');
assert(srcPath.includes('config'), 'src() includes subdirectory');

const logsPath = paths.logs();
assert(typeof logsPath === 'string', 'logs() returns string');
assert(fs.existsSync(logsPath), 'logs() creates directory');

const dataPath = paths.data();
assert(typeof dataPath === 'string', 'data() returns string');
assert(fs.existsSync(dataPath), 'data() creates directory');

const tempPath = paths.temp();
assert(typeof tempPath === 'string', 'temp() returns string');
assert(fs.existsSync(tempPath), 'temp() creates directory');

const allPaths = paths.getAll();
assert(typeof allPaths === 'object', 'getAll() returns object');
assert('root' in allPaths, 'getAll() has root');
assert('logs' in allPaths, 'getAll() has logs');

const validation = paths.validate();
assert(typeof validation === 'object', 'validate() returns object');
assert('valid' in validation, 'validate() has valid property');
assert(validation.valid === true, 'All paths are writable');

// ===================
// Integration Test
// ===================
console.log('\n--- Integration ---\n');

const config = require('../src/config');
assert(typeof config.docker.isRunning === 'boolean', 'Config uses environment detection');

// Summary
console.log('\n📊 Environment Summary:');
console.log(`   Platform: ${environment.platform}`);
console.log(`   Is Docker: ${environment.isDocker}`);
console.log(`   Node: ${resources.nodeVersion}`);
console.log(`   CPUs: ${resources.cpuCount}`);
console.log(`   Memory: ${resources.totalMemoryMB}MB`);

console.log('\n📂 Paths Summary:');
console.log(`   Root: ${paths.root}`);
console.log(`   Logs: ${paths.logs()}`);
console.log(`   Data: ${paths.data()}`);

console.log('\n✅ All environment and path tests passed!\n');
