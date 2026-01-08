/**
 * Environment Detection Utility
 * 
 * Detects whether we're running in Docker or directly on host.
 */

const fs = require('fs');
const os = require('os');

/**
 * Check if /.dockerenv file exists
 */
const checkDockerEnvFile = () => {
    try {
        return fs.existsSync('/.dockerenv');
    } catch {
        return false;
    }
};

/**
 * Check if running in Docker via cgroup
 */
const checkCgroup = () => {
    try {
        const cgroup = fs.readFileSync('/proc/1/cgroup', 'utf8');
        return cgroup.includes('docker') || cgroup.includes('kubepods');
    } catch {
        return false;
    }
};

/**
 * Check for Docker-style hostname (12 char hex)
 */
const checkHostname = () => {
    const hostname = os.hostname();
    return /^[a-f0-9]{12}$/.test(hostname);
};

/**
 * Detect if running inside Docker container
 */
const detectDocker = () => {
    // 1. Check explicit override
    const envOverride = process.env.RUNNING_IN_DOCKER;
    if (envOverride !== undefined) {
        return envOverride === 'true' || envOverride === '1';
    }
    
    // 2. Check /.dockerenv file
    if (checkDockerEnvFile()) {
        return true;
    }
    
    // 3. Check cgroup
    if (checkCgroup()) {
        return true;
    }
    
    // 4. Check hostname pattern
    if (checkHostname()) {
        return true;
    }
    
    return false;
};

/**
 * Get the platform
 */
const getPlatform = () => {
    if (detectDocker()) {
        return 'docker';
    }
    
    const platform = os.platform();
    switch (platform) {
        case 'linux':
            return 'linux';
        case 'darwin':
            return 'macos';
        case 'win32':
            return 'windows';
        default:
            return 'linux';
    }
};

/**
 * Get network information
 */
const getNetworkInfo = () => {
    const isDocker = detectDocker();
    
    return {
        isDocker,
        serviceDiscovery: isDocker ? 'docker-dns' : 'direct',
        defaultInterface: isDocker ? 'bridge' : 'loopback',
        hostname: os.hostname(),
        interfaces: getExternalInterfaces(),
    };
};

/**
 * Get external network interfaces
 */
const getExternalInterfaces = () => {
    const interfaces = os.networkInterfaces();
    const external = {};
    
    for (const [name, addrs] of Object.entries(interfaces)) {
        const filtered = addrs.filter(addr => !addr.internal);
        if (filtered.length > 0) {
            external[name] = filtered.map(addr => ({
                address: addr.address,
                family: addr.family,
            }));
        }
    }
    
    return external;
};

/**
 * Get system resources
 */
const getSystemResources = () => {
    return {
        cpuCount: os.cpus().length,
        totalMemoryMB: Math.round(os.totalmem() / 1024 / 1024),
        freeMemoryMB: Math.round(os.freemem() / 1024 / 1024),
        platform: os.platform(),
        arch: os.arch(),
        nodeVersion: process.version,
    };
};

// Cache detection results
const _isDocker = detectDocker();
const _platform = getPlatform();

/**
 * Environment object
 */
const environment = {
    isDocker: _isDocker,
    platform: _platform,
    
    isLinux: _platform === 'linux' || _platform === 'docker',
    isMacOS: _platform === 'macos',
    isWindows: _platform === 'windows',
    isProduction: process.env.NODE_ENV === 'production',
    isDevelopment: process.env.NODE_ENV !== 'production',
    
    getNetworkInfo,
    getSystemResources,
    
    _detectors: {
        checkDockerEnvFile,
        checkCgroup,
        checkHostname,
        detectDocker,
    },
    
    getSummary() {
        return {
            isDocker: this.isDocker,
            platform: this.platform,
            hostname: os.hostname(),
            nodeVersion: process.version,
            pid: process.pid,
        };
    },
};

module.exports = environment;
