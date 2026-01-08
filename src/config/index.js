/**
 * Configuration Loader
 * 
 * SINGLE SOURCE OF TRUTH for all configuration.
 * 
 * Usage:
 *   const config = require('./config');
 *   console.log(config.get('PORT'));
 */

const path = require('path');
const fs = require('fs');
const dotenv = require('dotenv');

// Find project root directory
const findRootDir = () => {
    let dir = __dirname;
    
    while (dir !== '/') {
        if (fs.existsSync(path.join(dir, 'package.json'))) {
            return dir;
        }
        dir = path.dirname(dir);
    }
    
    return process.cwd();
};

const ROOT_DIR = findRootDir();

// Load .env file if it exists
const envPath = path.join(ROOT_DIR, '.env');
if (fs.existsSync(envPath)) {
    dotenv.config({ path: envPath });
}

// Load schema after env is loaded
const schema = require('./schema');

/**
 * Validate configuration
 */
const loadConfig = () => {
    const { error, value } = schema.validate(process.env);
    
    if (error) {
        console.error('❌ Configuration validation failed:');
        console.error(error.details.map(d => `   - ${d.message}`).join('\n'));
        process.exit(1);
    }
    
    return value;
};

const rawConfig = loadConfig();

/**
 * Processed configuration object
 */
const config = {
    _raw: rawConfig,
    
    // Environment
    env: rawConfig.NODE_ENV,
    isDevelopment: rawConfig.NODE_ENV === 'development',
    isProduction: rawConfig.NODE_ENV === 'production',
    isTest: rawConfig.NODE_ENV === 'test',
    
    // Server
    server: {
        port: rawConfig.PORT,
        host: rawConfig.HOST,
    },
    
    // Upstream services
    upstream: {
        hosts: rawConfig.UPSTREAM_HOSTS 
            ? rawConfig.UPSTREAM_HOSTS.split(',').map(h => h.trim()).filter(Boolean)
            : [],
    },
    
    // Rate limiting
    rateLimit: {
        windowMs: rawConfig.RATE_LIMIT_WINDOW_MS,
        maxRequests: rawConfig.RATE_LIMIT_MAX_REQUESTS,
        blockDurationMs: rawConfig.RATE_LIMIT_BLOCK_DURATION_MS,
    },
    
    // Bot detection
    botDetection: {
        enabled: rawConfig.BOT_DETECTION_ENABLED,
        scoreThreshold: rawConfig.BOT_SCORE_THRESHOLD,
    },
    
    // Logging
    logging: {
        level: rawConfig.LOG_LEVEL,
        format: rawConfig.LOG_FORMAT,
        dir: rawConfig.LOG_DIR || null,
    },
    
    // Security
    security: {
        trustProxy: rawConfig.TRUST_PROXY,
        stealthMode: rawConfig.STEALTH_MODE,
    },
    
    // Paths
    paths: {
        root: ROOT_DIR,
        src: path.join(ROOT_DIR, 'src'),
        data: rawConfig.DATA_DIR || path.join(ROOT_DIR, 'data'),
        logs: rawConfig.LOG_DIR || path.join(ROOT_DIR, 'logs'),
    },
    
    // Docker detection (uses environment utility)
    docker: {
        get isRunning() {
            const { environment } = require('../utils');
            return environment.isDocker;
        },
    },
    
    /**
     * Get raw config value by key
     */
    get(key) {
        if (!(key in this._raw)) {
            throw new Error(`Unknown config key: ${key}`);
        }
        return this._raw[key];
    },
    
    /**
     * Check if feature is enabled
     */
    isEnabled(feature) {
        const features = {
            botDetection: this.botDetection.enabled,
            stealthMode: this.security.stealthMode,
        };
        return features[feature] ?? false;
    },
    
    /**
     * Get safe config for logging (no sensitive data)
     */
    toSafeObject() {
        return {
            env: this.env,
            server: this.server,
            upstream: { hostCount: this.upstream.hosts.length },
            rateLimit: this.rateLimit,
            botDetection: this.botDetection,
            logging: { level: this.logging.level, format: this.logging.format },
            security: { trustProxy: this.security.trustProxy, stealthMode: this.security.stealthMode },
        };
    }
};

// Freeze to prevent mutation
Object.freeze(config);
Object.freeze(config.server);
Object.freeze(config.upstream);
Object.freeze(config.rateLimit);
Object.freeze(config.botDetection);
Object.freeze(config.logging);
Object.freeze(config.security);
Object.freeze(config.paths);
Object.freeze(config.docker);

module.exports = config;
