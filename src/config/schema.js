/**
 * Configuration Schema
 * 
 * Defines ALL configuration options for ddos-guardian.
 * Every setting must be defined here with validation rules.
 */

const Joi = require('joi');

const schema = Joi.object({
    // ===================
    // NODE ENVIRONMENT
    // ===================
    NODE_ENV: Joi.string()
        .valid('development', 'production', 'test')
        .default('development')
        .description('Application environment'),

    // ===================
    // SERVER SETTINGS
    // ===================
    PORT: Joi.number()
        .port()
        .default(3000)
        .description('Port the guardian listens on'),

    HOST: Joi.string()
        .hostname()
        .default('0.0.0.0')
        .description('Host to bind to'),

    // ===================
    // UPSTREAM SERVICES
    // ===================
    UPSTREAM_HOSTS: Joi.string()
        .allow('')
        .default('')
        .description('Comma-separated list of upstream service URLs'),

    // ===================
    // AUTO-DISCOVERY
    // ===================
    AUTO_DISCOVER: Joi.boolean()
        .default(true)
        .description('Auto-discover Docker containers'),

    AUTO_DISCOVER_INTERVAL: Joi.number()
        .integer()
        .min(5000)
        .default(30000)
        .description('Interval for re-scanning containers (ms)'),

    DOCKER_SOCKET_PATH: Joi.string()
        .default('')
        .description('Path to Docker socket (auto-detected if empty)'),

    // ===================
    // RATE LIMITING
    // ===================
    RATE_LIMIT_WINDOW_MS: Joi.number()
        .integer()
        .min(1000)
        .default(60000)
        .description('Time window for rate limiting (ms)'),

    RATE_LIMIT_MAX_REQUESTS: Joi.number()
        .integer()
        .min(1)
        .default(100)
        .description('Max requests per window per IP'),

    RATE_LIMIT_BLOCK_DURATION_MS: Joi.number()
        .integer()
        .min(1000)
        .default(300000)
        .description('Block duration after limit exceeded (ms)'),

    // ===================
    // BOT DETECTION
    // ===================
    BOT_DETECTION_ENABLED: Joi.boolean()
        .default(true)
        .description('Enable bot detection'),

    BOT_SCORE_THRESHOLD: Joi.number()
        .min(0)
        .max(100)
        .default(70)
        .description('Score above which request is a bot (0-100)'),

    // ===================
    // LOGGING
    // ===================
    LOG_LEVEL: Joi.string()
        .valid('error', 'warn', 'info', 'debug')
        .default('info')
        .description('Minimum log level'),

    LOG_FORMAT: Joi.string()
        .valid('json', 'pretty')
        .default('json')
        .description('Log output format'),

    LOG_DIR: Joi.string()
        .default('')
        .description('Directory for log files'),

    // ===================
    // SECURITY
    // ===================
    TRUST_PROXY: Joi.boolean()
        .default(true)
        .description('Trust X-Forwarded-For headers'),

    STEALTH_MODE: Joi.boolean()
        .default(true)
        .description('Hide guardian fingerprints'),

    // ===================
    // DOCKER
    // ===================
    RUNNING_IN_DOCKER: Joi.boolean()
        .default(false)
        .description('Override Docker detection'),

    // ===================
    // PATHS
    // ===================
    DATA_DIR: Joi.string()
        .default('')
        .description('Directory for persistent data'),

}).options({
    allowUnknown: true,
    stripUnknown: false
});

module.exports = schema;
