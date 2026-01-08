/**
 * Logger
 * 
 * Structured logging with levels, formats, and file output.
 * 
 * Usage:
 *   const logger = require('./logging');
 *   logger.info('Server started', { port: 3000 });
 *   logger.error('Failed', { error: err.message });
 */

const fs = require('fs');
const path = require('path');
const { paths } = require('../utils');

// Log levels (lower = more severe)
const LEVELS = {
    error: 0,
    warn: 1,
    info: 2,
    debug: 3,
};

// Colors for pretty output
const COLORS = {
    reset: '\x1b[0m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    gray: '\x1b[90m',
    bold: '\x1b[1m',
};

const LEVEL_COLORS = {
    error: COLORS.red,
    warn: COLORS.yellow,
    info: COLORS.blue,
    debug: COLORS.gray,
};

/**
 * Get current config (lazy load to avoid circular deps)
 */
const getConfig = () => {
    try {
        return require('../config');
    } catch {
        return {
            logging: {
                level: 'info',
                format: 'pretty',
                dir: null,
            },
            isProduction: false,
        };
    }
};

/**
 * Format timestamp
 */
const getTimestamp = () => {
    return new Date().toISOString();
};

/**
 * Generate unique request ID
 */
const generateRequestId = () => {
    return `req_${Date.now().toString(36)}_${Math.random().toString(36).substr(2, 9)}`;
};

/**
 * Safely stringify objects (handles circular refs)
 */
const safeStringify = (obj, indent = null) => {
    const seen = new WeakSet();
    return JSON.stringify(obj, (key, value) => {
        if (typeof value === 'object' && value !== null) {
            if (seen.has(value)) {
                return '[Circular]';
            }
            seen.add(value);
        }
        if (value instanceof Error) {
            return {
                message: value.message,
                stack: value.stack,
                name: value.name,
            };
        }
        return value;
    }, indent);
};

/**
 * Format log entry as JSON
 */
const formatJson = (level, message, meta) => {
    const entry = {
        timestamp: getTimestamp(),
        level,
        message,
        ...meta,
    };
    return safeStringify(entry);
};

/**
 * Format log entry as pretty text
 */
const formatPretty = (level, message, meta) => {
    const timestamp = getTimestamp();
    const color = LEVEL_COLORS[level] || COLORS.reset;
    const levelStr = level.toUpperCase().padEnd(5);
    
    let output = `${COLORS.gray}${timestamp}${COLORS.reset} ${color}${levelStr}${COLORS.reset} ${message}`;
    
    if (meta && Object.keys(meta).length > 0) {
        const metaStr = safeStringify(meta, 2);
        output += `\n${COLORS.gray}${metaStr}${COLORS.reset}`;
    }
    
    return output;
};

/**
 * File writer with rotation support
 */
class FileWriter {
    constructor(logDir) {
        this.logDir = logDir;
        this.currentDate = null;
        this.stream = null;
    }
    
    getLogFilePath() {
        const date = new Date().toISOString().split('T')[0];
        return path.join(this.logDir, `guardian-${date}.log`);
    }
    
    ensureStream() {
        const today = new Date().toISOString().split('T')[0];
        
        // Rotate if date changed
        if (this.currentDate !== today) {
            if (this.stream) {
                this.stream.end();
            }
            
            const filePath = this.getLogFilePath();
            this.stream = fs.createWriteStream(filePath, { flags: 'a' });
            this.currentDate = today;
        }
        
        return this.stream;
    }
    
    write(line) {
        try {
            const stream = this.ensureStream();
            stream.write(line + '\n');
        } catch (err) {
            console.error('Failed to write log:', err.message);
        }
    }
    
    close() {
        if (this.stream) {
            this.stream.end();
            this.stream = null;
        }
    }
}

/**
 * Logger class
 */
class Logger {
    constructor(options = {}) {
        this.level = options.level || 'info';
        this.format = options.format || 'pretty';
        this.fileWriter = null;
        this.context = options.context || {};
        
        if (options.logDir) {
            this.fileWriter = new FileWriter(options.logDir);
        }
    }
    
    /**
     * Check if level should be logged
     */
    shouldLog(level) {
        return LEVELS[level] <= LEVELS[this.level];
    }
    
    /**
     * Core log method
     */
    log(level, message, meta = {}) {
        if (!this.shouldLog(level)) {
            return;
        }
        
        // Merge context with meta
        const fullMeta = { ...this.context, ...meta };
        
        // Format based on setting
        const formatted = this.format === 'json'
            ? formatJson(level, message, fullMeta)
            : formatPretty(level, message, fullMeta);
        
        // Output to console
        if (level === 'error') {
            console.error(formatted);
        } else {
            console.log(formatted);
        }
        
        // Output to file (always JSON for parseability)
        if (this.fileWriter) {
            const jsonLine = formatJson(level, message, fullMeta);
            this.fileWriter.write(jsonLine);
        }
    }
    
    /**
     * Level-specific methods
     */
    error(message, meta) {
        this.log('error', message, meta);
    }
    
    warn(message, meta) {
        this.log('warn', message, meta);
    }
    
    info(message, meta) {
        this.log('info', message, meta);
    }
    
    debug(message, meta) {
        this.log('debug', message, meta);
    }
    
    /**
     * Create child logger with additional context
     */
    child(context) {
        return new Logger({
            level: this.level,
            format: this.format,
            logDir: this.fileWriter?.logDir,
            context: { ...this.context, ...context },
        });
    }
    
    /**
     * Create request-scoped logger
     */
    forRequest(req) {
        return this.child({
            requestId: req.id || generateRequestId(),
            method: req.method,
            path: req.url,
            ip: req.ip || req.connection?.remoteAddress,
        });
    }
    
    /**
     * Close file writer
     */
    close() {
        if (this.fileWriter) {
            this.fileWriter.close();
        }
    }
}

/**
 * Create default logger instance
 */
const createDefaultLogger = () => {
    const config = getConfig();
    
    let logDir = null;
    if (config.logging.dir) {
        logDir = config.logging.dir;
    } else if (config.isProduction) {
        logDir = paths.logs();
    }
    
    return new Logger({
        level: config.logging.level,
        format: config.logging.format,
        logDir,
    });
};

// Export singleton and class
const defaultLogger = createDefaultLogger();

module.exports = defaultLogger;
module.exports.Logger = Logger;
module.exports.generateRequestId = generateRequestId;
