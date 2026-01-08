/**
 * Path Resolver
 * 
 * Consistent path resolution across Docker and non-Docker.
 * SINGLE SOURCE OF TRUTH for all paths.
 * 
 * Usage:
 *   const paths = require('./utils/paths');
 *   const logFile = paths.logs('app.log');
 */

const path = require('path');
const fs = require('fs');
const environment = require('./environment');

/**
 * Find project root directory
 */
const findProjectRoot = () => {
    let dir = __dirname;
    let depth = 0;
    const maxDepth = 10;
    
    while (dir !== '/' && depth < maxDepth) {
        if (fs.existsSync(path.join(dir, 'package.json'))) {
            return dir;
        }
        dir = path.dirname(dir);
        depth++;
    }
    
    return process.cwd();
};

const PROJECT_ROOT = findProjectRoot();

/**
 * Default directories
 */
const DEFAULT_DIRS = {
    src: 'src',
    config: 'src/config',
    logs: 'logs',
    data: 'data',
    temp: 'temp',
    tests: 'tests',
};

/**
 * Docker-specific paths
 */
const DOCKER_PATHS = {
    logs: process.env.LOG_DIR || '/var/log/ddos-guardian',
    data: process.env.DATA_DIR || '/var/lib/ddos-guardian',
    temp: '/tmp/ddos-guardian',
};

/**
 * Get base path for a directory type
 */
const getBasePath = (type) => {
    // Check env override first
    const envOverrides = {
        logs: process.env.LOG_DIR,
        data: process.env.DATA_DIR,
        temp: process.env.TEMP_DIR,
    };
    
    if (envOverrides[type]) {
        return envOverrides[type];
    }
    
    // Use Docker paths if in Docker
    if (environment.isDocker && DOCKER_PATHS[type]) {
        return DOCKER_PATHS[type];
    }
    
    // Default to project-relative
    return path.join(PROJECT_ROOT, DEFAULT_DIRS[type] || type);
};

/**
 * Ensure directory exists
 */
const ensureDir = (dirPath) => {
    try {
        if (!fs.existsSync(dirPath)) {
            fs.mkdirSync(dirPath, { recursive: true, mode: 0o755 });
        }
        return dirPath;
    } catch (err) {
        console.error(`[paths] Failed to create directory ${dirPath}:`, err.message);
        throw err;
    }
};

/**
 * Check if path is writable
 */
const isWritable = (testPath) => {
    try {
        const testFile = path.join(testPath, `.write-test-${Date.now()}`);
        fs.writeFileSync(testFile, '');
        fs.unlinkSync(testFile);
        return true;
    } catch {
        return false;
    }
};

/**
 * Path resolver object
 */
const paths = {
    root: PROJECT_ROOT,
    
    /**
     * Resolve path relative to project root
     */
    resolve(...segments) {
        return path.join(PROJECT_ROOT, ...segments);
    },
    
    /**
     * Get src directory
     */
    src(...segments) {
        return path.join(PROJECT_ROOT, DEFAULT_DIRS.src, ...segments);
    },
    
    /**
     * Get config directory
     */
    config(...segments) {
        return path.join(PROJECT_ROOT, DEFAULT_DIRS.config, ...segments);
    },
    
    /**
     * Get logs directory (creates if needed)
     */
    logs(...segments) {
        const base = getBasePath('logs');
        ensureDir(base);
        return path.join(base, ...segments);
    },
    
    /**
     * Get data directory (creates if needed)
     */
    data(...segments) {
        const base = getBasePath('data');
        ensureDir(base);
        return path.join(base, ...segments);
    },
    
    /**
     * Get temp directory (creates if needed)
     */
    temp(...segments) {
        const base = getBasePath('temp');
        ensureDir(base);
        return path.join(base, ...segments);
    },
    
    /**
     * Get tests directory
     */
    tests(...segments) {
        return path.join(PROJECT_ROOT, DEFAULT_DIRS.tests, ...segments);
    },
    
    utils: {
        ensureDir,
        isWritable,
        findProjectRoot,
    },
    
    /**
     * Get all paths
     */
    getAll() {
        return {
            root: this.root,
            src: this.src(),
            config: this.config(),
            logs: getBasePath('logs'),
            data: getBasePath('data'),
            temp: getBasePath('temp'),
            tests: this.tests(),
            isDocker: environment.isDocker,
        };
    },
    
    /**
     * Validate all paths are accessible
     */
    validate() {
        const errors = [];
        const dirsToCheck = ['logs', 'data', 'temp'];
        
        for (const dir of dirsToCheck) {
            try {
                const dirPath = this[dir]();
                if (!isWritable(dirPath)) {
                    errors.push(`${dir} directory is not writable: ${dirPath}`);
                }
            } catch (err) {
                errors.push(`${dir} directory error: ${err.message}`);
            }
        }
        
        return {
            valid: errors.length === 0,
            errors,
        };
    },
};

module.exports = paths;
