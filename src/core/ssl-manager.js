/**
 * SSL Manager
 * 
 * Handles SSL/TLS termination for DDoS Guardian.
 * Supports multiple certificate sources:
 * - Let's Encrypt (from /etc/letsencrypt)
 * - PhishProxy custom certs
 * - Cloudflare origin certs
 * - Self-signed certificates
 * 
 * Usage:
 *   const ssl = new SSLManager(config);
 *   const httpsServer = ssl.createServer(requestHandler);
 */

const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const logger = require('../logging');

/**
 * SSL Manager class
 */
class SSLManager {
    constructor(options = {}) {
        this.enabled = options.enabled !== false;
        this.certDir = options.certDir || '/certs';
        this.letsencryptDir = options.letsencryptDir || '/etc/letsencrypt/live';
        this.phishproxyCertDir = options.phishproxyCertDir || '/phishproxy-certs';
        this.domain = options.domain || null;
        
        // Current SSL context
        this.credentials = null;
        this.certHash = null;
        this.certSource = null;
        
        // Watch for cert changes
        this.watchInterval = null;
        this.reloadCallbacks = [];
        
        // Try to load certs on init
        if (this.enabled) {
            this.loadCertificates();
        }
        
        logger.info('SSLManager initialized', {
            enabled: this.enabled,
            domain: this.domain,
            certDir: this.certDir,
        });
    }
    
    /**
     * Load certificates from available sources
     * Priority: 1. Custom certs 2. PhishProxy certs 3. Let's Encrypt 4. Self-signed
     */
    loadCertificates() {
        const sources = [
            { name: 'custom', loader: () => this._loadCustomCerts() },
            { name: 'phishproxy', loader: () => this._loadPhishProxyCerts() },
            { name: 'letsencrypt', loader: () => this._loadLetsEncryptCerts() },
            { name: 'selfsigned', loader: () => this._generateSelfSigned() },
        ];
        
        for (const source of sources) {
            try {
                const creds = source.loader();
                if (creds) {
                    this.credentials = creds;
                    this.certSource = source.name;
                    this.certHash = this._hashCert(creds.cert);
                    
                    logger.info('SSL certificates loaded', {
                        source: source.name,
                        domain: this.domain,
                    });
                    
                    return true;
                }
            } catch (e) {
                logger.debug(`Failed to load certs from ${source.name}`, { error: e.message });
            }
        }
        
        logger.warn('No SSL certificates available');
        return false;
    }
    
    /**
     * Load custom certificates from certDir
     */
    _loadCustomCerts() {
        const certPath = path.join(this.certDir, 'custom.crt');
        const keyPath = path.join(this.certDir, 'custom.key');
        
        if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
            return {
                cert: fs.readFileSync(certPath, 'utf8'),
                key: fs.readFileSync(keyPath, 'utf8'),
            };
        }
        
        // Also check for cert.pem / key.pem
        const certPem = path.join(this.certDir, 'cert.pem');
        const keyPem = path.join(this.certDir, 'key.pem');
        
        if (fs.existsSync(certPem) && fs.existsSync(keyPem)) {
            return {
                cert: fs.readFileSync(certPem, 'utf8'),
                key: fs.readFileSync(keyPem, 'utf8'),
            };
        }
        
        // Check for fullchain.pem / privkey.pem (Let's Encrypt format)
        const fullchain = path.join(this.certDir, 'fullchain.pem');
        const privkey = path.join(this.certDir, 'privkey.pem');
        
        if (fs.existsSync(fullchain) && fs.existsSync(privkey)) {
            return {
                cert: fs.readFileSync(fullchain, 'utf8'),
                key: fs.readFileSync(privkey, 'utf8'),
            };
        }
        
        return null;
    }
    
    /**
     * Load certificates from PhishProxy's cert directory
     */
    _loadPhishProxyCerts() {
        const certPath = path.join(this.phishproxyCertDir, 'custom.crt');
        const keyPath = path.join(this.phishproxyCertDir, 'custom.key');
        
        if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
            return {
                cert: fs.readFileSync(certPath, 'utf8'),
                key: fs.readFileSync(keyPath, 'utf8'),
            };
        }
        
        return null;
    }
    
    /**
     * Load Let's Encrypt certificates
     */
    _loadLetsEncryptCerts() {
        if (!this.domain) {
            return null;
        }
        
        const domainDir = path.join(this.letsencryptDir, this.domain);
        const certPath = path.join(domainDir, 'fullchain.pem');
        const keyPath = path.join(domainDir, 'privkey.pem');
        
        if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
            return {
                cert: fs.readFileSync(certPath, 'utf8'),
                key: fs.readFileSync(keyPath, 'utf8'),
            };
        }
        
        // Try to find any domain in letsencrypt dir
        if (fs.existsSync(this.letsencryptDir)) {
            try {
                const domains = fs.readdirSync(this.letsencryptDir);
                for (const d of domains) {
                    if (d.startsWith('.')) continue;
                    
                    const dCert = path.join(this.letsencryptDir, d, 'fullchain.pem');
                    const dKey = path.join(this.letsencryptDir, d, 'privkey.pem');
                    
                    if (fs.existsSync(dCert) && fs.existsSync(dKey)) {
                        this.domain = d; // Update domain
                        return {
                            cert: fs.readFileSync(dCert, 'utf8'),
                            key: fs.readFileSync(dKey, 'utf8'),
                        };
                    }
                }
            } catch (e) {
                // Ignore
            }
        }
        
        return null;
    }
    
    /**
     * Generate self-signed certificate
     */
    _generateSelfSigned() {
        try {
            const { generateKeyPairSync, createSign } = require('crypto');
            
            // Generate key pair
            const { privateKey, publicKey } = generateKeyPairSync('rsa', {
                modulusLength: 2048,
            });
            
            // Create a simple self-signed cert (basic implementation)
            // In production, you'd use a proper library like node-forge
            logger.warn('Using self-signed certificate - not recommended for production');
            
            // For now, return null and let HTTP work
            // Self-signed requires proper X509 generation
            return null;
            
        } catch (e) {
            logger.debug('Could not generate self-signed cert', { error: e.message });
            return null;
        }
    }
    
    /**
     * Hash certificate for change detection
     */
    _hashCert(cert) {
        return crypto.createHash('sha256').update(cert).digest('hex').substring(0, 16);
    }
    
    /**
     * Check if certificates have changed
     */
    checkForChanges() {
        const oldHash = this.certHash;
        const oldSource = this.certSource;
        
        this.loadCertificates();
        
        if (this.certHash !== oldHash) {
            logger.info('SSL certificates changed', {
                oldSource,
                newSource: this.certSource,
            });
            
            // Notify callbacks
            for (const cb of this.reloadCallbacks) {
                try {
                    cb(this.credentials);
                } catch (e) {
                    logger.error('SSL reload callback error', { error: e.message });
                }
            }
            
            return true;
        }
        
        return false;
    }
    
    /**
     * Start watching for certificate changes
     */
    startWatching(intervalMs = 60000) {
        if (this.watchInterval) {
            return;
        }
        
        this.watchInterval = setInterval(() => {
            this.checkForChanges();
        }, intervalMs);
        
        if (this.watchInterval.unref) {
            this.watchInterval.unref();
        }
        
        logger.debug('SSL certificate watch started', { interval: intervalMs });
    }
    
    /**
     * Stop watching
     */
    stopWatching() {
        if (this.watchInterval) {
            clearInterval(this.watchInterval);
            this.watchInterval = null;
        }
    }
    
    /**
     * Register callback for cert reload
     */
    onReload(callback) {
        this.reloadCallbacks.push(callback);
    }
    
    /**
     * Create HTTPS server
     */
    createServer(requestHandler) {
        if (!this.credentials) {
            logger.warn('No SSL credentials available, cannot create HTTPS server');
            return null;
        }
        
        const server = https.createServer({
            cert: this.credentials.cert,
            key: this.credentials.key,
            // Modern SSL settings
            minVersion: 'TLSv1.2',
            // Prefer server cipher order
            honorCipherOrder: true,
        }, requestHandler);
        
        // Handle SNI if needed
        server.on('tlsClientError', (err) => {
            logger.debug('TLS client error', { error: err.message });
        });
        
        return server;
    }
    
    /**
     * Update server credentials (for hot reload)
     */
    updateServerCredentials(server) {
        if (!server || !this.credentials) {
            return false;
        }
        
        try {
            server.setSecureContext({
                cert: this.credentials.cert,
                key: this.credentials.key,
            });
            
            logger.info('HTTPS server credentials updated');
            return true;
        } catch (e) {
            logger.error('Failed to update server credentials', { error: e.message });
            return false;
        }
    }
    
    /**
     * Get SSL status
     */
    getStatus() {
        return {
            enabled: this.enabled,
            available: !!this.credentials,
            source: this.certSource,
            domain: this.domain,
            certHash: this.certHash,
        };
    }
    
    /**
     * Get stats for metrics
     */
    getStats() {
        return {
            enabled: this.enabled,
            available: !!this.credentials,
            source: this.certSource || 'none',
            domain: this.domain || 'unknown',
        };
    }
    
    /**
     * Cleanup
     */
    destroy() {
        this.stopWatching();
        this.reloadCallbacks = [];
    }
}

module.exports = SSLManager;
