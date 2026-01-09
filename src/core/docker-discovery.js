/**
 * Docker Discovery Module
 * 
 * Auto-discovers running Docker containers and their exposed ports.
 * Uses Docker socket to query container information.
 * Works in both Docker and non-Docker environments.
 * 
 * Usage:
 *   const DockerDiscovery = require('./docker-discovery');
 *   const discovery = new DockerDiscovery();
 *   const upstreams = await discovery.discoverUpstreams();
 */

const http = require('http');
const fs = require('fs');
const logger = require('../logging');
const config = require('../config');

class DockerDiscovery {
    constructor(options = {}) {
        // Use config as single source of truth, with option overrides
        this.socketPath = options.socketPath || config.discovery.socketPath;
        this.refreshInterval = options.refreshInterval || config.discovery.interval;
        this.selfContainerName = options.selfContainerName || 'ddos-guardian';
        
        this.upstreams = new Map(); // port -> upstream info
        this.refreshTimer = null;
        this.isAvailable = false;
        
        // Check if Docker is available
        this._checkAvailability();
    }

    /**
     * Check if Docker socket is available
     */
    _checkAvailability() {
        if (!this.socketPath) {
            logger.debug('Docker socket path not configured');
            this.isAvailable = false;
            return;
        }
        
        try {
            fs.accessSync(this.socketPath, fs.constants.R_OK);
            this.isAvailable = true;
            logger.debug('Docker socket available', { path: this.socketPath });
        } catch (e) {
            this.isAvailable = false;
            logger.debug('Docker socket not accessible', { 
                path: this.socketPath, 
                error: e.message 
            });
        }
    }

    /**
     * Query Docker API via socket
     */
    _dockerRequest(path) {
        return new Promise((resolve, reject) => {
            if (!this.isAvailable) {
                reject(new Error('Docker socket not available'));
                return;
            }

            const options = {
                socketPath: this.socketPath,
                path: path,
                method: 'GET',
            };

            const req = http.request(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        resolve(JSON.parse(data));
                    } catch (e) {
                        reject(new Error(`Failed to parse Docker response: ${e.message}`));
                    }
                });
            });

            req.on('error', (e) => {
                // More specific error messages
                if (e.code === 'ENOENT') {
                    reject(new Error(`Docker socket not found at ${this.socketPath}`));
                } else if (e.code === 'EACCES') {
                    reject(new Error(`Permission denied accessing Docker socket at ${this.socketPath}`));
                } else if (e.code === 'ECONNREFUSED') {
                    reject(new Error('Docker daemon not running'));
                } else {
                    reject(new Error(`Docker socket error: ${e.message}`));
                }
            });

            req.setTimeout(5000, () => {
                req.destroy();
                reject(new Error('Docker request timeout'));
            });

            req.end();
        });
    }

    /**
     * Get all running containers
     */
    async getContainers() {
        try {
            const containers = await this._dockerRequest('/containers/json');
            return containers.filter(c => c.State === 'running');
        } catch (e) {
            logger.error('Failed to get containers', { error: e.message });
            return [];
        }
    }

    /**
     * Discover all upstreams from running containers
     */
    async discoverUpstreams() {
        if (!this.isAvailable) {
            logger.debug('Docker discovery skipped - socket not available');
            return new Map();
        }

        let containers;
        try {
            containers = await this.getContainers();
        } catch (e) {
            logger.error('Container discovery failed', { error: e.message });
            return this.upstreams; // Return existing upstreams
        }

        const upstreams = new Map();

        for (const container of containers) {
            try {
                // Skip self
                const names = container.Names || [];
                const isSelf = names.some(n => 
                    n.toLowerCase().includes(this.selfContainerName.toLowerCase())
                );
                if (isSelf) continue;

                // Get container name (remove leading /)
                const name = names[0] ? names[0].replace(/^\//, '') : container.Id.slice(0, 12);

                // Get network info - find any usable IP
                const networks = container.NetworkSettings?.Networks || {};
                let ip = null;

                for (const [netName, netInfo] of Object.entries(networks)) {
                    if (netInfo.IPAddress) {
                        ip = netInfo.IPAddress;
                        break;
                    }
                }

                // Get exposed ports
                const ports = container.Ports || [];
                
                for (const port of ports) {
                    // We care about ports that were published (have PublicPort)
                    if (port.PublicPort && port.PrivatePort) {
                        const publicPort = port.PublicPort;
                        const privatePort = port.PrivatePort;
                        const protocol = port.Type || 'tcp';

                        // Skip non-TCP ports
                        if (protocol !== 'tcp') continue;

                        // Create upstream entry - use container name for Docker DNS
                        const upstream = {
                            container: name,
                            host: name,
                            port: privatePort,
                            publicPort: publicPort,
                            ip: ip,
                            url: `http://${name}:${privatePort}`,
                        };

                        // Map by public port
                        if (!upstreams.has(publicPort)) {
                            upstreams.set(publicPort, []);
                        }
                        upstreams.get(publicPort).push(upstream);

                        logger.debug('Discovered upstream', {
                            container: name,
                            publicPort,
                            privatePort,
                            url: upstream.url,
                        });
                    }
                }
            } catch (e) {
                logger.warn('Error processing container', { 
                    id: container.Id?.slice(0, 12), 
                    error: e.message 
                });
            }
        }

        this.upstreams = upstreams;
        
        const containerCount = containers.length - 1; // Exclude self
        logger.info('Docker discovery complete', {
            containers: containerCount > 0 ? containerCount : 0,
            upstreams: upstreams.size,
            ports: Array.from(upstreams.keys()),
        });

        return upstreams;
    }

    /**
     * Get upstream for a specific port
     */
    getUpstreamForPort(port) {
        return this.upstreams.get(port) || [];
    }

    /**
     * Get all discovered upstreams as flat array
     */
    getAllUpstreams() {
        const all = [];
        for (const upstreamList of this.upstreams.values()) {
            all.push(...upstreamList);
        }
        return all;
    }

    /**
     * Get unique upstream URLs
     */
    getUpstreamUrls() {
        const urls = new Set();
        for (const upstreamList of this.upstreams.values()) {
            for (const upstream of upstreamList) {
                urls.add(upstream.url);
            }
        }
        return Array.from(urls);
    }

    /**
     * Start auto-refresh
     */
    startAutoRefresh(callback) {
        if (!this.isAvailable) {
            logger.debug('Auto-refresh not started - Docker not available');
            return;
        }

        this.stopAutoRefresh();
        
        this.refreshTimer = setInterval(async () => {
            try {
                await this.discoverUpstreams();
                if (callback) callback(this.upstreams);
            } catch (e) {
                logger.error('Auto-refresh error', { error: e.message });
            }
        }, this.refreshInterval);

        logger.info('Docker auto-refresh started', {
            interval: this.refreshInterval,
        });
    }

    /**
     * Stop auto-refresh
     */
    stopAutoRefresh() {
        if (this.refreshTimer) {
            clearInterval(this.refreshTimer);
            this.refreshTimer = null;
            logger.debug('Docker auto-refresh stopped');
        }
    }

    /**
     * Get discovery stats
     */
    getStats() {
        const ports = Array.from(this.upstreams.keys());
        const containers = new Set();
        
        for (const upstreamList of this.upstreams.values()) {
            for (const u of upstreamList) {
                containers.add(u.container);
            }
        }

        return {
            available: this.isAvailable,
            socketPath: this.socketPath,
            discoveredPorts: ports,
            discoveredContainers: Array.from(containers),
            totalUpstreams: this.getAllUpstreams().length,
            refreshInterval: this.refreshInterval,
        };
    }

    /**
     * Cleanup
     */
    destroy() {
        this.stopAutoRefresh();
    }
}

module.exports = DockerDiscovery;
