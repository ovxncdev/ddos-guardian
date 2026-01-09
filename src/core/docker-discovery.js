/**
 * Docker Discovery Module
 * 
 * Auto-discovers running Docker containers and their exposed ports.
 * Automatically connects containers to guardian's network.
 * Uses Docker socket to query container information.
 * Works in both Docker and non-Docker environments.
 * 
 * Features:
 * - Auto-detect new containers every 30s (configurable)
 * - Auto-connect containers to guardian's network
 * - Auto-protect any new service added in the future
 * 
 * Usage:
 *   const DockerDiscovery = require('./docker-discovery');
 *   const discovery = new DockerDiscovery();
 *   await discovery.discoverUpstreams();
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
        this.networkName = options.networkName || null; // Will be auto-detected
        
        this.upstreams = new Map(); // port -> upstream info
        this.connectedContainers = new Set(); // Track containers we've connected
        this.refreshTimer = null;
        this.isAvailable = false;
        this.selfContainerId = null;
        
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
            fs.accessSync(this.socketPath, fs.constants.R_OK | fs.constants.W_OK);
            this.isAvailable = true;
            logger.debug('Docker socket available (read/write)', { path: this.socketPath });
        } catch (e) {
            // Try read-only
            try {
                fs.accessSync(this.socketPath, fs.constants.R_OK);
                this.isAvailable = true;
                logger.debug('Docker socket available (read-only)', { path: this.socketPath });
            } catch (e2) {
                this.isAvailable = false;
                logger.debug('Docker socket not accessible', { 
                    path: this.socketPath, 
                    error: e.message 
                });
            }
        }
    }

    /**
     * Query Docker API via socket (GET request)
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
                if (e.code === 'ENOENT') {
                    reject(new Error(`Docker socket not found at ${this.socketPath}`));
                } else if (e.code === 'EACCES') {
                    reject(new Error(`Permission denied accessing Docker socket`));
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
     * POST request to Docker API
     */
    _dockerPost(path, body = null) {
        return new Promise((resolve, reject) => {
            if (!this.isAvailable) {
                reject(new Error('Docker socket not available'));
                return;
            }

            const postData = body ? JSON.stringify(body) : '';
            
            const options = {
                socketPath: this.socketPath,
                path: path,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(postData),
                },
            };

            const req = http.request(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    if (res.statusCode >= 200 && res.statusCode < 300) {
                        resolve({ success: true, statusCode: res.statusCode, data });
                    } else if (res.statusCode === 304) {
                        // Already connected - not an error
                        resolve({ success: true, statusCode: res.statusCode, alreadyConnected: true });
                    } else {
                        reject(new Error(`Docker API error: ${res.statusCode} - ${data}`));
                    }
                });
            });

            req.on('error', (e) => {
                reject(new Error(`Docker POST error: ${e.message}`));
            });

            req.setTimeout(5000, () => {
                req.destroy();
                reject(new Error('Docker POST timeout'));
            });

            if (postData) {
                req.write(postData);
            }
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
     * Get guardian's own container info and network
     */
    async _getSelfInfo() {
        if (this.selfContainerId && this.networkName) {
            return; // Already have info
        }

        try {
            const containers = await this.getContainers();
            
            for (const container of containers) {
                const names = container.Names || [];
                const isSelf = names.some(n => 
                    n.toLowerCase().includes(this.selfContainerName.toLowerCase())
                );
                
                if (isSelf) {
                    this.selfContainerId = container.Id;
                    
                    // Get network name
                    const networks = container.NetworkSettings?.Networks || {};
                    const networkNames = Object.keys(networks);
                    
                    // Prefer network with 'guardian' in name, otherwise use first
                    this.networkName = networkNames.find(n => n.includes('guardian')) 
                        || networkNames[0] 
                        || 'ddos-guardian_default';
                    
                    logger.debug('Guardian self-info detected', {
                        containerId: this.selfContainerId.slice(0, 12),
                        network: this.networkName,
                    });
                    return;
                }
            }
        } catch (e) {
            logger.error('Failed to get self info', { error: e.message });
        }
    }

    /**
     * Connect a container to guardian's network
     */
    async connectContainer(containerId, containerName) {
        if (!this.networkName) {
            await this._getSelfInfo();
        }

        if (!this.networkName) {
            logger.warn('Cannot connect container - network not found');
            return false;
        }

        // Skip if already connected
        if (this.connectedContainers.has(containerId)) {
            return true;
        }

        try {
            const endpoint = `/networks/${this.networkName}/connect`;
            await this._dockerPost(endpoint, { Container: containerId });
            
            this.connectedContainers.add(containerId);
            logger.info('Container connected to guardian network', {
                container: containerName,
                network: this.networkName,
            });
            return true;
        } catch (e) {
            // Check if already connected (409 or message contains "already")
            if (e.message.includes('already') || e.message.includes('409')) {
                this.connectedContainers.add(containerId);
                logger.debug('Container already connected', { container: containerName });
                return true;
            }
            
            logger.error('Failed to connect container', {
                container: containerName,
                network: this.networkName,
                error: e.message,
            });
            return false;
        }
    }

    /**
     * Check if container is on guardian's network
     */
    isContainerConnected(container) {
        const networks = container.NetworkSettings?.Networks || {};
        return Object.keys(networks).some(n => 
            n === this.networkName || n.includes('guardian')
        );
    }

    /**
     * Discover all upstreams from running containers
     */
    async discoverUpstreams() {
        if (!this.isAvailable) {
            logger.debug('Docker discovery skipped - socket not available');
            return new Map();
        }

        // Get guardian's network info first
        await this._getSelfInfo();

        let containers;
        try {
            containers = await this.getContainers();
        } catch (e) {
            logger.error('Container discovery failed', { error: e.message });
            return this.upstreams;
        }

        const upstreams = new Map();
        let newContainersFound = 0;

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
                const containerId = container.Id;

                // Auto-connect container to guardian's network
                const wasConnected = this.connectedContainers.has(containerId);
                const connected = await this.connectContainer(containerId, name);
                
                if (!connected) {
                    logger.warn('Skipping container - could not connect', { container: name });
                    continue;
                }

                if (!wasConnected) {
                    newContainersFound++;
                }

                // Get exposed/published ports
                const ports = container.Ports || [];
                
                for (const port of ports) {
                    // Get private port (container's internal port)
                    const privatePort = port.PrivatePort;
                    const publicPort = port.PublicPort || privatePort;
                    const protocol = port.Type || 'tcp';

                    // Skip non-TCP
                    if (protocol !== 'tcp') continue;

                    // Skip guardian's own ports
                    if (privatePort === 80 || privatePort === 443 || privatePort === 8443) {
                        // Check if this is actually guardian
                        if (isSelf) continue;
                    }

                    // Create upstream entry using container name (Docker DNS)
                    const upstream = {
                        container: name,
                        containerId: containerId.slice(0, 12),
                        host: name,
                        port: privatePort,
                        publicPort: publicPort,
                        url: `http://${name}:${privatePort}`,
                    };

                    // Map by public port for routing
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
            } catch (e) {
                logger.warn('Error processing container', { 
                    id: container.Id?.slice(0, 12), 
                    error: e.message 
                });
            }
        }

        this.upstreams = upstreams;
        
        const containerCount = containers.length - 1; // Exclude self
        
        if (newContainersFound > 0) {
            logger.info('New containers discovered and connected', {
                newContainers: newContainersFound,
                totalContainers: containerCount > 0 ? containerCount : 0,
                totalUpstreams: this.getAllUpstreams().length,
                ports: Array.from(upstreams.keys()),
            });
        } else {
            logger.debug('Discovery scan complete', {
                containers: containerCount > 0 ? containerCount : 0,
                upstreams: upstreams.size,
            });
        }

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
        
        // Initial scan
        this.discoverUpstreams().then(() => {
            if (callback) callback(this.upstreams);
        });
        
        // Periodic scan
        this.refreshTimer = setInterval(async () => {
            try {
                const oldCount = this.getAllUpstreams().length;
                await this.discoverUpstreams();
                const newCount = this.getAllUpstreams().length;
                
                // Only callback if something changed
                if (oldCount !== newCount || callback) {
                    if (callback) callback(this.upstreams);
                }
            } catch (e) {
                logger.error('Auto-refresh error', { error: e.message });
            }
        }, this.refreshInterval);

        logger.info('Docker auto-refresh started', {
            interval: this.refreshInterval,
            network: this.networkName,
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
            networkName: this.networkName,
            connectedContainers: this.connectedContainers.size,
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
