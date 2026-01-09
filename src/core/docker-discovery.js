/**
 * Docker Discovery Module
 * 
 * Auto-discovers running Docker containers and their exposed ports.
 * Uses Docker socket to query container information.
 * 
 * Usage:
 *   const DockerDiscovery = require('./docker-discovery');
 *   const discovery = new DockerDiscovery();
 *   const upstreams = await discovery.discoverUpstreams();
 */

const http = require('http');
const logger = require('../logging');

class DockerDiscovery {
    constructor(options = {}) {
        this.socketPath = options.socketPath || '/var/run/docker.sock';
        this.refreshInterval = options.refreshInterval || 30000; // 30 seconds
        this.selfContainerName = options.selfContainerName || 'ddos-guardian';
        this.upstreams = new Map(); // port -> upstream info
        this.refreshTimer = null;
    }

    /**
     * Query Docker API via socket
     */
    _dockerRequest(path) {
        return new Promise((resolve, reject) => {
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
                        reject(new Error('Failed to parse Docker response'));
                    }
                });
            });

            req.on('error', (e) => {
                reject(new Error(`Docker socket error: ${e.message}`));
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
        const containers = await this.getContainers();
        const upstreams = new Map();

        for (const container of containers) {
            // Skip self
            const names = container.Names || [];
            const isSelf = names.some(n => n.includes(this.selfContainerName));
            if (isSelf) continue;

            // Get container name (remove leading /)
            const name = names[0] ? names[0].replace(/^\//, '') : container.Id.slice(0, 12);

            // Get network info
            const networks = container.NetworkSettings?.Networks || {};
            let ip = null;

            // Find IP address (prefer bridge network)
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

                    if (protocol !== 'tcp') continue;

                    // Create upstream entry
                    const upstream = {
                        container: name,
                        host: name, // Use container name as hostname
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
        }

        this.upstreams = upstreams;
        
        logger.info('Docker discovery complete', {
            containers: containers.length - 1, // Exclude self
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
        for (const upstreams of this.upstreams.values()) {
            all.push(...upstreams);
        }
        return all;
    }

    /**
     * Start auto-refresh
     */
    startAutoRefresh(callback) {
        this.stopAutoRefresh();
        
        this.refreshTimer = setInterval(async () => {
            await this.discoverUpstreams();
            if (callback) callback(this.upstreams);
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
        }
    }

    /**
     * Get discovery stats
     */
    getStats() {
        const ports = Array.from(this.upstreams.keys());
        const containers = new Set();
        
        for (const upstreams of this.upstreams.values()) {
            for (const u of upstreams) {
                containers.add(u.container);
            }
        }

        return {
            discoveredPorts: ports,
            discoveredContainers: Array.from(containers),
            totalUpstreams: this.getAllUpstreams().length,
        };
    }
}

module.exports = DockerDiscovery;
