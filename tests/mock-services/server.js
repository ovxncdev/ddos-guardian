/**
 * Mock Service
 * 
 * Simple HTTP server that simulates your real services.
 * Used for testing ddos-guardian in Docker.
 */

const http = require('http');

const SERVICE_NAME = process.env.SERVICE_NAME || 'mock-service';
const PORT = process.env.PORT || 3000;

const server = http.createServer((req, res) => {
    const path = req.url.split('?')[0];
    
    res.setHeader('Content-Type', 'application/json');
    
    // Health check
    if (path === '/health') {
        res.end(JSON.stringify({
            status: 'healthy',
            service: SERVICE_NAME,
        }));
        return;
    }
    
    // Simulate some delay (realistic)
    const delay = Math.floor(Math.random() * 50) + 10;
    
    setTimeout(() => {
        res.end(JSON.stringify({
            service: SERVICE_NAME,
            path: path,
            method: req.method,
            timestamp: new Date().toISOString(),
            headers: {
                'x-request-id': req.headers['x-request-id'],
                'x-forwarded-for': req.headers['x-forwarded-for'],
            },
            message: `Hello from ${SERVICE_NAME}!`,
        }));
    }, delay);
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`${SERVICE_NAME} listening on port ${PORT}`);
});
