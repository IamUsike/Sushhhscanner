"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.websocketHandler = websocketHandler;
exports.getWebSocketManager = getWebSocketManager;
const ws_1 = require("ws");
const uuid_1 = require("uuid");
const logger_1 = require("@utils/logger");
class WebSocketManager {
    constructor(wss) {
        this.wss = wss;
        this.clients = new Map();
        this.heartbeatInterval = null;
        this.setupHeartbeat();
    }
    setupHeartbeat() {
        const interval = parseInt(process.env.WS_HEARTBEAT_INTERVAL || '30000');
        this.heartbeatInterval = setInterval(() => {
            const now = new Date();
            this.clients.forEach((client, clientId) => {
                const timeSinceHeartbeat = now.getTime() - client.lastHeartbeat.getTime();
                if (timeSinceHeartbeat > interval * 2) {
                    // Client hasn't responded to heartbeat, disconnect
                    logger_1.logger.warn(`WebSocket client ${clientId} heartbeat timeout, disconnecting`);
                    this.removeClient(clientId);
                    return;
                }
                if (client.ws.readyState === ws_1.WebSocket.OPEN) {
                    this.sendMessage(clientId, {
                        type: 'heartbeat',
                        timestamp: now,
                    });
                }
            });
        }, interval);
    }
    addClient(ws) {
        const clientId = (0, uuid_1.v4)();
        const client = {
            id: clientId,
            ws,
            subscribedScans: new Set(),
            lastHeartbeat: new Date(),
        };
        this.clients.set(clientId, client);
        logger_1.logger.info(`WebSocket client connected: ${clientId}`);
        return clientId;
    }
    removeClient(clientId) {
        const client = this.clients.get(clientId);
        if (client) {
            if (client.ws.readyState === ws_1.WebSocket.OPEN) {
                client.ws.close();
            }
            this.clients.delete(clientId);
            logger_1.logger.info(`WebSocket client disconnected: ${clientId}`);
        }
    }
    sendMessage(clientId, message) {
        const client = this.clients.get(clientId);
        if (client && client.ws.readyState === ws_1.WebSocket.OPEN) {
            try {
                client.ws.send(JSON.stringify(message));
            }
            catch (error) {
                logger_1.logger.error(`Failed to send WebSocket message to ${clientId}:`, error);
                this.removeClient(clientId);
            }
        }
    }
    broadcastToScanSubscribers(scanId, message) {
        let subscriberCount = 0;
        this.clients.forEach((client, clientId) => {
            if (client.subscribedScans.has(scanId)) {
                this.sendMessage(clientId, { ...message, scanId });
                subscriberCount++;
            }
        });
        if (subscriberCount > 0) {
            logger_1.logger.debug(`Broadcasted scan update to ${subscriberCount} subscribers`, {
                scanId,
                messageType: message.type,
            });
        }
    }
    notifyVulnerabilityFound(scanId, vulnerability) {
        this.broadcastToScanSubscribers(scanId, {
            type: 'vulnerability_found',
            data: { vulnerability },
            timestamp: new Date(),
        });
    }
    notifyScanProgress(scanId, progress, step, details) {
        this.broadcastToScanSubscribers(scanId, {
            type: 'progress',
            data: { progress, step, details },
            timestamp: new Date(),
        });
    }
    notifyScanCompleted(scanId, summary) {
        this.broadcastToScanSubscribers(scanId, {
            type: 'scan_completed',
            data: { summary },
            timestamp: new Date(),
        });
    }
    notifyError(scanId, error) {
        this.broadcastToScanSubscribers(scanId, {
            type: 'error',
            data: { error },
            timestamp: new Date(),
        });
    }
    handleMessage(clientId, message) {
        try {
            const data = JSON.parse(message);
            const client = this.clients.get(clientId);
            if (!client)
                return;
            switch (data.type) {
                case 'heartbeat':
                    client.lastHeartbeat = new Date();
                    break;
                case 'subscribe_scan':
                    if (data.scanId) {
                        client.subscribedScans.add(data.scanId);
                        logger_1.logger.debug(`Client ${clientId} subscribed to scan ${data.scanId}`);
                        this.sendMessage(clientId, {
                            type: 'progress',
                            scanId: data.scanId,
                            data: { message: 'Subscribed to scan updates' },
                            timestamp: new Date(),
                        });
                    }
                    break;
                case 'unsubscribe_scan':
                    if (data.scanId) {
                        client.subscribedScans.delete(data.scanId);
                        logger_1.logger.debug(`Client ${clientId} unsubscribed from scan ${data.scanId}`);
                    }
                    break;
                case 'authenticate':
                    // In a real app, validate the token
                    if (data.token && data.userId) {
                        client.userId = data.userId;
                        logger_1.logger.info(`WebSocket client ${clientId} authenticated as user ${data.userId}`);
                    }
                    break;
                default:
                    logger_1.logger.warn(`Unknown WebSocket message type: ${data.type}`, {
                        clientId,
                        messageType: data.type,
                    });
            }
        }
        catch (error) {
            logger_1.logger.error(`Failed to handle WebSocket message from ${clientId}:`, error);
            this.sendMessage(clientId, {
                type: 'error',
                data: { error: 'Invalid message format' },
                timestamp: new Date(),
            });
        }
    }
    getClientCount() {
        return this.clients.size;
    }
    getActiveScans() {
        const scans = new Set();
        this.clients.forEach(client => {
            client.subscribedScans.forEach(scanId => scans.add(scanId));
        });
        return Array.from(scans);
    }
    cleanup() {
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
        }
        // Close all client connections
        this.clients.forEach((client, clientId) => {
            this.removeClient(clientId);
        });
        logger_1.logger.info('WebSocket manager cleaned up');
    }
}
let wsManager;
function websocketHandler(wss) {
    wsManager = new WebSocketManager(wss);
    wss.on('connection', (ws, request) => {
        const clientId = wsManager['addClient'](ws);
        // Log connection details
        logger_1.logger.info('New WebSocket connection', {
            clientId,
            userAgent: request.headers['user-agent'],
            origin: request.headers.origin,
            ip: request.socket.remoteAddress,
        });
        // Send welcome message
        wsManager['sendMessage'](clientId, {
            type: 'progress',
            data: {
                message: 'Connected to API Risk Visualizer',
                clientId,
                serverTime: new Date().toISOString(),
            },
            timestamp: new Date(),
        });
        // Handle incoming messages
        ws.on('message', (message) => {
            wsManager['handleMessage'](clientId, message.toString());
        });
        // Handle connection close
        ws.on('close', (code, reason) => {
            logger_1.logger.info(`WebSocket client ${clientId} disconnected`, {
                code,
                reason: reason.toString(),
            });
            wsManager['removeClient'](clientId);
        });
        // Handle errors
        ws.on('error', (error) => {
            logger_1.logger.error(`WebSocket error for client ${clientId}:`, error);
            wsManager['removeClient'](clientId);
        });
        // Handle pong (response to ping)
        ws.on('pong', () => {
            const client = wsManager['clients'].get(clientId);
            if (client) {
                client.lastHeartbeat = new Date();
            }
        });
    });
    // Handle server errors
    wss.on('error', (error) => {
        logger_1.logger.error('WebSocket server error:', error);
    });
    logger_1.logger.info('WebSocket server initialized');
}
// Export the manager instance for use in other modules
function getWebSocketManager() {
    if (!wsManager) {
        throw new Error('WebSocket manager not initialized');
    }
    return wsManager;
}
// Graceful shutdown
process.on('SIGTERM', () => {
    if (wsManager) {
        wsManager.cleanup();
    }
});
process.on('SIGINT', () => {
    if (wsManager) {
        wsManager.cleanup();
    }
});
//# sourceMappingURL=websocket.js.map