import { WebSocketServer, WebSocket } from 'ws';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '@utils/logger';
import { WebSocketMessage } from '@/types';

interface ClientConnection {
  id: string;
  ws: WebSocket;
  userId?: string;
  subscribedScans: Set<string>;
  lastHeartbeat: Date;
}

class WebSocketManager {
  private clients = new Map<string, ClientConnection>();
  private heartbeatInterval: NodeJS.Timeout | null = null;

  constructor(private wss: WebSocketServer) {
    this.setupHeartbeat();
  }

  private setupHeartbeat(): void {
    const interval = parseInt(process.env.WS_HEARTBEAT_INTERVAL || '30000');
    
    this.heartbeatInterval = setInterval(() => {
      const now = new Date();
      
      this.clients.forEach((client, clientId) => {
        const timeSinceHeartbeat = now.getTime() - client.lastHeartbeat.getTime();
        
        if (timeSinceHeartbeat > interval * 2) {
          // Client hasn't responded to heartbeat, disconnect
          logger.warn(`WebSocket client ${clientId} heartbeat timeout, disconnecting`);
          this.removeClient(clientId);
          return;
        }

        if (client.ws.readyState === WebSocket.OPEN) {
          this.sendMessage(clientId, {
            type: 'heartbeat',
            timestamp: now,
          });
        }
      });
    }, interval);
  }

  private addClient(ws: WebSocket): string {
    const clientId = uuidv4();
    
    const client: ClientConnection = {
      id: clientId,
      ws,
      subscribedScans: new Set(),
      lastHeartbeat: new Date(),
    };

    this.clients.set(clientId, client);
    
    logger.info(`WebSocket client connected: ${clientId}`);
    
    return clientId;
  }

  private removeClient(clientId: string): void {
    const client = this.clients.get(clientId);
    
    if (client) {
      if (client.ws.readyState === WebSocket.OPEN) {
        client.ws.close();
      }
      
      this.clients.delete(clientId);
      logger.info(`WebSocket client disconnected: ${clientId}`);
    }
  }

  private sendMessage(clientId: string, message: WebSocketMessage): void {
    const client = this.clients.get(clientId);
    
    if (client && client.ws.readyState === WebSocket.OPEN) {
      try {
        client.ws.send(JSON.stringify(message));
      } catch (error) {
        logger.error(`Failed to send WebSocket message to ${clientId}:`, error);
        this.removeClient(clientId);
      }
    }
  }

  public broadcastToScanSubscribers(scanId: string, message: WebSocketMessage): void {
    let subscriberCount = 0;
    
    this.clients.forEach((client, clientId) => {
      if (client.subscribedScans.has(scanId)) {
        this.sendMessage(clientId, { ...message, scanId });
        subscriberCount++;
      }
    });

    if (subscriberCount > 0) {
      logger.debug(`Broadcasted scan update to ${subscriberCount} subscribers`, {
        scanId,
        messageType: message.type,
      });
    }
  }

  public notifyVulnerabilityFound(scanId: string, vulnerability: any): void {
    this.broadcastToScanSubscribers(scanId, {
      type: 'vulnerability_found',
      data: { vulnerability },
      timestamp: new Date(),
    });
  }

  public notifyScanProgress(scanId: string, progress: number, step: string, details?: any): void {
    this.broadcastToScanSubscribers(scanId, {
      type: 'progress',
      data: { progress, step, details },
      timestamp: new Date(),
    });
  }

  public notifyScanCompleted(scanId: string, summary: any): void {
    this.broadcastToScanSubscribers(scanId, {
      type: 'scan_completed',
      data: { summary },
      timestamp: new Date(),
    });
  }

  public notifyError(scanId: string, error: string): void {
    this.broadcastToScanSubscribers(scanId, {
      type: 'error',
      data: { error },
      timestamp: new Date(),
    });
  }

  private handleMessage(clientId: string, message: string): void {
    try {
      const data = JSON.parse(message);
      const client = this.clients.get(clientId);
      
      if (!client) return;

      switch (data.type) {
        case 'heartbeat':
          client.lastHeartbeat = new Date();
          break;

        case 'subscribe_scan':
          if (data.scanId) {
            client.subscribedScans.add(data.scanId);
            logger.debug(`Client ${clientId} subscribed to scan ${data.scanId}`);
            
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
            logger.debug(`Client ${clientId} unsubscribed from scan ${data.scanId}`);
          }
          break;

        case 'authenticate':
          // In a real app, validate the token
          if (data.token && data.userId) {
            client.userId = data.userId;
            logger.info(`WebSocket client ${clientId} authenticated as user ${data.userId}`);
          }
          break;

        default:
          logger.warn(`Unknown WebSocket message type: ${data.type}`, {
            clientId,
            messageType: data.type,
          });
      }
    } catch (error) {
      logger.error(`Failed to handle WebSocket message from ${clientId}:`, error);
      
      this.sendMessage(clientId, {
        type: 'error',
        data: { error: 'Invalid message format' },
        timestamp: new Date(),
      });
    }
  }

  public getClientCount(): number {
    return this.clients.size;
  }

  public getActiveScans(): string[] {
    const scans = new Set<string>();
    
    this.clients.forEach(client => {
      client.subscribedScans.forEach(scanId => scans.add(scanId));
    });
    
    return Array.from(scans);
  }

  public cleanup(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
    }
    
    // Close all client connections
    this.clients.forEach((client, clientId) => {
      this.removeClient(clientId);
    });
    
    logger.info('WebSocket manager cleaned up');
  }
}

let wsManager: WebSocketManager;

export function websocketHandler(wss: WebSocketServer): void {
  wsManager = new WebSocketManager(wss);

  wss.on('connection', (ws: WebSocket, request) => {
    const clientId = wsManager['addClient'](ws);
    
    // Log connection details
    logger.info('New WebSocket connection', {
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
    ws.on('message', (message: Buffer) => {
      wsManager['handleMessage'](clientId, message.toString());
    });

    // Handle connection close
    ws.on('close', (code: number, reason: Buffer) => {
      logger.info(`WebSocket client ${clientId} disconnected`, {
        code,
        reason: reason.toString(),
      });
      wsManager['removeClient'](clientId);
    });

    // Handle errors
    ws.on('error', (error: Error) => {
      logger.error(`WebSocket error for client ${clientId}:`, error);
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
  wss.on('error', (error: Error) => {
    logger.error('WebSocket server error:', error);
  });

  logger.info('WebSocket server initialized');
}

// Export the manager instance for use in other modules
export function getWebSocketManager(): WebSocketManager {
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