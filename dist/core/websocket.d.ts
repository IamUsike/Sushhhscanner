import { WebSocketServer } from 'ws';
import { WebSocketMessage } from '@/types';
declare class WebSocketManager {
    private wss;
    private clients;
    private heartbeatInterval;
    constructor(wss: WebSocketServer);
    private setupHeartbeat;
    private addClient;
    private removeClient;
    private sendMessage;
    broadcastToScanSubscribers(scanId: string, message: WebSocketMessage): void;
    notifyVulnerabilityFound(scanId: string, vulnerability: any): void;
    notifyScanProgress(scanId: string, progress: number, step: string, details?: any): void;
    notifyScanCompleted(scanId: string, summary: any): void;
    notifyError(scanId: string, error: string): void;
    private handleMessage;
    getClientCount(): number;
    getActiveScans(): string[];
    cleanup(): void;
}
export declare function websocketHandler(wss: WebSocketServer): void;
export declare function getWebSocketManager(): WebSocketManager;
export {};
//# sourceMappingURL=websocket.d.ts.map