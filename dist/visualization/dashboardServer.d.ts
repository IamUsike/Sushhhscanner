import { RiskScoringEngine, VulnerabilityData } from '../ai/riskScoringEngine';
export interface DashboardConfig {
    port: number;
    host: string;
    corsOrigins: string[];
    updateInterval: number;
}
export interface ClientConnection {
    id: string;
    connectedAt: Date;
    subscriptions: string[];
}
export declare class DashboardServer {
    private app;
    private server;
    private io;
    private config;
    private riskEngine;
    private analytics;
    private realTimeScanner;
    private clients;
    private updateTimer;
    private vulnerabilities;
    private lastUpdate;
    private hasRealScanData;
    constructor(config: DashboardConfig, riskEngine: RiskScoringEngine);
    private setupMiddleware;
    private setupRoutes;
    private setupSocketHandlers;
    private loadSampleData;
    private generateTimelineData;
    private generateDashboardMetrics;
    private startRealTimeUpdates;
    private stopRealTimeUpdates;
    start(): Promise<void>;
    stop(): Promise<void>;
    getConnectedClients(): ClientConnection[];
    broadcastMessage(channel: string, message: any): void;
    updateWithRealScanData(vulnerabilities: VulnerabilityData[]): void;
    resetToSampleData(): void;
}
//# sourceMappingURL=dashboardServer.d.ts.map