import { EndpointDiscovery } from '../discovery/endpointDiscovery';
import { AuthenticationTester } from '../security/authenticationTester';
import { ParameterVulnerabilityScanner } from '../security/parameterVulnerabilityScanner';
import { RiskScoringEngine } from '../ai/riskScoringEngine';
import { DashboardServer } from '../visualization/dashboardServer';
import { EndpointInfo } from '../types';
export interface ApiScanRequest {
    targetUrl: string;
    scanMethods: ('swagger' | 'crawl' | 'brute_force')[];
    authConfig?: {
        headers?: Record<string, string>;
        cookies?: Record<string, string>;
        basicAuth?: {
            username: string;
            password: string;
        };
        bearerToken?: string;
    };
    scanDepth: 'shallow' | 'deep' | 'comprehensive';
    realTimeUpdates: boolean;
}
export interface ScanProgress {
    phase: 'discovery' | 'auth_testing' | 'parameter_testing' | 'risk_scoring' | 'complete';
    progress: number;
    currentEndpoint?: string;
    endpointsFound: number;
    vulnerabilitiesFound: number;
    estimatedTimeRemaining?: number;
    lastUpdate: Date;
}
export interface RealTimeScanResults {
    scanId: string;
    targetUrl: string;
    progress: ScanProgress;
    discoveredEndpoints: EndpointInfo[];
    vulnerabilities: any[];
    riskScores: any[];
    insights: any[];
    startTime: Date;
    endTime?: Date;
    totalDuration?: number;
}
export declare class RealTimeApiScanner {
    private discoveryEngine;
    private authTester;
    private parameterScanner;
    private riskEngine;
    private dashboardServer;
    private activeScan;
    private scanCallbacks;
    constructor(riskEngine: RiskScoringEngine, discoveryEngine: EndpointDiscovery | null, authTester: AuthenticationTester, parameterScanner: ParameterVulnerabilityScanner);
    setDashboardServer(dashboardServer: DashboardServer): void;
    startRealTimeScan(request: ApiScanRequest): Promise<string>;
    private performRealTimeScan;
    private performDiscoveryPhase;
    private getJSONPlaceholderEndpoints;
    private generateJSONPlaceholderParameters;
    private performBasicWebCrawling;
    private isSwaggerEndpoint;
    private detectParametersFromPath;
    private parseBasicSwaggerEndpoints;
    private extractSwaggerParameters;
    private mapSwaggerParamType;
    private detectParametersFromEndpoint;
    private generatePostParameters;
    private performBasicBruteForce;
    private detectAuthMethods;
    private generateBruteForceParameters;
    private performAuthenticationPhase;
    private performParameterTestingPhase;
    private performFastParameterTest;
    private performRiskScoringPhase;
    private completeScan;
    private generateSimplifiedInsights;
    private updateDashboardWithRealData;
    private updateScanProgress;
    private getPhaseDetails;
    private broadcastScanUpdate;
    private mapToCWE;
    private mapToOWASP;
    private inferBusinessCriticality;
    private inferDataClassification;
    private convertParameterInfoToParameter;
    private mapDataTypeToParameterType;
    getScanStatus(scanId: string): RealTimeScanResults | null;
    cancelScan(scanId: string): boolean;
    getActiveScan(): RealTimeScanResults | null;
}
//# sourceMappingURL=realTimeApiScanner.d.ts.map