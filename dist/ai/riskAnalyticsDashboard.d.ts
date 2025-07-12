import { RiskScoringEngine, VulnerabilityData } from './riskScoringEngine';
export interface RiskTrend {
    timestamp: string;
    overallRisk: number;
    criticalVulns: number;
    highVulns: number;
    mediumVulns: number;
    lowVulns: number;
    newVulns: number;
    resolvedVulns: number;
    avgTimeToDetect: number;
    avgTimeToResolve: number;
}
export interface RiskHeatmapData {
    endpoint: string;
    method: string;
    riskScore: number;
    vulnerabilityCount: number;
    criticalityLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    businessImpact: number;
    lastScanned: string;
}
export interface MLInsight {
    type: 'TREND' | 'ANOMALY' | 'PREDICTION' | 'RECOMMENDATION';
    severity: 'HIGH' | 'MEDIUM' | 'LOW';
    title: string;
    description: string;
    confidence: number;
    impact: string;
    recommendation: string;
    dataPoints?: any[];
}
export interface RiskPortfolio {
    totalEndpoints: number;
    scannedEndpoints: number;
    vulnerableEndpoints: number;
    riskDistribution: {
        critical: number;
        high: number;
        medium: number;
        low: number;
    };
    businessCriticalityBreakdown: {
        high: {
            count: number;
            avgRisk: number;
        };
        medium: {
            count: number;
            avgRisk: number;
        };
        low: {
            count: number;
            avgRisk: number;
        };
    };
    complianceStatus: {
        owaspCompliant: boolean;
        pciCompliant: boolean;
        gdprCompliant: boolean;
        complianceScore: number;
    };
    topRisks: Array<{
        endpoint: string;
        riskScore: number;
        vulnerabilities: string[];
        businessImpact: number;
    }>;
}
export declare class RiskAnalyticsDashboard {
    private riskEngine;
    private riskHistory;
    private vulnerabilityHistory;
    private mlInsights;
    constructor(riskEngine: RiskScoringEngine);
    generateRiskPortfolio(vulnerabilities: VulnerabilityData[]): Promise<RiskPortfolio>;
    generateRiskHeatmap(vulnerabilities: VulnerabilityData[]): Promise<RiskHeatmapData[]>;
    generateMLInsights(vulnerabilities: VulnerabilityData[]): Promise<MLInsight[]>;
    private groupRisksByEndpoint;
    private calculateRiskDistribution;
    private calculateBusinessCriticalityBreakdown;
    private assessComplianceStatus;
    private identifyTopRisks;
    private analyzeTrends;
    private detectAnomalies;
    private generatePredictiveInsights;
    private generateStrategicRecommendations;
    private mapRiskToCriticality;
    addRiskTrend(trend: RiskTrend): void;
    getRiskTrends(days?: number): RiskTrend[];
    getMLInsights(): MLInsight[];
    exportRiskReport(): Promise<{
        portfolio: RiskPortfolio;
        insights: MLInsight[];
        trends: RiskTrend[];
        modelMetrics: any;
    }>;
}
//# sourceMappingURL=riskAnalyticsDashboard.d.ts.map