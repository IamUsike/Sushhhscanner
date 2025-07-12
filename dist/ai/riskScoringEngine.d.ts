export interface VulnerabilityData {
    type: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
    confidence: number;
    cwe: string;
    owasp: string;
    endpoint: string;
    method: string;
    parameter?: string;
    responseTime: number;
    statusCode: number;
    errorSignatures: string[];
    businessCriticality?: 'HIGH' | 'MEDIUM' | 'LOW';
    dataClassification?: 'CONFIDENTIAL' | 'INTERNAL' | 'PUBLIC';
    userAccess?: 'EXTERNAL' | 'INTERNAL' | 'ADMIN';
    framework?: string;
    database?: string;
    authentication?: boolean;
    encryption?: boolean;
    exploitability?: number;
    impact?: number;
    attackComplexity?: 'LOW' | 'MEDIUM' | 'HIGH';
}
export interface RiskScore {
    overall: number;
    components: {
        severity: number;
        exploitability: number;
        businessImpact: number;
        contextualRisk: number;
        temporalRisk: number;
    };
    prediction: {
        likelihood: number;
        timeToExploit: number;
        impactMagnitude: number;
    };
    recommendations: {
        priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
        timeframe: string;
        resources: string[];
        alternatives: string[];
    };
    confidence: number;
}
export interface MLModelMetrics {
    accuracy: number;
    precision: number;
    recall: number;
    f1Score: number;
    trainedSamples: number;
    lastUpdated: string;
}
export declare class RiskScoringEngine {
    private severityModel;
    private exploitabilityModel;
    private businessImpactModel;
    private ensembleModel;
    private isInitialized;
    private modelMetrics;
    private readonly severityWeights;
    private readonly cweRiskScores;
    private readonly owaspRiskFactors;
    constructor();
    initialize(): Promise<void>;
    calculateRiskScore(vulnerability: VulnerabilityData): Promise<RiskScore>;
    private createModels;
    private trainModels;
    private extractFeatures;
    private predictSeverityRisk;
    private predictExploitability;
    private predictBusinessImpact;
    private calculateContextualRisk;
    private calculateTemporalRisk;
    private calculateEnsembleScore;
    private generatePredictions;
    private generateRecommendations;
    private calculateModelConfidence;
    private calculateFallbackScore;
    private generateTrainingData;
    getModelMetrics(): MLModelMetrics;
    saveModels(basePath: string): Promise<void>;
    loadModels(basePath: string): Promise<void>;
}
//# sourceMappingURL=riskScoringEngine.d.ts.map