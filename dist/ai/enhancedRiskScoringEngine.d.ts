export interface CVSSMetrics {
    baseScore: number;
    temporalScore: number;
    environmentalScore: number;
    vector: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
}
export interface EnhancedVulnerabilityData {
    type: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
    confidence: number;
    cwe: string;
    owasp: string;
    cvss?: CVSSMetrics;
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
    attackVector?: 'NETWORK' | 'ADJACENT_NETWORK' | 'LOCAL' | 'PHYSICAL';
    privilegesRequired?: 'NONE' | 'LOW' | 'HIGH';
    userInteraction?: 'NONE' | 'REQUIRED';
    scope?: 'UNCHANGED' | 'CHANGED';
    confidentialityImpact?: 'NONE' | 'LOW' | 'HIGH';
    integrityImpact?: 'NONE' | 'LOW' | 'HIGH';
    availabilityImpact?: 'NONE' | 'LOW' | 'HIGH';
}
export interface EnhancedRiskScore {
    overall: number;
    cvssAdjusted: number;
    components: {
        severity: number;
        exploitability: number;
        businessImpact: number;
        contextualRisk: number;
        temporalRisk: number;
        cvssRisk: number;
    };
    prediction: {
        likelihood: number;
        timeToExploit: number;
        impactMagnitude: number;
        attackProbability: number;
    };
    recommendations: {
        priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
        timeframe: string;
        resources: string[];
        alternatives: string[];
        cvssRemediation: string[];
    };
    confidence: number;
    cvssMetrics: CVSSMetrics | null;
}
export interface MLModelMetrics {
    accuracy: number;
    precision: number;
    recall: number;
    f1Score: number;
    cvssCorrelation: number;
    trainedSamples: number;
    lastUpdated: string;
}
export declare class EnhancedRiskScoringEngine {
    private severityModel;
    private exploitabilityModel;
    private businessImpactModel;
    private cvssModel;
    private ensembleModel;
    private anomalyDetectionModel;
    private isInitialized;
    private modelMetrics;
    private readonly severityWeights;
    private readonly cweRiskScores;
    private readonly owaspRiskFactors;
    private readonly cvssSeverityRanges;
    constructor();
    initialize(): Promise<void>;
    calculateEnhancedRiskScore(vulnerability: EnhancedVulnerabilityData): Promise<EnhancedRiskScore>;
    private createEnhancedModels;
    private trainEnhancedModels;
    private extractEnhancedFeatures;
    private calculateCVSSMetrics;
    private calculateCVSSBaseScore;
    private getCVSSSeverity;
    private getAttackVectorScore;
    private getPrivilegesScore;
    private getImpactScore;
    private predictSeverityRisk;
    private predictExploitability;
    private predictBusinessImpact;
    private predictCVSSRisk;
    private calculateCVSSAdjustedScore;
    private generateEnhancedPredictions;
    private generateEnhancedRecommendations;
    private generateCVSSRemediation;
    private generateEnhancedTrainingData;
    private calculateContextualRisk;
    private calculateTemporalRisk;
    private calculateEnhancedEnsembleScore;
    private calculateModelConfidence;
    private calculateEnhancedFallbackScore;
    private updateModelMetrics;
    getModelMetrics(): MLModelMetrics;
    saveModels(basePath: string): Promise<void>;
    loadModels(basePath: string): Promise<void>;
}
//# sourceMappingURL=enhancedRiskScoringEngine.d.ts.map