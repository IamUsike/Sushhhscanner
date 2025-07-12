import { AxiosResponse } from 'axios';
export interface Parameter {
    name: string;
    type: 'string' | 'number' | 'boolean' | 'array' | 'object' | 'unknown';
    location: 'query' | 'body' | 'header' | 'path' | 'form';
    required?: boolean;
    format?: string;
    example?: any;
    constraints?: {
        minLength?: number;
        maxLength?: number;
        pattern?: string;
        minimum?: number;
        maximum?: number;
        enum?: any[];
    };
}
export interface ParameterVulnerability {
    parameter: Parameter;
    vulnerability: {
        type: string;
        name: string;
        description: string;
        severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
        confidence: number;
        cwe: string;
        owasp: string;
    };
    payload: {
        original: any;
        malicious: any;
        technique: string;
        category: string;
    };
    evidence: {
        request: string;
        response: string;
        statusCode: number;
        responseTime: number;
        differenceDetected: boolean;
        errorSignatures?: string[];
    };
    impact: string;
    recommendation: string;
}
export interface PayloadGenerationOptions {
    useAI: boolean;
    maxPayloads: number;
    includeAdvanced: boolean;
    targetLanguage?: 'sql' | 'nosql' | 'javascript' | 'python' | 'php' | 'all';
    customPatterns?: string[];
}
export declare class ParameterTester {
    private options;
    private readonly sqlInjectionPayloads;
    private readonly nosqlInjectionPayloads;
    private readonly xssPayloads;
    private readonly commandInjectionPayloads;
    private readonly pathTraversalPayloads;
    private readonly ldapInjectionPayloads;
    private readonly xxePayloads;
    private readonly errorSignatures;
    constructor(options?: PayloadGenerationOptions);
    testParameter(endpoint: string, method: string, parameter: Parameter, baselineResponse?: AxiosResponse): Promise<ParameterVulnerability[]>;
    private generatePayloads;
    private generateAIEnhancedPayloads;
    private testPayload;
    private analyzeResponse;
    private detectErrorSignatures;
    private analyzeContentDifference;
    private classifyVulnerability;
    private getVulnerabilityImpact;
    private getVulnerabilityRecommendation;
    private makeBaselineRequest;
    private makeRequest;
    private generateSafeValue;
    private enhanceVulnerabilityAnalysis;
}
//# sourceMappingURL=parameterTester.d.ts.map