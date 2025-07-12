import { Parameter } from './parameterTester';
export interface AIPayload {
    value: any;
    technique: string;
    category: string;
    description: string;
    confidence: number;
    complexity: 'basic' | 'intermediate' | 'advanced' | 'expert';
    tags: string[];
    source: 'static' | 'ai_generated' | 'context_aware' | 'ml_enhanced';
}
export interface PayloadContext {
    parameterName: string;
    parameterType: string;
    endpoint: string;
    method: string;
    applicationContext?: {
        framework?: string;
        database?: string;
        language?: string;
        platform?: string;
    };
    previousFindings?: Array<{
        type: string;
        parameter: string;
        success: boolean;
    }>;
}
export declare class AIPayloadGenerator {
    private readonly mlPatterns;
    private readonly contextualEnhancements;
    private readonly frameworkPayloads;
    generatePayloads(parameter: Parameter, context: PayloadContext): Promise<AIPayload[]>;
    private generateStaticPayloads;
    private generateContextAwarePayloads;
    private generateMLEnhancedPayloads;
    private generateFrameworkSpecificPayloads;
    private generateMutationPayloads;
    private prioritizePayloads;
    private generateRegexBypass;
    private randomCase;
    private doubleEncode;
    private htmlEncode;
    analyzePayloadEffectiveness(parameter: Parameter, payload: AIPayload, response: any, baseline: any): Promise<{
        effectiveness: number;
        reasoning: string;
    }>;
}
//# sourceMappingURL=aiPayloadGenerator.d.ts.map