export interface PDFReportConfig {
    includeExecutiveSummary: boolean;
    includeTechnicalDetails: boolean;
    includeRemediationPlan: boolean;
    includeRiskAnalysis: boolean;
    includeComplianceAssessment: boolean;
    customBranding?: {
        logo?: Buffer;
        companyName?: string;
        primaryColor?: string;
    };
}
export interface VulnerabilityWithRemediation {
    id: string;
    type: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
    endpoint: string;
    method: string;
    description: string;
    impact: string;
    confidence: number;
    cwe: string;
    cvss?: number;
    aiRemediation: {
        priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
        timeframe: string;
        effort: string;
        steps: string[];
        codeExamples: string[];
        resources: string[];
        alternatives: string[];
        aiConfidence: number;
    };
    riskScore: number;
}
export type LLMProvider = 'gemini' | 'groq';
export interface AIRemediationEngine {
    generateRemediation(vulnerability: any): Promise<any>;
    generateExecutiveSummary(vulnerabilities: any[]): Promise<string>;
    generateRiskAnalysis(vulnerabilities: any[]): Promise<any>;
    generateComplianceAssessment(vulnerabilities: any[]): Promise<any>;
}
export declare class PDFReportGenerator {
    private gemini;
    private groq;
    private riskEngine;
    private remediationEngine;
    private provider;
    constructor(provider?: LLMProvider, apiKey?: string);
    generatePDFReport(scanData: any, config?: PDFReportConfig): Promise<Buffer>;
    private addHeader;
    private addExecutiveSummary;
    private addRiskAnalysis;
    private addVulnerabilityDetails;
    private addRemediationPlan;
    private addComplianceAssessment;
    private addFooter;
    private splitTextIntoParagraphs;
    private getSeverityColor;
    private getComplianceColor;
}
//# sourceMappingURL=pdfReportGenerator.d.ts.map