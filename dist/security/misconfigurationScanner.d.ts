import { MisconfigurationResult, MisconfigurationScanOptions } from './misconfigurationDetector';
export interface MisconfigurationScanResult {
    target: string;
    scanStartTime: string;
    scanEndTime: string;
    scanDuration: number;
    totalIssues: number;
    issuesBySeverity: {
        CRITICAL: number;
        HIGH: number;
        MEDIUM: number;
        LOW: number;
        INFO: number;
    };
    issuesByCategory: Record<string, number>;
    complianceStatus: {
        owaspTop10: {
            covered: string[];
            issues: number;
        };
        cweMapping: Record<string, number>;
    };
    findings: MisconfigurationResult[];
    recommendations: string[];
    executiveSummary: string;
}
export interface ComprehensiveScanOptions extends MisconfigurationScanOptions {
    includeConfigAnalysis?: boolean;
    analyzeSwagger?: boolean;
    checkCloudConfig?: boolean;
    generateReport?: boolean;
    exportFormat?: 'json' | 'html' | 'csv';
}
export declare class MisconfigurationScanner {
    private options;
    private detector;
    private configAnalyzer;
    constructor(options?: ComprehensiveScanOptions);
    scanTarget(target: string, progressCallback?: (progress: string) => void): Promise<MisconfigurationScanResult>;
    private analyzeConfigurationFiles;
    private analyzeSwaggerConfigurations;
    private analyzeCloudConfigurations;
    private generateScanResult;
    private generateRecommendations;
    private generateExecutiveSummary;
    private calculateOverallRiskLevel;
    private truncateContent;
    exportReport(scanResult: MisconfigurationScanResult, format?: 'json' | 'html' | 'csv'): Promise<string>;
    private generateHTMLReport;
    private generateCSVReport;
}
//# sourceMappingURL=misconfigurationScanner.d.ts.map