import { VulnerabilitySeverity, RemediationGuidance } from '../types';
export interface MisconfigurationResult {
    category: string;
    type: string;
    severity: VulnerabilitySeverity;
    confidence: number;
    title: string;
    description: string;
    evidence: {
        url?: string;
        response?: string;
        headers?: Record<string, string>;
        statusCode?: number;
        file?: string;
        content?: string;
    };
    cwe: string;
    owasp: string;
    recommendation: RemediationGuidance;
    impact: string;
    references: string[];
}
export interface MisconfigurationScanOptions {
    timeout?: number;
    followRedirects?: boolean;
    checkSSL?: boolean;
    checkHeaders?: boolean;
    checkFiles?: boolean;
    checkDirectories?: boolean;
    checkServerInfo?: boolean;
    checkCORS?: boolean;
    checkCSP?: boolean;
    maxRedirects?: number;
    userAgent?: string;
}
export declare class MisconfigurationDetector {
    private options;
    private recommendationService;
    private readonly defaultOptions;
    private readonly sensitiveFiles;
    private readonly sensitivePaths;
    constructor(options?: MisconfigurationScanOptions);
    scanTarget(baseUrl: string, progressCallback?: (progress: string) => void): Promise<MisconfigurationResult[]>;
    private checkSecurityHeaders;
    private checkSensitiveFiles;
    private checkDirectoryMisconfigurations;
    private checkServerInformation;
    private checkCORSMisconfiguration;
    private checkCSPMisconfiguration;
    private checkSSLConfiguration;
    private checkRobotsAndSitemap;
    private checkInsecureCookieDirectives;
    private checkHttpMethodEnforcement;
    private makeRequest;
    private normalizeUrl;
    private isValidContent;
    private isDirectoryListing;
    private isAdminInterface;
    private isServerInfoPage;
    private hasDetailedErrorInfo;
    private getSensitiveFileSeverity;
    private truncateContent;
    private generateRecommendationForMisconfiguration;
}
//# sourceMappingURL=misconfigurationDetector.d.ts.map