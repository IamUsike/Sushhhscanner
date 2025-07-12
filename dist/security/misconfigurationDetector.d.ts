export interface MisconfigurationResult {
    category: string;
    type: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
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
    recommendation: string;
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
    private makeRequest;
    private normalizeUrl;
    private isValidContent;
    private isDirectoryListing;
    private isAdminInterface;
    private isServerInfoPage;
    private hasDetailedErrorInfo;
    private getSensitiveFileSeverity;
    private truncateContent;
}
//# sourceMappingURL=misconfigurationDetector.d.ts.map