import { EndpointInfo, ScanTarget } from '../types';
export interface DiscoveryOptions {
    maxEndpoints?: number;
    timeout?: number;
    includeSwagger?: boolean;
    includeCrawling?: boolean;
    includeBruteForce?: boolean;
    includeRobots?: boolean;
    customWordlists?: string[];
    excludePatterns?: string[];
    userAgent?: string;
}
export interface DiscoveryResult {
    endpoints: EndpointInfo[];
    discoveryMethods: {
        swagger: number;
        crawling: number;
        bruteForce: number;
        robots: number;
        manual: number;
    };
    totalFound: number;
    duration: number;
    errors: string[];
}
export declare class EndpointDiscovery {
    private target;
    private options;
    private swaggerDiscovery;
    private passiveCrawler;
    private bruteForceDiscovery;
    private robotsParser;
    private discoveredEndpoints;
    private errors;
    constructor(target: ScanTarget, options?: DiscoveryOptions);
    discover(scanId: string, progressCallback?: (progress: number, step: string, details?: any) => void): Promise<DiscoveryResult>;
    private updateProgress;
    private basicReconnaissance;
    private detectFramework;
    private processManualEndpoints;
    private discoverSwaggerEndpoints;
    private discoverRobotsEndpoints;
    private discoverCrawlingEndpoints;
    private discoverBruteForceEndpoints;
    private analyzeEndpoints;
    private enhanceEndpointInfo;
    private validateEndpoints;
    private analyzeEndpoint;
    private extractUrlParameters;
    private inferDataType;
    private analyzeAuthentication;
    private addEndpoint;
    private getEndpointKey;
    private shouldExcludeEndpoint;
    private mergeEndpointInfo;
    private makeRequest;
    private buildResult;
}
//# sourceMappingURL=endpointDiscovery.d.ts.map