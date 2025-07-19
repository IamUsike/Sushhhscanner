import { APIEndpoint, ScanTarget, Vulnerability } from '../types';
export interface DiscoveryOptions {
    includeSwagger?: boolean;
    includeCrawling?: boolean;
    includeBruteForce?: boolean;
    includeRobots?: boolean;
    maxEndpoints?: number;
    timeout?: number;
    userAgent?: string;
}
export interface DiscoveryResult {
    endpoints: APIEndpoint[];
    totalFound: number;
    duration: number;
    discoveryMethods: Record<string, number>;
    errors: string[];
}
export declare class EndpointDiscovery {
    private target;
    private options;
    private swaggerDiscovery;
    private bruteForceDiscovery;
    private robotsParser;
    constructor(target: ScanTarget, options?: DiscoveryOptions);
    discover(scanId: string, progressCallback: (progress: number, step: string, details?: any) => void, emitEndpoint: (endpoint: APIEndpoint) => void, emitVulnerability: (vulnerability: Vulnerability) => void): Promise<DiscoveryResult>;
    private mapEndpointInfoToAPIEndpoint;
}
//# sourceMappingURL=endpointDiscovery.d.ts.map