import { APIEndpoint, DiscoveryProgress } from '../types';
export declare class BruteForceDiscovery {
    private loggerInstance;
    private readonly commonEndpoints;
    private readonly httpMethods;
    discoverEndpoints(baseUrl: string, options?: {
        timeout?: number;
        maxConcurrent?: number;
        testMethods?: string[];
    }, progressCallback?: (progress: DiscoveryProgress) => void, onEndpointDiscovered?: (endpoint: APIEndpoint) => void): Promise<APIEndpoint[]>;
    private normalizeUrl;
    private sanitizeHeaders;
    private extractParametersFromResponse;
    private detectAuthType;
}
//# sourceMappingURL=bruteForceDiscovery.d.ts.map