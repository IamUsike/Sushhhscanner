import { EndpointInfo, ScanTarget, Vulnerability } from '../types';
import { DiscoveryOptions } from './endpointDiscovery';
export declare class PassiveCrawler {
    private target;
    private options;
    private visitedUrls;
    private discoveredEndpoints;
    private maxDepth;
    private maxUrls;
    private sensitiveDataDetector;
    private onVulnerabilityFound;
    constructor(target: ScanTarget, options: DiscoveryOptions, onVulnerabilityFound: (vulnerability: Vulnerability) => void);
    discover(): Promise<EndpointInfo[]>;
    private crawlPage;
    private parseHtmlPage;
    private parseJavaScriptFile;
    private parseJavaScriptContent;
    private parseJsonResponse;
    private extractEndpointsFromObject;
    private looksLikeApiEndpoint;
    private extractApiEndpointsFromUrl;
    private isSameDomain;
    private createEndpointInfo;
    private retryRequest;
}
//# sourceMappingURL=passiveCrawler.d.ts.map