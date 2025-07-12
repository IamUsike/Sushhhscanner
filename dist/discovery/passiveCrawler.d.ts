import { EndpointInfo, ScanTarget } from '../types';
import { DiscoveryOptions } from './endpointDiscovery';
export declare class PassiveCrawler {
    private target;
    private options;
    private visitedUrls;
    private discoveredEndpoints;
    private maxDepth;
    private maxUrls;
    constructor(target: ScanTarget, options: DiscoveryOptions);
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
}
//# sourceMappingURL=passiveCrawler.d.ts.map