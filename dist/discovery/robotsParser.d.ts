import { APIEndpoint, DiscoveryProgress } from '../types';
export declare class RobotsParser {
    private loggerInstance;
    discoverEndpoints(baseUrl: string, options?: {
        timeout?: number;
        followSitemaps?: boolean;
        maxSitemapDepth?: number;
    }, progressCallback?: (progress: DiscoveryProgress) => void): Promise<APIEndpoint[]>;
    private parseRobotsTxt;
    private extractSitemapUrls;
    private parseSitemaps;
    private extractUrlsFromSitemap;
    private looksLikeAPIPath;
}
//# sourceMappingURL=robotsParser.d.ts.map