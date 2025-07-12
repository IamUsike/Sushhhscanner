import axios from 'axios';
import { APIEndpoint, DiscoveryProgress } from '../types';
import { logger } from '../utils/logger';

export class RobotsParser {
    private loggerInstance = logger;
    
    async discoverEndpoints(
        baseUrl: string,
        options: {
            timeout?: number;
            followSitemaps?: boolean;
            maxSitemapDepth?: number;
        } = {},
        progressCallback?: (progress: DiscoveryProgress) => void
    ): Promise<APIEndpoint[]> {
        const {
            timeout = 10000,
            followSitemaps = true,
            maxSitemapDepth = 2
        } = options;
        
        this.loggerInstance.info('Starting robots.txt discovery', { baseUrl });
        
        const endpoints: APIEndpoint[] = [];
        let progress = 0;
        const totalSteps = followSitemaps ? 3 : 2;
        
        try {
            // Step 1: Parse robots.txt
            if (progressCallback) {
                progressCallback({
                    phase: 'robots-discovery',
                    percentage: (progress / totalSteps) * 100,
                    currentOperation: 'Fetching robots.txt'
                });
            }
            
            const robotsEndpoints = await this.parseRobotsTxt(baseUrl, timeout);
            endpoints.push(...robotsEndpoints);
            progress++;
            
            // Step 2: Find sitemap URLs from robots.txt
            if (progressCallback) {
                progressCallback({
                    phase: 'robots-discovery',
                    percentage: (progress / totalSteps) * 100,
                    currentOperation: 'Parsing sitemap references'
                });
            }
            
            const sitemapUrls = await this.extractSitemapUrls(baseUrl, timeout);
            progress++;
            
            // Step 3: Parse sitemaps if enabled
            if (followSitemaps && sitemapUrls.length > 0) {
                if (progressCallback) {
                    progressCallback({
                        phase: 'robots-discovery',
                        percentage: (progress / totalSteps) * 100,
                        currentOperation: 'Parsing sitemaps'
                    });
                }
                
                const sitemapEndpoints = await this.parseSitemaps(sitemapUrls, maxSitemapDepth, timeout);
                endpoints.push(...sitemapEndpoints);
            }
            
            if (progressCallback) {
                progressCallback({
                    phase: 'robots-discovery',
                    percentage: 100,
                    currentOperation: 'Robots.txt discovery complete'
                });
            }
            
        } catch (error: any) {
            this.loggerInstance.warn('Robots.txt discovery failed', {
                baseUrl,
                error: error.message
            });
        }
        
        this.loggerInstance.info('Robots.txt discovery completed', {
            baseUrl,
            endpointsFound: endpoints.length
        });
        
        return endpoints;
    }
    
    private async parseRobotsTxt(baseUrl: string, timeout: number): Promise<APIEndpoint[]> {
        const endpoints: APIEndpoint[] = [];
        
        try {
            const robotsUrl = `${baseUrl.replace(/\/$/, '')}/robots.txt`;
            const response = await axios.get(robotsUrl, { timeout });
            
            if (response.status === 200 && response.data) {
                const lines = response.data.split('\n');
                
                for (const line of lines) {
                    const trimmedLine = line.trim();
                    
                    // Parse Disallow directives
                    if (trimmedLine.toLowerCase().startsWith('disallow:')) {
                        const path = trimmedLine.substring(9).trim();
                        if (path && path !== '/' && this.looksLikeAPIPath(path)) {
                            endpoints.push({
                                path: path,
                                method: 'GET',
                                url: `${baseUrl.replace(/\/$/, '')}${path}`,
                                discoveredBy: ['robots-txt'],
                                description: 'Found in robots.txt disallow directive',
                                timestamp: new Date().toISOString()
                            });
                        }
                    }
                    
                    // Parse Allow directives
                    if (trimmedLine.toLowerCase().startsWith('allow:')) {
                        const path = trimmedLine.substring(6).trim();
                        if (path && path !== '/' && this.looksLikeAPIPath(path)) {
                            endpoints.push({
                                path: path,
                                method: 'GET',
                                url: `${baseUrl.replace(/\/$/, '')}${path}`,
                                discoveredBy: ['robots-txt'],
                                description: 'Found in robots.txt allow directive',
                                timestamp: new Date().toISOString()
                            });
                        }
                    }
                }
            }
            
        } catch (error: any) {
            this.loggerInstance.debug('Failed to fetch robots.txt', {
                baseUrl,
                error: error.message
            });
        }
        
        return endpoints;
    }
    
    private async extractSitemapUrls(baseUrl: string, timeout: number): Promise<string[]> {
        const sitemapUrls: string[] = [];
        
        try {
            const robotsUrl = `${baseUrl.replace(/\/$/, '')}/robots.txt`;
            const response = await axios.get(robotsUrl, { timeout });
            
            if (response.status === 200 && response.data) {
                const lines = response.data.split('\n');
                
                for (const line of lines) {
                    const trimmedLine = line.trim();
                    
                    if (trimmedLine.toLowerCase().startsWith('sitemap:')) {
                        const sitemapUrl = trimmedLine.substring(8).trim();
                        if (sitemapUrl) {
                            sitemapUrls.push(sitemapUrl);
                        }
                    }
                }
            }
            
        } catch (error: any) {
            this.loggerInstance.debug('Failed to extract sitemap URLs from robots.txt', {
                baseUrl,
                error: error.message
            });
        }
        
        // Also try common sitemap locations
        const commonSitemaps = [
            `${baseUrl.replace(/\/$/, '')}/sitemap.xml`,
            `${baseUrl.replace(/\/$/, '')}/sitemap_index.xml`,
            `${baseUrl.replace(/\/$/, '')}/sitemaps.xml`
        ];
        
        sitemapUrls.push(...commonSitemaps);
        
        return [...new Set(sitemapUrls)]; // Remove duplicates
    }
    
    private async parseSitemaps(
        sitemapUrls: string[],
        maxDepth: number,
        timeout: number,
        currentDepth: number = 0
    ): Promise<APIEndpoint[]> {
        const endpoints: APIEndpoint[] = [];
        
        if (currentDepth >= maxDepth) {
            return endpoints;
        }
        
        for (const sitemapUrl of sitemapUrls) {
            try {
                const response = await axios.get(sitemapUrl, { timeout });
                
                if (response.status === 200 && response.data) {
                    const urls = this.extractUrlsFromSitemap(response.data);
                    
                    for (const url of urls) {
                        // Check if this is a sitemap index (contains other sitemaps)
                        if (url.endsWith('.xml') && (url.includes('sitemap') || url.includes('index'))) {
                            const nestedEndpoints = await this.parseSitemaps([url], maxDepth, timeout, currentDepth + 1);
                            endpoints.push(...nestedEndpoints);
                        } else if (this.looksLikeAPIPath(url)) {
                            // Extract path from URL
                            const urlObj = new URL(url);
                            const path = urlObj.pathname + urlObj.search;
                            
                            endpoints.push({
                                path: path,
                                method: 'GET',
                                url: url,
                                discoveredBy: ['sitemap'],
                                description: 'Found in sitemap',
                                timestamp: new Date().toISOString()
                            });
                        }
                    }
                }
                
            } catch (error: any) {
                this.loggerInstance.debug('Failed to parse sitemap', {
                    sitemapUrl,
                    error: error.message
                });
            }
        }
        
        return endpoints;
    }
    
    private extractUrlsFromSitemap(sitemapContent: string): string[] {
        const urls: string[] = [];
        
        // Handle XML sitemaps
        if (sitemapContent.includes('<urlset') || sitemapContent.includes('<sitemapindex')) {
            // Extract URLs from <loc> tags
            const locRegex = /<loc>(.*?)<\/loc>/gi;
            let match;
            
            while ((match = locRegex.exec(sitemapContent)) !== null) {
                const url = match[1].trim();
                if (url) {
                    urls.push(url);
                }
            }
        } else {
            // Handle text sitemaps
            const lines = sitemapContent.split('\n');
            for (const line of lines) {
                const trimmedLine = line.trim();
                if (trimmedLine && (trimmedLine.startsWith('http://') || trimmedLine.startsWith('https://'))) {
                    urls.push(trimmedLine);
                }
            }
        }
        
        return urls;
    }
    
    private looksLikeAPIPath(path: string): boolean {
        // Check if path looks like an API endpoint
        const apiPatterns = [
            /\/api\//i,
            /\/rest\//i,
            /\/v\d+\//i,
            /\.json$/i,
            /\.xml$/i,
            /\/graphql/i,
            /\/webhook/i,
            /\/callback/i
        ];
        
        return apiPatterns.some(pattern => pattern.test(path)) ||
               // Common API keywords
               /\/(users?|accounts?|auth|login|register|profile|data|items?|products?|orders?|admin|settings|config|search|upload|download)(\?|\/|$)/i.test(path);
    }
} 