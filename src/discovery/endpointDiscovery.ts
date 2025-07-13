import { logger } from '../utils/logger';
import { APIEndpoint, ScanTarget, EndpointInfo, Vulnerability } from '../types';
import { SwaggerDiscovery } from './swaggerDiscovery';
import { PassiveCrawler } from './passiveCrawler'; // Keep import for type inference
import { BruteForceDiscovery } from './bruteForceDiscovery';
import { RobotsParser } from './robotsParser';
import { URL } from 'url';

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

export class EndpointDiscovery {
  private target: ScanTarget;
  private options: DiscoveryOptions;
  private swaggerDiscovery: SwaggerDiscovery;
  private bruteForceDiscovery: BruteForceDiscovery;
  private robotsParser: RobotsParser;

  constructor(target: ScanTarget, options: DiscoveryOptions = {}) {
    this.target = target;
    this.options = {
      includeSwagger: true,
      includeCrawling: true,
      includeBruteForce: true,
      includeRobots: true,
      ...options,
    };
        this.swaggerDiscovery = new SwaggerDiscovery(this.target, this.options);
    this.bruteForceDiscovery = new BruteForceDiscovery();
    this.robotsParser = new RobotsParser();
  }

    async discover(
        scanId: string,
        progressCallback: (progress: number, step: string, details?: any) => void,
        emitEndpoint: (endpoint: APIEndpoint) => void,
        emitVulnerability: (vulnerability: Vulnerability) => void
    ): Promise<DiscoveryResult> {
        const updateProgress = (progress: number, step: string, details = {}) => {
            progressCallback(progress, step, details);
        };
        updateProgress(0, 'Starting discovery...');

        const allEndpoints = new Map<string, APIEndpoint>();
        const discoveryMethods = { swagger: 0, crawling: 0, bruteForce: 0, robots: 0 };
        const startTime = Date.now();

        const addAndEmit = (endpoint: APIEndpoint, method: keyof typeof discoveryMethods) => {
            if (!allEndpoints.has(endpoint.url)) {
                allEndpoints.set(endpoint.url, endpoint);
                discoveryMethods[method]++;
                emitEndpoint(endpoint);
      }
        };

        // Instantiate PassiveCrawler here, as emitVulnerability is available
        const passiveCrawlerInstance = new PassiveCrawler(this.target, this.options, emitVulnerability);

        if (this.options.includeSwagger) {
            updateProgress(10, 'Searching for Swagger/OpenAPI specifications...');
    try {
                const swaggerEndpoints = await this.swaggerDiscovery.discover();
                swaggerEndpoints.forEach(ep => addAndEmit(this.mapEndpointInfoToAPIEndpoint(ep, 'swagger'), 'swagger'));
                updateProgress(25, `Swagger discovery completed`);
      } catch (error) {
                logger.warn('Swagger discovery failed:', { error: (error as Error).message });
      }
    }

        if (this.options.includeRobots) {
            updateProgress(30, 'Parsing robots.txt and sitemaps...');
        try {
                const robotsEndpoints = await this.robotsParser.discoverEndpoints(this.target.baseUrl);
                robotsEndpoints.forEach(ep => addAndEmit(ep, 'robots'));
                updateProgress(40, `Robots.txt discovery completed`);
        } catch (error) {
                logger.warn('Robots.txt parsing failed:', { error: (error as Error).message });
            }
        }
        
        if (this.options.includeCrawling) {
            updateProgress(45, 'Starting passive crawl...');
            try {
                const crawlerEndpoints = await passiveCrawlerInstance.discover(); // Use the new instance
                crawlerEndpoints.forEach(ep => addAndEmit(this.mapEndpointInfoToAPIEndpoint(ep, 'crawling'), 'crawling'));
                updateProgress(65, `Passive crawl completed`);
    } catch (error) {
                logger.warn('Passive crawling failed:', { error: (error as Error).message });
    }
  }

        if (this.options.includeBruteForce) {
            updateProgress(70, 'Starting brute force discovery...');
    try {
                await this.bruteForceDiscovery.discoverEndpoints(
                    this.target.baseUrl,
                    {},
                    (progressUpdate) => {
                        const overallProgress = 70 + Math.round(progressUpdate.percentage * 0.25);
                        updateProgress(overallProgress, progressUpdate.currentOperation);
                    },
                    (ep) => addAndEmit(ep, 'bruteForce') // Real-time emission
                );
                updateProgress(95, `Brute force discovery completed`);
    } catch (error) {
                logger.warn('Brute force discovery failed:', { error: (error as Error).message });
            }
        }

        updateProgress(100, 'All discovery methods complete.');
        const duration = Date.now() - startTime;
        const finalEndpoints = Array.from(allEndpoints.values());

        logger.info(`Endpoint discovery completed for ${this.target.baseUrl}`, { scanId, totalFound: finalEndpoints.length, duration, methods: discoveryMethods });

        return {
            endpoints: finalEndpoints,
            totalFound: finalEndpoints.length,
            duration,
            discoveryMethods,
            errors: [],
        };
  }

    private mapEndpointInfoToAPIEndpoint(info: EndpointInfo, method: string): APIEndpoint {
        // Ensure the authentication object has a 'type' property
        const auth = info.authentication || { required: false };
        const authWithType = { ...auth, type: auth.required ? 'unknown' : 'none' }; // Default type if not specified

        return {
            path: new URL(info.url).pathname,
            url: info.url,
            method: info.method,
            discoveredBy: [method],
            timestamp: new Date().toISOString(),
            parameters: info.parameters || [],
            authentication: authWithType,
            response: {
                statusCode: 0,
                headers: {},
                contentType: 'unknown'
            }
    };
  }
} 