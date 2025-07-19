"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.EndpointDiscovery = void 0;
const logger_1 = require("../utils/logger");
const swaggerDiscovery_1 = require("./swaggerDiscovery");
const passiveCrawler_1 = require("./passiveCrawler"); // Keep import for type inference
const bruteForceDiscovery_1 = require("./bruteForceDiscovery");
const robotsParser_1 = require("./robotsParser");
const url_1 = require("url");
class EndpointDiscovery {
    constructor(target, options = {}) {
        this.target = target;
        this.options = {
            includeSwagger: true,
            includeCrawling: true,
            includeBruteForce: true,
            includeRobots: true,
            ...options,
        };
        this.swaggerDiscovery = new swaggerDiscovery_1.SwaggerDiscovery(this.target, this.options);
        this.bruteForceDiscovery = new bruteForceDiscovery_1.BruteForceDiscovery();
        this.robotsParser = new robotsParser_1.RobotsParser();
    }
    async discover(scanId, progressCallback, emitEndpoint, emitVulnerability) {
        const updateProgress = (progress, step, details = {}) => {
            progressCallback(progress, step, details);
        };
        updateProgress(0, 'Starting discovery...');
        const allEndpoints = new Map();
        const discoveryMethods = { swagger: 0, crawling: 0, bruteForce: 0, robots: 0 };
        const startTime = Date.now();
        const addAndEmit = (endpoint, method) => {
            if (!allEndpoints.has(endpoint.url)) {
                allEndpoints.set(endpoint.url, endpoint);
                discoveryMethods[method]++;
                emitEndpoint(endpoint);
            }
        };
        // Instantiate PassiveCrawler here, as emitVulnerability is available
        const passiveCrawlerInstance = new passiveCrawler_1.PassiveCrawler(this.target, this.options, emitVulnerability);
        if (this.options.includeSwagger) {
            updateProgress(10, 'Searching for Swagger/OpenAPI specifications...');
            try {
                const swaggerEndpoints = await this.swaggerDiscovery.discover();
                swaggerEndpoints.forEach(ep => addAndEmit(this.mapEndpointInfoToAPIEndpoint(ep, 'swagger'), 'swagger'));
                updateProgress(25, `Swagger discovery completed`);
            }
            catch (error) {
                logger_1.logger.warn('Swagger discovery failed:', { error: error.message });
            }
        }
        if (this.options.includeRobots) {
            updateProgress(30, 'Parsing robots.txt and sitemaps...');
            try {
                const robotsEndpoints = await this.robotsParser.discoverEndpoints(this.target.baseUrl);
                robotsEndpoints.forEach(ep => addAndEmit(ep, 'robots'));
                updateProgress(40, `Robots.txt discovery completed`);
            }
            catch (error) {
                logger_1.logger.warn('Robots.txt parsing failed:', { error: error.message });
            }
        }
        if (this.options.includeCrawling) {
            updateProgress(45, 'Starting passive crawl...');
            try {
                const crawlerEndpoints = await passiveCrawlerInstance.discover(); // Use the new instance
                crawlerEndpoints.forEach(ep => addAndEmit(this.mapEndpointInfoToAPIEndpoint(ep, 'crawling'), 'crawling'));
                updateProgress(65, `Passive crawl completed`);
            }
            catch (error) {
                logger_1.logger.warn('Passive crawling failed:', { error: error.message });
            }
        }
        if (this.options.includeBruteForce) {
            updateProgress(70, 'Starting brute force discovery...');
            try {
                await this.bruteForceDiscovery.discoverEndpoints(this.target.baseUrl, {}, (progressUpdate) => {
                    const overallProgress = 70 + Math.round(progressUpdate.percentage * 0.25);
                    updateProgress(overallProgress, progressUpdate.currentOperation);
                }, (ep) => addAndEmit(ep, 'bruteForce') // Real-time emission
                );
                updateProgress(95, `Brute force discovery completed`);
            }
            catch (error) {
                logger_1.logger.warn('Brute force discovery failed:', { error: error.message });
            }
        }
        updateProgress(100, 'All discovery methods complete.');
        const duration = Date.now() - startTime;
        const finalEndpoints = Array.from(allEndpoints.values());
        logger_1.logger.info(`Endpoint discovery completed for ${this.target.baseUrl}`, { scanId, totalFound: finalEndpoints.length, duration, methods: discoveryMethods });
        return {
            endpoints: finalEndpoints,
            totalFound: finalEndpoints.length,
            duration,
            discoveryMethods,
            errors: [],
        };
    }
    mapEndpointInfoToAPIEndpoint(info, method) {
        // Ensure the authentication object has a 'type' property
        const auth = info.authentication || { required: false };
        const authWithType = { ...auth, type: auth.required ? 'unknown' : 'none' }; // Default type if not specified
        return {
            path: new url_1.URL(info.url).pathname,
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
exports.EndpointDiscovery = EndpointDiscovery;
//# sourceMappingURL=endpointDiscovery.js.map