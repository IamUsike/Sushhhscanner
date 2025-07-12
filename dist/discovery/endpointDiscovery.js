"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.EndpointDiscovery = void 0;
const axios_1 = __importDefault(require("axios"));
const url_1 = require("url");
const logger_1 = require("../utils/logger");
const swaggerDiscovery_1 = require("./swaggerDiscovery");
const passiveCrawler_1 = require("./passiveCrawler");
const bruteForceDiscovery_1 = require("./bruteForceDiscovery");
const robotsParser_1 = require("./robotsParser");
class EndpointDiscovery {
    constructor(target, options = {}) {
        this.discoveredEndpoints = new Map();
        this.errors = [];
        this.target = target;
        this.options = {
            maxEndpoints: 1000,
            timeout: 30000,
            includeSwagger: true,
            includeCrawling: true,
            includeBruteForce: true,
            includeRobots: true,
            userAgent: 'API-Risk-Visualizer/1.0',
            ...options,
        };
        // Initialize discovery modules
        this.swaggerDiscovery = new swaggerDiscovery_1.SwaggerDiscovery(target, this.options);
        this.passiveCrawler = new passiveCrawler_1.PassiveCrawler(target, this.options);
        this.bruteForceDiscovery = new bruteForceDiscovery_1.BruteForceDiscovery();
        this.robotsParser = new robotsParser_1.RobotsParser();
    }
    async discover(scanId, progressCallback) {
        const startTime = Date.now();
        logger_1.logger.info(`Starting endpoint discovery for ${this.target.baseUrl}`, { scanId });
        try {
            // Phase 1: Basic reconnaissance
            await this.updateProgress(5, 'Starting reconnaissance', progressCallback);
            await this.basicReconnaissance();
            // Phase 2: Manual endpoints (if provided)
            if (this.target.endpoints && this.target.endpoints.length > 0) {
                await this.updateProgress(10, 'Processing manual endpoints', progressCallback, { count: this.target.endpoints.length });
                await this.processManualEndpoints();
            }
            // Phase 3: Swagger/OpenAPI discovery
            if (this.options.includeSwagger) {
                await this.updateProgress(20, 'Discovering Swagger/OpenAPI endpoints', progressCallback);
                await this.discoverSwaggerEndpoints(scanId);
            }
            // Phase 4: Robots.txt parsing
            if (this.options.includeRobots) {
                await this.updateProgress(30, 'Parsing robots.txt for endpoints', progressCallback);
                await this.discoverRobotsEndpoints(scanId);
            }
            // Phase 5: Passive crawling
            if (this.options.includeCrawling) {
                await this.updateProgress(50, 'Passive crawling for endpoints', progressCallback);
                await this.discoverCrawlingEndpoints(scanId);
            }
            // Phase 6: Brute force discovery
            if (this.options.includeBruteForce) {
                await this.updateProgress(70, 'Brute force endpoint discovery', progressCallback);
                await this.discoverBruteForceEndpoints(scanId);
            }
            // Phase 7: Endpoint analysis and enrichment
            await this.updateProgress(90, 'Analyzing and enriching endpoints', progressCallback);
            await this.analyzeEndpoints();
            // Phase 8: Final cleanup and validation
            await this.updateProgress(95, 'Validating discovered endpoints', progressCallback);
            await this.validateEndpoints();
            const duration = Date.now() - startTime;
            const result = this.buildResult(duration);
            await this.updateProgress(100, 'Endpoint discovery completed', progressCallback, {
                totalFound: result.totalFound,
                duration: `${Math.round(duration / 1000)}s`,
            });
            logger_1.logger.info(`Endpoint discovery completed for ${this.target.baseUrl}`, {
                scanId,
                totalFound: result.totalFound,
                duration,
                methods: result.discoveryMethods,
            });
            return result;
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            this.errors.push(`Discovery failed: ${errorMessage}`);
            logger_1.logger.error(`Endpoint discovery failed for ${this.target.baseUrl}:`, error);
            const duration = Date.now() - startTime;
            return this.buildResult(duration);
        }
    }
    async updateProgress(progress, step, callback, details) {
        if (callback) {
            callback(progress, step, details);
        }
    }
    async basicReconnaissance() {
        try {
            // Check if target is reachable
            const response = await this.makeRequest('GET', '/');
            // Extract basic information about the target
            const serverHeader = response.headers['server'];
            const poweredBy = response.headers['x-powered-by'];
            const framework = this.detectFramework(response);
            logger_1.logger.info('Basic reconnaissance completed', {
                target: this.target.baseUrl,
                server: serverHeader,
                poweredBy,
                framework,
                statusCode: response.status,
            });
        }
        catch (error) {
            this.errors.push(`Basic reconnaissance failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
    detectFramework(response) {
        const headers = response.headers;
        const body = typeof response.data === 'string' ? response.data : '';
        // Common framework detection patterns
        if (headers['x-powered-by']?.includes('Express'))
            return 'Express.js';
        if (headers['server']?.includes('nginx'))
            return 'Nginx';
        if (headers['server']?.includes('Apache'))
            return 'Apache';
        if (body.includes('Laravel'))
            return 'Laravel';
        if (body.includes('Django'))
            return 'Django';
        if (body.includes('Rails'))
            return 'Ruby on Rails';
        if (headers['x-aspnet-version'])
            return 'ASP.NET';
        return undefined;
    }
    async processManualEndpoints() {
        if (!this.target.endpoints)
            return;
        for (const endpoint of this.target.endpoints) {
            try {
                const endpointInfo = await this.analyzeEndpoint(endpoint, 'GET', 'manual');
                this.addEndpoint(endpointInfo);
            }
            catch (error) {
                this.errors.push(`Failed to process manual endpoint ${endpoint}: ${error instanceof Error ? error.message : 'Unknown error'}`);
            }
        }
    }
    async discoverSwaggerEndpoints(scanId) {
        try {
            const swaggerEndpoints = await this.swaggerDiscovery.discover();
            for (const endpoint of swaggerEndpoints) {
                this.addEndpoint(endpoint);
            }
            (0, logger_1.logScanProgress)(scanId, 'swagger_discovery', 20, {
                endpointsFound: swaggerEndpoints.length,
            });
        }
        catch (error) {
            this.errors.push(`Swagger discovery failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
    async discoverRobotsEndpoints(scanId) {
        try {
            const robotsEndpoints = await this.robotsParser.discoverEndpoints(this.target.baseUrl, this.options);
            for (const apiEndpoint of robotsEndpoints) {
                // Convert APIEndpoint to EndpointInfo
                const endpoint = {
                    url: apiEndpoint.url,
                    method: apiEndpoint.method,
                    parameters: apiEndpoint.parameters?.map(p => ({
                        name: p.name,
                        type: 'query',
                        dataType: p.type,
                        required: p.required || false,
                        example: undefined
                    })) || [],
                    authentication: {
                        required: apiEndpoint.authentication?.required || false,
                        methods: apiEndpoint.authentication?.type ? [apiEndpoint.authentication.type] : [],
                        tested: false,
                        bypassed: false
                    },
                    discoveryMethod: 'robots',
                    responseTypes: apiEndpoint.response?.contentType ? [apiEndpoint.response.contentType] : []
                };
                this.addEndpoint(endpoint);
            }
            (0, logger_1.logScanProgress)(scanId, 'robots_discovery', 30, {
                endpointsFound: robotsEndpoints.length,
            });
        }
        catch (error) {
            this.errors.push(`Robots.txt discovery failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
    async discoverCrawlingEndpoints(scanId) {
        try {
            const crawledEndpoints = await this.passiveCrawler.discover();
            for (const endpoint of crawledEndpoints) {
                this.addEndpoint(endpoint);
            }
            (0, logger_1.logScanProgress)(scanId, 'crawling_discovery', 50, {
                endpointsFound: crawledEndpoints.length,
            });
        }
        catch (error) {
            this.errors.push(`Passive crawling failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
    async discoverBruteForceEndpoints(scanId) {
        try {
            const bruteForceEndpoints = await this.bruteForceDiscovery.discoverEndpoints(this.target.baseUrl, this.options);
            for (const apiEndpoint of bruteForceEndpoints) {
                // Convert APIEndpoint to EndpointInfo
                const endpoint = {
                    url: apiEndpoint.url,
                    method: apiEndpoint.method,
                    parameters: apiEndpoint.parameters?.map(p => ({
                        name: p.name,
                        type: 'query',
                        dataType: p.type,
                        required: p.required || false,
                        example: undefined
                    })) || [],
                    authentication: {
                        required: apiEndpoint.authentication?.required || false,
                        methods: apiEndpoint.authentication?.type ? [apiEndpoint.authentication.type] : [],
                        tested: false,
                        bypassed: false
                    },
                    discoveryMethod: 'brute-force',
                    responseTypes: apiEndpoint.response?.contentType ? [apiEndpoint.response.contentType] : []
                };
                this.addEndpoint(endpoint);
            }
            (0, logger_1.logScanProgress)(scanId, 'bruteforce_discovery', 70, {
                endpointsFound: bruteForceEndpoints.length,
            });
        }
        catch (error) {
            this.errors.push(`Brute force discovery failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
    async analyzeEndpoints() {
        const endpoints = Array.from(this.discoveredEndpoints.values());
        for (const endpoint of endpoints) {
            try {
                // Enhance endpoint with additional analysis
                await this.enhanceEndpointInfo(endpoint);
            }
            catch (error) {
                // Non-critical error, just log it
                logger_1.logger.warn(`Failed to enhance endpoint ${endpoint.url}:`, error);
            }
        }
    }
    async enhanceEndpointInfo(endpoint) {
        try {
            // Test different HTTP methods
            const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];
            const allowedMethods = [];
            for (const method of methods) {
                try {
                    const response = await this.makeRequest(method, endpoint.url, { timeout: 5000 });
                    if (response.status < 405) { // Not "Method Not Allowed"
                        allowedMethods.push(method);
                    }
                }
                catch (error) {
                    // Method not allowed or other error, skip
                }
            }
            // Update endpoint with discovered methods
            if (allowedMethods.length > 0) {
                endpoint.method = allowedMethods[0]; // Primary method
            }
            // Analyze response types
            try {
                const response = await this.makeRequest('GET', endpoint.url);
                const contentType = response.headers['content-type'] || '';
                if (contentType.includes('json')) {
                    endpoint.responseTypes = ['application/json'];
                }
                else if (contentType.includes('xml')) {
                    endpoint.responseTypes = ['application/xml'];
                }
                else if (contentType.includes('html')) {
                    endpoint.responseTypes = ['text/html'];
                }
            }
            catch (error) {
                // Non-critical error
            }
        }
        catch (error) {
            // Non-critical error
        }
    }
    async validateEndpoints() {
        const endpoints = Array.from(this.discoveredEndpoints.values());
        const validatedEndpoints = new Map();
        for (const endpoint of endpoints) {
            try {
                // Quick validation request
                const response = await this.makeRequest('HEAD', endpoint.url, { timeout: 5000 });
                // If we get a response, endpoint is valid
                if (response.status < 500) {
                    validatedEndpoints.set(this.getEndpointKey(endpoint), endpoint);
                }
            }
            catch (error) {
                // Endpoint might not be accessible, but keep it for now
                validatedEndpoints.set(this.getEndpointKey(endpoint), endpoint);
            }
        }
        this.discoveredEndpoints = validatedEndpoints;
    }
    async analyzeEndpoint(url, method, discoveryMethod) {
        const endpointInfo = {
            url,
            method,
            parameters: [],
            authentication: {
                required: false,
                methods: [],
                tested: false,
                bypassed: false,
            },
            discoveryMethod: discoveryMethod,
            responseTypes: [],
        };
        try {
            // Basic endpoint analysis
            const response = await this.makeRequest(method, url);
            // Extract parameters from URL
            endpointInfo.parameters = this.extractUrlParameters(url);
            // Basic authentication detection
            endpointInfo.authentication = this.analyzeAuthentication(response);
            return endpointInfo;
        }
        catch (error) {
            // Return basic endpoint info even if analysis fails
            return endpointInfo;
        }
    }
    extractUrlParameters(url) {
        const parameters = [];
        try {
            const urlObj = new url_1.URL(url, this.target.baseUrl);
            // Extract query parameters
            urlObj.searchParams.forEach((value, key) => {
                parameters.push({
                    name: key,
                    type: 'query',
                    dataType: this.inferDataType(value),
                    required: false,
                    example: value,
                });
            });
            // Extract path parameters (simplified detection)
            const pathSegments = urlObj.pathname.split('/');
            pathSegments.forEach((segment, index) => {
                if (segment.includes('{') || segment.includes(':') || /^\d+$/.test(segment)) {
                    parameters.push({
                        name: segment.replace(/[{}:]/g, '') || `param${index}`,
                        type: 'path',
                        dataType: /^\d+$/.test(segment) ? 'integer' : 'string',
                        required: true,
                        example: segment,
                    });
                }
            });
        }
        catch (error) {
            // Invalid URL, skip parameter extraction
        }
        return parameters;
    }
    inferDataType(value) {
        if (/^\d+$/.test(value))
            return 'integer';
        if (/^\d+\.\d+$/.test(value))
            return 'number';
        if (/^(true|false)$/i.test(value))
            return 'boolean';
        if (/^\d{4}-\d{2}-\d{2}/.test(value))
            return 'date';
        return 'string';
    }
    analyzeAuthentication(response) {
        const authInfo = {
            required: false,
            methods: [],
            tested: false,
            bypassed: false,
        };
        // Check for authentication indicators
        if (response.status === 401 || response.status === 403) {
            authInfo.required = true;
        }
        // Check WWW-Authenticate header
        const wwwAuth = response.headers['www-authenticate'];
        if (wwwAuth) {
            authInfo.required = true;
            authInfo.methods = authInfo.methods || [];
            if (wwwAuth.includes('Bearer'))
                authInfo.methods.push('Bearer');
            if (wwwAuth.includes('Basic'))
                authInfo.methods.push('Basic');
            if (wwwAuth.includes('Digest'))
                authInfo.methods.push('Digest');
        }
        // Check for common authentication patterns in response
        const responseText = typeof response.data === 'string' ? response.data : '';
        if (responseText.includes('login') || responseText.includes('unauthorized')) {
            authInfo.required = true;
        }
        return authInfo;
    }
    addEndpoint(endpoint) {
        const key = this.getEndpointKey(endpoint);
        // Check if we've reached the maximum number of endpoints
        if (this.discoveredEndpoints.size >= (this.options.maxEndpoints || 1000)) {
            return;
        }
        // Check exclude patterns
        if (this.shouldExcludeEndpoint(endpoint.url)) {
            return;
        }
        // Add or update endpoint
        const existing = this.discoveredEndpoints.get(key);
        if (existing) {
            // Merge information from different discovery methods
            this.mergeEndpointInfo(existing, endpoint);
        }
        else {
            this.discoveredEndpoints.set(key, endpoint);
        }
    }
    getEndpointKey(endpoint) {
        return `${endpoint.method}:${endpoint.url}`;
    }
    shouldExcludeEndpoint(url) {
        if (!this.options.excludePatterns)
            return false;
        return this.options.excludePatterns.some(pattern => {
            try {
                const regex = new RegExp(pattern);
                return regex.test(url);
            }
            catch (error) {
                // Invalid regex pattern, treat as literal string
                return url.includes(pattern);
            }
        });
    }
    mergeEndpointInfo(existing, newInfo) {
        // Merge parameters
        newInfo.parameters.forEach(param => {
            if (!existing.parameters.find(p => p.name === param.name && p.type === param.type)) {
                existing.parameters.push(param);
            }
        });
        // Merge authentication methods
        if (newInfo.authentication.methods) {
            existing.authentication.methods = existing.authentication.methods || [];
            newInfo.authentication.methods.forEach(method => {
                if (!existing.authentication.methods.includes(method)) {
                    existing.authentication.methods.push(method);
                }
            });
        }
        // Update authentication requirement
        if (newInfo.authentication.required) {
            existing.authentication.required = true;
        }
        // Merge response types
        newInfo.responseTypes.forEach(type => {
            if (!existing.responseTypes.includes(type)) {
                existing.responseTypes.push(type);
            }
        });
    }
    async makeRequest(method, path, options = {}) {
        const url = new url_1.URL(path, this.target.baseUrl).toString();
        const requestConfig = {
            method,
            url,
            timeout: this.options.timeout || 30000,
            headers: {
                'User-Agent': this.options.userAgent || 'API-Risk-Visualizer/1.0',
                ...this.target.headers,
            },
            validateStatus: () => true, // Don't throw on any status code
            ...options,
        };
        // Add authentication if provided
        if (this.target.authMethod !== 'none' && this.target.authToken) {
            switch (this.target.authMethod) {
                case 'bearer':
                    requestConfig.headers['Authorization'] = `Bearer ${this.target.authToken}`;
                    break;
                case 'basic':
                    if (this.target.authUsername && this.target.authPassword) {
                        const credentials = Buffer.from(`${this.target.authUsername}:${this.target.authPassword}`).toString('base64');
                        requestConfig.headers['Authorization'] = `Basic ${credentials}`;
                    }
                    break;
                case 'api-key':
                    requestConfig.headers['X-API-Key'] = this.target.authToken;
                    break;
            }
        }
        return (0, axios_1.default)(requestConfig);
    }
    buildResult(duration) {
        const endpoints = Array.from(this.discoveredEndpoints.values());
        // Count endpoints by discovery method
        const methodCounts = {
            swagger: 0,
            crawling: 0,
            bruteForce: 0,
            robots: 0,
            manual: 0,
        };
        endpoints.forEach(endpoint => {
            switch (endpoint.discoveryMethod) {
                case 'swagger':
                    methodCounts.swagger++;
                    break;
                case 'crawling':
                    methodCounts.crawling++;
                    break;
                case 'brute-force':
                    methodCounts.bruteForce++;
                    break;
                case 'manual':
                    methodCounts.manual++;
                    break;
                default:
                    methodCounts.robots++;
            }
        });
        return {
            endpoints,
            discoveryMethods: methodCounts,
            totalFound: endpoints.length,
            duration,
            errors: this.errors,
        };
    }
}
exports.EndpointDiscovery = EndpointDiscovery;
//# sourceMappingURL=endpointDiscovery.js.map