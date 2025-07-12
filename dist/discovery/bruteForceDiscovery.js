"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.BruteForceDiscovery = void 0;
const axios_1 = __importDefault(require("axios"));
const logger_1 = require("../utils/logger");
class BruteForceDiscovery {
    constructor() {
        this.loggerInstance = logger_1.logger;
        // Common API endpoint patterns
        this.commonEndpoints = [
            // Basic CRUD patterns
            '/api/users', '/api/user', '/users', '/user',
            '/api/accounts', '/api/account', '/accounts', '/account',
            '/api/auth', '/auth', '/login', '/logout', '/register',
            '/api/profile', '/profile', '/me',
            // Data endpoints
            '/api/data', '/data', '/api/items', '/items',
            '/api/products', '/products', '/api/orders', '/orders',
            '/api/posts', '/posts', '/api/comments', '/comments',
            // Admin/Management
            '/api/admin', '/admin', '/api/dashboard', '/dashboard',
            '/api/settings', '/settings', '/api/config', '/config',
            '/api/system', '/system', '/api/health', '/health',
            // File operations
            '/api/files', '/files', '/api/upload', '/upload',
            '/api/download', '/download', '/api/images', '/images',
            // Search and filtering
            '/api/search', '/search', '/api/filter', '/filter',
            '/api/list', '/list', '/api/find', '/find',
            // Versioned APIs
            '/api/v1', '/api/v2', '/api/v3', '/v1', '/v2', '/v3',
            '/api/v1/users', '/api/v2/users', '/v1/users', '/v2/users',
            // Framework-specific patterns
            // Laravel
            '/api/resources', '/resources',
            // Django REST
            '/api/viewsets', '/viewsets',
            // Express.js
            '/api/routes', '/routes',
            // Spring Boot
            '/actuator', '/actuator/health', '/actuator/info',
            '/api/rest', '/rest',
            // FastAPI
            '/docs', '/redoc', '/openapi.json',
            // Common API docs
            '/api-docs', '/api/docs', '/documentation',
            '/swagger', '/api/swagger'
        ];
        // HTTP methods to test
        this.httpMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];
    }
    async discoverEndpoints(baseUrl, options = {}, progressCallback) {
        const { timeout = 10000, maxConcurrent = 5, testMethods = this.httpMethods } = options;
        this.loggerInstance.info('Starting brute force endpoint discovery', { baseUrl });
        const endpoints = [];
        const total = this.commonEndpoints.length * testMethods.length;
        let completed = 0;
        // Create test combinations
        const testCombinations = [];
        for (const path of this.commonEndpoints) {
            for (const method of testMethods) {
                testCombinations.push({ path, method });
            }
        }
        // Process in batches for concurrency control
        for (let i = 0; i < testCombinations.length; i += maxConcurrent) {
            const batch = testCombinations.slice(i, i + maxConcurrent);
            const batchPromises = batch.map(async ({ path, method }) => {
                try {
                    const fullUrl = this.normalizeUrl(baseUrl, path);
                    const response = await (0, axios_1.default)({
                        method: method.toLowerCase(),
                        url: fullUrl,
                        timeout,
                        validateStatus: (status) => status < 500, // Accept all non-server-error responses
                        headers: {
                            'User-Agent': 'API-Security-Scanner/1.0',
                            'Accept': 'application/json, text/plain, */*'
                        }
                    });
                    // Consider endpoint found if it responds with non-404/405
                    if (response.status !== 404 && response.status !== 405) {
                        const endpoint = {
                            path,
                            method,
                            url: fullUrl,
                            discoveredBy: ['brute-force'],
                            response: {
                                statusCode: response.status,
                                headers: this.sanitizeHeaders(response.headers),
                                contentType: response.headers['content-type'] || 'unknown'
                            },
                            timestamp: new Date().toISOString()
                        };
                        // Try to extract parameters from response
                        if (response.data && typeof response.data === 'object') {
                            endpoint.parameters = this.extractParametersFromResponse(response.data);
                        }
                        // Detect authentication requirements
                        if (response.status === 401) {
                            endpoint.authentication = {
                                required: true,
                                type: this.detectAuthType(response.headers)
                            };
                        }
                        endpoints.push(endpoint);
                        this.loggerInstance.debug('Found endpoint via brute force', {
                            method,
                            path,
                            status: response.status
                        });
                    }
                }
                catch (error) {
                    // Log errors for debugging but don't fail the whole discovery
                    this.loggerInstance.debug('Brute force request failed', {
                        method,
                        path,
                        error: error.message
                    });
                }
                completed++;
                if (progressCallback) {
                    progressCallback({
                        phase: 'brute-force-discovery',
                        percentage: (completed / total) * 100,
                        currentOperation: `Testing ${method} ${path}`
                    });
                }
            });
            await Promise.all(batchPromises);
        }
        this.loggerInstance.info('Brute force discovery completed', {
            baseUrl,
            endpointsFound: endpoints.length,
            totalTested: total
        });
        return endpoints;
    }
    normalizeUrl(baseUrl, path) {
        const cleanBase = baseUrl.replace(/\/$/, '');
        const cleanPath = path.startsWith('/') ? path : `/${path}`;
        return `${cleanBase}${cleanPath}`;
    }
    sanitizeHeaders(headers) {
        const sanitized = {};
        const relevantHeaders = [
            'content-type', 'content-length', 'server', 'x-powered-by',
            'access-control-allow-origin', 'cache-control', 'expires'
        ];
        for (const header of relevantHeaders) {
            if (headers[header]) {
                sanitized[header] = headers[header];
            }
        }
        return sanitized;
    }
    extractParametersFromResponse(data) {
        const parameters = [];
        if (Array.isArray(data) && data.length > 0) {
            // If response is an array, analyze first item
            data = data[0];
        }
        if (typeof data === 'object' && data !== null) {
            for (const [key, value] of Object.entries(data)) {
                parameters.push({
                    name: key,
                    type: typeof value,
                    required: false // Can't determine from response
                });
            }
        }
        return parameters;
    }
    detectAuthType(headers) {
        const authHeader = headers['www-authenticate'] || headers['WWW-Authenticate'];
        if (authHeader) {
            if (authHeader.toLowerCase().includes('bearer')) {
                return 'Bearer';
            }
            else if (authHeader.toLowerCase().includes('basic')) {
                return 'Basic';
            }
            else if (authHeader.toLowerCase().includes('digest')) {
                return 'Digest';
            }
        }
        return 'Unknown';
    }
}
exports.BruteForceDiscovery = BruteForceDiscovery;
//# sourceMappingURL=bruteForceDiscovery.js.map