"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.SwaggerDiscovery = void 0;
const axios_1 = __importDefault(require("axios"));
const url_1 = require("url");
const logger_1 = require("../utils/logger");
class SwaggerDiscovery {
    constructor(target, options) {
        this.commonSwaggerPaths = [
            '/swagger.json',
            '/swagger.yaml',
            '/swagger.yml',
            '/openapi.json',
            '/openapi.yaml',
            '/openapi.yml',
            '/api-docs',
            '/api-docs.json',
            '/api/docs',
            '/api/swagger',
            '/api/swagger.json',
            '/api/openapi.json',
            '/docs/swagger.json',
            '/v1/swagger.json',
            '/v2/swagger.json',
            '/v3/swagger.json',
            '/swagger/v1/swagger.json',
            '/swagger/docs',
            '/api/v1/swagger.json',
            '/api/v2/swagger.json',
            '/api/v3/swagger.json',
            '/.well-known/openapi.json',
            '/redoc',
            '/swagger-ui.html',
            '/swagger-ui/',
            '/docs/',
            '/api-docs/',
        ];
        this.target = target;
        this.options = options;
    }
    async discover() {
        const endpoints = [];
        logger_1.logger.info(`Starting Swagger/OpenAPI discovery for ${this.target.baseUrl}`);
        try {
            // Try user-provided swagger URL first
            if (this.target.swaggerUrl) {
                const swaggerEndpoints = await this.parseSwaggerFromUrl(this.target.swaggerUrl);
                endpoints.push(...swaggerEndpoints);
            }
            // Try common swagger paths
            for (const path of this.commonSwaggerPaths) {
                try {
                    const swaggerUrl = new url_1.URL(path, this.target.baseUrl).toString();
                    const swaggerEndpoints = await this.parseSwaggerFromUrl(swaggerUrl);
                    endpoints.push(...swaggerEndpoints);
                    if (swaggerEndpoints.length > 0) {
                        logger_1.logger.info(`Found Swagger spec at ${swaggerUrl} with ${swaggerEndpoints.length} endpoints`);
                        break; // Found a valid spec, no need to check others
                    }
                }
                catch (error) {
                    // Continue to next path
                }
            }
            // Try to discover swagger URLs through HTML parsing
            const discoveredSwaggerUrls = await this.discoverSwaggerUrlsFromHtml();
            for (const url of discoveredSwaggerUrls) {
                try {
                    const swaggerEndpoints = await this.parseSwaggerFromUrl(url);
                    endpoints.push(...swaggerEndpoints);
                }
                catch (error) {
                    // Continue to next URL
                }
            }
            logger_1.logger.info(`Swagger discovery completed: ${endpoints.length} endpoints found`);
            return this.deduplicateEndpoints(endpoints);
        }
        catch (error) {
            logger_1.logger.error('Swagger discovery failed:', error);
            return endpoints;
        }
    }
    async parseSwaggerFromUrl(swaggerUrl) {
        try {
            const response = await axios_1.default.get(swaggerUrl, {
                timeout: this.options.timeout || 30000,
                headers: {
                    'User-Agent': this.options.userAgent || 'API-Risk-Visualizer/1.0',
                    'Accept': 'application/json, application/yaml, text/yaml, text/plain',
                    ...this.target.headers,
                },
                validateStatus: (status) => status === 200,
            });
            let swaggerSpec;
            // Parse JSON or YAML
            if (typeof response.data === 'object') {
                swaggerSpec = response.data;
            }
            else {
                // Try to parse as JSON first, then YAML
                try {
                    swaggerSpec = JSON.parse(response.data);
                }
                catch (jsonError) {
                    // For YAML parsing, we'd need a YAML library, but for now treat as JSON
                    throw new Error('YAML parsing not implemented - use JSON format');
                }
            }
            return this.parseSwaggerSpec(swaggerSpec);
        }
        catch (error) {
            logger_1.logger.debug(`Failed to parse swagger from ${swaggerUrl}:`, error);
            throw error;
        }
    }
    parseSwaggerSpec(spec) {
        const endpoints = [];
        if (!spec.paths) {
            return endpoints;
        }
        // Determine base URL from spec
        let baseUrl = this.target.baseUrl;
        if (spec.servers && spec.servers.length > 0) {
            // OpenAPI 3.x servers
            const server = spec.servers[0];
            if (server.url.startsWith('http')) {
                baseUrl = server.url;
            }
            else if (server.url.startsWith('/')) {
                baseUrl = new url_1.URL(server.url, this.target.baseUrl).toString();
            }
        }
        else if (spec.swagger && spec.host) {
            // Swagger 2.0 host
            const scheme = spec.schemes?.[0] || 'https';
            const basePath = spec.basePath || '';
            baseUrl = `${scheme}://${spec.host}${basePath}`;
        }
        // Parse paths
        for (const [path, pathItem] of Object.entries(spec.paths)) {
            if (!pathItem || typeof pathItem !== 'object')
                continue;
            for (const [method, operation] of Object.entries(pathItem)) {
                if (!operation || typeof operation !== 'object')
                    continue;
                if (['parameters', 'summary', 'description'].includes(method))
                    continue;
                const endpoint = this.createEndpointFromOperation(baseUrl, path, method.toUpperCase(), operation, pathItem.parameters || []);
                endpoints.push(endpoint);
            }
        }
        return endpoints;
    }
    createEndpointFromOperation(baseUrl, path, method, operation, pathParameters = []) {
        const fullUrl = new url_1.URL(path, baseUrl).toString();
        const endpoint = {
            url: fullUrl,
            method,
            parameters: [],
            authentication: {
                required: false,
                methods: [],
                tested: false,
                bypassed: false,
            },
            discoveryMethod: 'swagger',
            responseTypes: [],
        };
        // Extract parameters
        const allParameters = [...pathParameters, ...(operation.parameters || [])];
        endpoint.parameters = this.parseSwaggerParameters(allParameters);
        // Detect authentication requirements
        endpoint.authentication = this.parseSwaggerAuthentication(operation);
        // Extract response types
        endpoint.responseTypes = this.parseSwaggerResponseTypes(operation);
        return endpoint;
    }
    parseSwaggerParameters(parameters) {
        const params = [];
        for (const param of parameters) {
            if (!param.name)
                continue;
            const paramInfo = {
                name: param.name,
                type: this.mapSwaggerParameterType(param.in),
                dataType: this.mapSwaggerDataType(param.type || param.schema?.type || 'string'),
                required: param.required || false,
                example: param.example || param.default,
            };
            params.push(paramInfo);
        }
        return params;
    }
    mapSwaggerParameterType(swaggerType) {
        switch (swaggerType) {
            case 'query': return 'query';
            case 'path': return 'path';
            case 'header': return 'header';
            case 'body':
            case 'formData': return 'body';
            default: return 'query';
        }
    }
    mapSwaggerDataType(swaggerType) {
        switch (swaggerType) {
            case 'integer': return 'integer';
            case 'number': return 'number';
            case 'boolean': return 'boolean';
            case 'array': return 'array';
            case 'object': return 'object';
            case 'string':
            default: return 'string';
        }
    }
    parseSwaggerAuthentication(operation) {
        const authInfo = {
            required: false,
            methods: [],
            tested: false,
            bypassed: false,
        };
        // Check for security requirements
        const security = operation.security || [];
        if (security.length > 0) {
            authInfo.required = true;
            for (const securityItem of security) {
                for (const securityName of Object.keys(securityItem)) {
                    // Common security scheme names
                    if (securityName.toLowerCase().includes('bearer') || securityName.toLowerCase().includes('jwt')) {
                        authInfo.methods.push('Bearer');
                    }
                    else if (securityName.toLowerCase().includes('basic')) {
                        authInfo.methods.push('Basic');
                    }
                    else if (securityName.toLowerCase().includes('api') && securityName.toLowerCase().includes('key')) {
                        authInfo.methods.push('API-Key');
                    }
                    else {
                        authInfo.methods.push('Unknown');
                    }
                }
            }
        }
        return authInfo;
    }
    parseSwaggerResponseTypes(operation) {
        const responseTypes = [];
        if (operation.responses) {
            for (const [statusCode, response] of Object.entries(operation.responses)) {
                if (typeof response === 'object' && response !== null) {
                    const responseObj = response;
                    // OpenAPI 3.x
                    if (responseObj.content) {
                        responseTypes.push(...Object.keys(responseObj.content));
                    }
                    // Swagger 2.0
                    if (responseObj.produces) {
                        responseTypes.push(...responseObj.produces);
                    }
                }
            }
        }
        // Fallback to operation-level produces (Swagger 2.0)
        if (operation.produces) {
            responseTypes.push(...operation.produces);
        }
        return [...new Set(responseTypes)]; // Remove duplicates
    }
    async discoverSwaggerUrlsFromHtml() {
        const discoveredUrls = [];
        try {
            // Try to get the main page
            const response = await axios_1.default.get(this.target.baseUrl, {
                timeout: this.options.timeout || 30000,
                headers: {
                    'User-Agent': this.options.userAgent || 'API-Risk-Visualizer/1.0',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    ...this.target.headers,
                },
                validateStatus: (status) => status < 400,
            });
            if (typeof response.data === 'string') {
                const html = response.data;
                // Look for common swagger UI patterns
                const swaggerPatterns = [
                    /spec-url["\s]*[:=]["\s]*["']([^"']+)["']/gi,
                    /swagger[_-]?url["\s]*[:=]["\s]*["']([^"']+)["']/gi,
                    /openapi[_-]?url["\s]*[:=]["\s]*["']([^"']+)["']/gi,
                    /url["\s]*[:=]["\s]*["']([^"']*swagger[^"']*)["']/gi,
                    /url["\s]*[:=]["\s]*["']([^"']*openapi[^"']*)["']/gi,
                    /href=["']([^"']*swagger[^"']*)["']/gi,
                    /href=["']([^"']*openapi[^"']*)["']/gi,
                    /src=["']([^"']*swagger[^"']*)["']/gi,
                ];
                for (const pattern of swaggerPatterns) {
                    let match;
                    while ((match = pattern.exec(html)) !== null) {
                        try {
                            const url = new url_1.URL(match[1], this.target.baseUrl).toString();
                            if (!discoveredUrls.includes(url)) {
                                discoveredUrls.push(url);
                            }
                        }
                        catch (error) {
                            // Invalid URL, skip
                        }
                    }
                }
                // Look for meta tags with swagger info
                const metaPatterns = [
                    /<meta[^>]+name=["']swagger[^"']*["'][^>]+content=["']([^"']+)["']/gi,
                    /<meta[^>]+name=["']openapi[^"']*["'][^>]+content=["']([^"']+)["']/gi,
                ];
                for (const pattern of metaPatterns) {
                    let match;
                    while ((match = pattern.exec(html)) !== null) {
                        try {
                            const url = new url_1.URL(match[1], this.target.baseUrl).toString();
                            if (!discoveredUrls.includes(url)) {
                                discoveredUrls.push(url);
                            }
                        }
                        catch (error) {
                            // Invalid URL, skip
                        }
                    }
                }
            }
        }
        catch (error) {
            logger_1.logger.debug('Failed to discover swagger URLs from HTML:', error);
        }
        return discoveredUrls;
    }
    deduplicateEndpoints(endpoints) {
        const seen = new Set();
        const deduplicated = [];
        for (const endpoint of endpoints) {
            const key = `${endpoint.method}:${endpoint.url}`;
            if (!seen.has(key)) {
                seen.add(key);
                deduplicated.push(endpoint);
            }
        }
        return deduplicated;
    }
}
exports.SwaggerDiscovery = SwaggerDiscovery;
//# sourceMappingURL=swaggerDiscovery.js.map