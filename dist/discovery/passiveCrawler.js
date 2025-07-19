"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.PassiveCrawler = void 0;
const axios_1 = __importDefault(require("axios"));
const url_1 = require("url");
const cheerio = __importStar(require("cheerio"));
const logger_1 = require("../utils/logger");
const sensitiveDataDetector_1 = require("../security/sensitiveDataDetector");
class PassiveCrawler {
    constructor(target, options, onVulnerabilityFound) {
        this.visitedUrls = new Set();
        this.discoveredEndpoints = new Set();
        this.maxDepth = 2;
        this.maxUrls = 50;
        this.target = target;
        this.options = options;
        this.sensitiveDataDetector = new sensitiveDataDetector_1.SensitiveDataDetector();
        this.onVulnerabilityFound = onVulnerabilityFound;
    }
    async discover() {
        const endpoints = [];
        logger_1.logger.info(`Starting passive crawling for ${this.target.baseUrl}`);
        try {
            // Start with the main page
            await this.crawlPage(this.target.baseUrl, 0);
            // Try common entry points
            const commonPages = [
                '/',
                '/index.html',
                '/index.htm',
                '/home',
                '/app',
                '/admin',
                '/dashboard',
                '/docs',
                '/api',
                '/assets/js/',
                '/static/js/',
                '/js/',
                '/scripts/',
            ];
            for (const page of commonPages) {
                try {
                    const url = new url_1.URL(page, this.target.baseUrl).toString();
                    if (!this.visitedUrls.has(url)) {
                        await this.crawlPage(url, 0);
                    }
                }
                catch (error) {
                    // Continue with next page
                }
            }
            // Convert discovered endpoints to EndpointInfo objects
            for (const endpointUrl of this.discoveredEndpoints) {
                const endpoint = await this.createEndpointInfo(endpointUrl);
                endpoints.push(endpoint);
            }
            logger_1.logger.info(`Passive crawling completed: ${endpoints.length} endpoints found`);
            return endpoints;
        }
        catch (error) {
            logger_1.logger.error('Passive crawling failed:', error);
            return endpoints;
        }
    }
    async crawlPage(url, depth) {
        if (depth > this.maxDepth || this.visitedUrls.size > this.maxUrls) {
            return;
        }
        if (this.visitedUrls.has(url)) {
            return;
        }
        this.visitedUrls.add(url);
        try {
            const response = await this.retryRequest(url, {
                timeout: this.options.timeout || 10000,
                headers: {
                    'User-Agent': this.options.userAgent || 'API-Risk-Visualizer/1.0',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    ...this.target.headers,
                },
                validateStatus: (status) => status < 400,
            });
            if (!response) {
                logger_1.logger.debug(`No response received for ${url} after retries.`);
                return;
            }
            const contentType = response.headers['content-type'] || '';
            // Scan response body for sensitive data
            const bodyFindings = this.sensitiveDataDetector.scan(response.data, 'response_body');
            if (bodyFindings.length > 0) {
                sensitiveDataDetector_1.SensitiveDataDetector.findingsToVulnerabilities(bodyFindings, url, 'GET').forEach(v => this.onVulnerabilityFound(v));
            }
            // Scan response headers for sensitive data
            for (const headerName in response.headers) {
                const headerValue = response.headers[headerName];
                if (typeof headerValue === 'string') {
                    const headerFindings = this.sensitiveDataDetector.scan(headerValue, `header: ${headerName}`);
                    if (headerFindings.length > 0) {
                        sensitiveDataDetector_1.SensitiveDataDetector.findingsToVulnerabilities(headerFindings, url, 'GET').forEach(v => this.onVulnerabilityFound(v));
                    }
                }
            }
            if (contentType.includes('text/html')) {
                await this.parseHtmlPage(response.data, url, depth);
            }
            else if (contentType.includes('javascript') || url.includes('.js')) {
                await this.parseJavaScriptFile(response.data, url);
            }
            else if (contentType.includes('application/json')) {
                await this.parseJsonResponse(response.data, url);
            }
        }
        catch (error) {
            logger_1.logger.debug(`Failed to crawl ${url}:`, error);
        }
    }
    async parseHtmlPage(html, baseUrl, depth) {
        try {
            const $ = cheerio.load(html);
            // Extract JavaScript files
            const scriptSrcs = [];
            $('script[src]').each((_, element) => {
                const src = $(element).attr('src');
                if (src) {
                    try {
                        const scriptUrl = new url_1.URL(src, baseUrl).toString();
                        scriptSrcs.push(scriptUrl);
                    }
                    catch (error) {
                        // Invalid URL, skip
                    }
                }
            });
            // Extract inline JavaScript
            const inlineScripts = [];
            $('script:not([src])').each((_, element) => {
                const scriptContent = $(element).html();
                if (scriptContent) {
                    inlineScripts.push(scriptContent);
                }
            });
            // Extract links for further crawling
            const links = [];
            $('a[href]').each((_, element) => {
                const href = $(element).attr('href');
                if (href) {
                    try {
                        const linkUrl = new url_1.URL(href, baseUrl).toString();
                        if (this.isSameDomain(linkUrl)) {
                            links.push(linkUrl);
                        }
                    }
                    catch (error) {
                        // Invalid URL, skip
                    }
                }
            });
            // Extract form actions
            $('form[action]').each((_, element) => {
                const action = $(element).attr('action');
                if (action) {
                    try {
                        const actionUrl = new url_1.URL(action, baseUrl).toString();
                        this.extractApiEndpointsFromUrl(actionUrl);
                    }
                    catch (error) {
                        // Invalid URL, skip
                    }
                }
            });
            // Extract data attributes that might contain API endpoints
            $('[data-api-url], [data-endpoint], [data-url]').each((_, element) => {
                const apiUrl = $(element).attr('data-api-url') ||
                    $(element).attr('data-endpoint') ||
                    $(element).attr('data-url');
                if (apiUrl) {
                    try {
                        const fullUrl = new url_1.URL(apiUrl, baseUrl).toString();
                        this.extractApiEndpointsFromUrl(fullUrl);
                    }
                    catch (error) {
                        // Invalid URL, skip
                    }
                }
            });
            // Parse JavaScript files
            for (const scriptUrl of scriptSrcs) {
                await this.crawlPage(scriptUrl, depth + 1);
            }
            // Parse inline scripts
            for (const script of inlineScripts) {
                await this.parseJavaScriptContent(script, baseUrl);
            }
            // Follow links (limited depth)
            if (depth < this.maxDepth) {
                for (const link of links.slice(0, 10)) { // Limit to 10 links per page
                    await this.crawlPage(link, depth + 1);
                }
            }
        }
        catch (error) {
            logger_1.logger.debug(`Failed to parse HTML for ${baseUrl}:`, error);
        }
    }
    async parseJavaScriptFile(content, url) {
        await this.parseJavaScriptContent(content, url);
    }
    async parseJavaScriptContent(content, baseUrl) {
        try {
            // Extract API endpoints from JavaScript code
            const apiPatterns = [
                // Common API call patterns
                /fetch\s*\(\s*['"`]([^'"`]+)['"`]/g,
                /axios\.\w+\s*\(\s*['"`]([^'"`]+)['"`]/g,
                /\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*['"`]([^'"`]+)['"`]/g,
                /\$\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/g,
                /XMLHttpRequest.*open\s*\(\s*['"`]\w+['"`]\s*,\s*['"`]([^'"`]+)['"`]/g,
                // URL patterns in variables
                /(?:url|endpoint|api)\s*[:=]\s*['"`]([^'"`]+)['"`]/gi,
                /['"`](\/api\/[^'"`]*?)['"`]/g,
                /['"`](\/v\d+\/[^'"`]*?)['"`]/g,
                /['"`](\/rest\/[^'"`]*?)['"`]/g,
                /['"`](\/graphql[^'"`]*?)['"`]/g,
                // Environment variables or config
                /process\.env\.\w*(?:URL|ENDPOINT|API)\s*\|\|\s*['"`]([^'"`]+)['"`]/g,
                /config\.\w*(?:url|endpoint|api)[^'"`]*['"`]([^'"`]+)['"`]/gi,
                // Template literals
                /`([^`]*\/api\/[^`]*)`/g,
                /`([^`]*\/v\d+\/[^`]*)`/g,
            ];
            for (const pattern of apiPatterns) {
                let match;
                while ((match = pattern.exec(content)) !== null) {
                    const endpoint = match[1] || match[2]; // Different capture groups for different patterns
                    if (endpoint) {
                        try {
                            // Skip obviously non-API URLs
                            if (this.looksLikeApiEndpoint(endpoint)) {
                                const fullUrl = endpoint.startsWith('http')
                                    ? endpoint
                                    : new url_1.URL(endpoint, baseUrl).toString();
                                if (this.isSameDomain(fullUrl) || endpoint.startsWith('/')) {
                                    this.extractApiEndpointsFromUrl(fullUrl);
                                }
                            }
                        }
                        catch (error) {
                            // Invalid URL, skip
                        }
                    }
                }
            }
            // Look for dynamic route patterns (React Router, etc.)
            const routePatterns = [
                /path\s*:\s*['"`]([^'"`]+)['"`]/g,
                /route\s*:\s*['"`]([^'"`]+)['"`]/g,
                /<Route[^>]+path=['"`]([^'"`]+)['"`]/g,
            ];
            for (const pattern of routePatterns) {
                let match;
                while ((match = pattern.exec(content)) !== null) {
                    const route = match[1];
                    if (route && this.looksLikeApiEndpoint(route)) {
                        try {
                            const fullUrl = new url_1.URL(route, baseUrl).toString();
                            this.extractApiEndpointsFromUrl(fullUrl);
                        }
                        catch (error) {
                            // Invalid URL, skip
                        }
                    }
                }
            }
        }
        catch (error) {
            logger_1.logger.debug(`Failed to parse JavaScript content:`, error);
        }
    }
    async parseJsonResponse(content, url) {
        try {
            const jsonData = JSON.parse(content);
            this.extractEndpointsFromObject(jsonData, url);
        }
        catch (error) {
            // Not valid JSON or other error
        }
    }
    extractEndpointsFromObject(obj, baseUrl) {
        if (typeof obj !== 'object' || obj === null) {
            return;
        }
        for (const [key, value] of Object.entries(obj)) {
            if (typeof value === 'string') {
                // Check if the value looks like an API endpoint
                if (this.looksLikeApiEndpoint(value)) {
                    try {
                        const fullUrl = value.startsWith('http')
                            ? value
                            : new url_1.URL(value, baseUrl).toString();
                        this.extractApiEndpointsFromUrl(fullUrl);
                    }
                    catch (error) {
                        // Invalid URL, skip
                    }
                }
            }
            else if (typeof value === 'object') {
                // Recursively search nested objects
                this.extractEndpointsFromObject(value, baseUrl);
            }
        }
    }
    looksLikeApiEndpoint(url) {
        const apiIndicators = [
            '/api/',
            '/v1/',
            '/v2/',
            '/v3/',
            '/rest/',
            '/graphql',
            '/json',
            '/xml',
            '.json',
            '.xml',
        ];
        const lowerUrl = url.toLowerCase();
        return apiIndicators.some(indicator => lowerUrl.includes(indicator)) ||
            /\/api\//.test(lowerUrl) ||
            /\/v\d+\//.test(lowerUrl) ||
            /\.(json|xml)(\?|$)/.test(lowerUrl);
    }
    extractApiEndpointsFromUrl(url) {
        try {
            const urlObj = new url_1.URL(url);
            // Clean up the URL (remove query parameters and fragments for base endpoint)
            const cleanPath = urlObj.pathname.replace(/\/$/, '') || '/';
            const baseEndpoint = `${urlObj.protocol}//${urlObj.host}${cleanPath}`;
            if (this.isSameDomain(baseEndpoint) && this.looksLikeApiEndpoint(cleanPath)) {
                this.discoveredEndpoints.add(baseEndpoint);
                // Also add with query parameters if they exist
                if (urlObj.search) {
                    this.discoveredEndpoints.add(url);
                }
            }
        }
        catch (error) {
            // Invalid URL, skip
        }
    }
    isSameDomain(url) {
        try {
            const targetDomain = new url_1.URL(this.target.baseUrl).host;
            const urlDomain = new url_1.URL(url).host;
            return targetDomain === urlDomain;
        }
        catch (error) {
            return false;
        }
    }
    async createEndpointInfo(url) {
        return {
            url,
            method: 'GET', // Default to GET for discovered URLs
            parameters: [],
            authentication: { required: false },
            discoveryMethod: 'crawling',
            responseTypes: [],
        };
    }
    // Helper method for retrying requests with exponential back-off
    async retryRequest(url, config, retries = 3, delay = 1000) {
        try {
            const response = await axios_1.default.get(url, config);
            return response;
        }
        catch (error) {
            if (axios_1.default.isAxiosError(error) && error.response && error.response.status === 429 && retries > 0) {
                logger_1.logger.warn(`Rate limit hit for ${url}. Retrying in ${delay / 1000}s... (Attempts left: ${retries})`);
                await new Promise(resolve => setTimeout(resolve, delay));
                return this.retryRequest(url, config, retries - 1, delay * 2); // Exponential back-off
            }
            else if (axios_1.default.isAxiosError(error) && error.response) {
                logger_1.logger.debug(`HTTP Error for ${url}: ${error.response.status}`);
            }
            else if (error instanceof Error) {
                logger_1.logger.debug(`Request failed for ${url}: ${error.message}`);
            }
            return null; // Return null on non-retriable errors or after exhausting retries
        }
    }
}
exports.PassiveCrawler = PassiveCrawler;
//# sourceMappingURL=passiveCrawler.js.map