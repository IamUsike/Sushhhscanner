import axios from 'axios';
import { URL } from 'url';
import * as cheerio from 'cheerio';
import { logger } from '../utils/logger';
import { EndpointInfo, ScanTarget, Vulnerability } from '../types';
import { DiscoveryOptions } from './endpointDiscovery';
import { SensitiveDataDetector } from '../security/sensitiveDataDetector';

export class PassiveCrawler {
  private target: ScanTarget;
  private options: DiscoveryOptions;
  private visitedUrls = new Set<string>();
  private discoveredEndpoints = new Set<string>();
  private maxDepth = 2;
  private maxUrls = 50;
  private sensitiveDataDetector: SensitiveDataDetector;
  private onVulnerabilityFound: (vulnerability: Vulnerability) => void;

  constructor(target: ScanTarget, options: DiscoveryOptions, onVulnerabilityFound: (vulnerability: Vulnerability) => void) {
    this.target = target;
    this.options = options;
    this.sensitiveDataDetector = new SensitiveDataDetector();
    this.onVulnerabilityFound = onVulnerabilityFound;
  }

  async discover(): Promise<EndpointInfo[]> {
    const endpoints: EndpointInfo[] = [];
    
    logger.info(`Starting passive crawling for ${this.target.baseUrl}`);

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
          const url = new URL(page, this.target.baseUrl).toString();
          if (!this.visitedUrls.has(url)) {
            await this.crawlPage(url, 0);
          }
        } catch (error) {
          // Continue with next page
        }
      }

      // Convert discovered endpoints to EndpointInfo objects
      for (const endpointUrl of this.discoveredEndpoints) {
        const endpoint = await this.createEndpointInfo(endpointUrl);
        endpoints.push(endpoint);
      }

      logger.info(`Passive crawling completed: ${endpoints.length} endpoints found`);
      return endpoints;
    } catch (error) {
      logger.error('Passive crawling failed:', error);
      return endpoints;
    }
  }

  private async crawlPage(url: string, depth: number): Promise<void> {
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
        logger.debug(`No response received for ${url} after retries.`);
        return;
      }

      const contentType = response.headers['content-type'] || '';

      // Scan response body for sensitive data
      const bodyFindings = this.sensitiveDataDetector.scan(response.data, 'response_body');
      if (bodyFindings.length > 0) {
        SensitiveDataDetector.findingsToVulnerabilities(bodyFindings, url, 'GET').forEach(v => this.onVulnerabilityFound(v));
      }

      // Scan response headers for sensitive data
      for (const headerName in response.headers) {
        const headerValue = response.headers[headerName];
        if (typeof headerValue === 'string') {
          const headerFindings = this.sensitiveDataDetector.scan(headerValue, `header: ${headerName}`);
          if (headerFindings.length > 0) {
            SensitiveDataDetector.findingsToVulnerabilities(headerFindings, url, 'GET').forEach(v => this.onVulnerabilityFound(v));
          }
        }
      }

      if (contentType.includes('text/html')) {
        await this.parseHtmlPage(response.data, url, depth);
      } else if (contentType.includes('javascript') || url.includes('.js')) {
        await this.parseJavaScriptFile(response.data, url);
      } else if (contentType.includes('application/json')) {
        await this.parseJsonResponse(response.data, url);
      }
    } catch (error) {
      logger.debug(`Failed to crawl ${url}:`, error);
    }
  }

  private async parseHtmlPage(html: string, baseUrl: string, depth: number): Promise<void> {
    try {
      const $ = cheerio.load(html);

      // Extract JavaScript files
      const scriptSrcs: string[] = [];
      $('script[src]').each((_, element) => {
        const src = $(element).attr('src');
        if (src) {
          try {
            const scriptUrl = new URL(src, baseUrl).toString();
            scriptSrcs.push(scriptUrl);
          } catch (error) {
            // Invalid URL, skip
          }
        }
      });

      // Extract inline JavaScript
      const inlineScripts: string[] = [];
      $('script:not([src])').each((_, element) => {
        const scriptContent = $(element).html();
        if (scriptContent) {
          inlineScripts.push(scriptContent);
        }
      });

      // Extract links for further crawling
      const links: string[] = [];
      $('a[href]').each((_, element) => {
        const href = $(element).attr('href');
        if (href) {
          try {
            const linkUrl = new URL(href, baseUrl).toString();
            if (this.isSameDomain(linkUrl)) {
              links.push(linkUrl);
            }
          } catch (error) {
            // Invalid URL, skip
          }
        }
      });

      // Extract form actions
      $('form[action]').each((_, element) => {
        const action = $(element).attr('action');
        if (action) {
          try {
            const actionUrl = new URL(action, baseUrl).toString();
            this.extractApiEndpointsFromUrl(actionUrl);
          } catch (error) {
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
            const fullUrl = new URL(apiUrl, baseUrl).toString();
            this.extractApiEndpointsFromUrl(fullUrl);
          } catch (error) {
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
    } catch (error) {
      logger.debug(`Failed to parse HTML for ${baseUrl}:`, error);
    }
  }

  private async parseJavaScriptFile(content: string, url: string): Promise<void> {
    await this.parseJavaScriptContent(content, url);
  }

  private async parseJavaScriptContent(content: string, baseUrl: string): Promise<void> {
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
                  : new URL(endpoint, baseUrl).toString();
                
                if (this.isSameDomain(fullUrl) || endpoint.startsWith('/')) {
                  this.extractApiEndpointsFromUrl(fullUrl);
                }
              }
            } catch (error) {
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
              const fullUrl = new URL(route, baseUrl).toString();
              this.extractApiEndpointsFromUrl(fullUrl);
            } catch (error) {
              // Invalid URL, skip
            }
          }
        }
      }
    } catch (error) {
      logger.debug(`Failed to parse JavaScript content:`, error);
    }
  }

  private async parseJsonResponse(content: string, url: string): Promise<void> {
    try {
      const jsonData = JSON.parse(content);
      this.extractEndpointsFromObject(jsonData, url);
    } catch (error) {
      // Not valid JSON or other error
    }
  }

  private extractEndpointsFromObject(obj: any, baseUrl: string): void {
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
              : new URL(value, baseUrl).toString();
            this.extractApiEndpointsFromUrl(fullUrl);
          } catch (error) {
            // Invalid URL, skip
          }
        }
      } else if (typeof value === 'object') {
        // Recursively search nested objects
        this.extractEndpointsFromObject(value, baseUrl);
      }
    }
  }

  private looksLikeApiEndpoint(url: string): boolean {
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

  private extractApiEndpointsFromUrl(url: string): void {
    try {
      const urlObj = new URL(url);
      
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
    } catch (error) {
      // Invalid URL, skip
    }
  }

  private isSameDomain(url: string): boolean {
    try {
      const targetDomain = new URL(this.target.baseUrl).host;
      const urlDomain = new URL(url).host;
      return targetDomain === urlDomain;
    } catch (error) {
      return false;
    }
  }

  private async createEndpointInfo(url: string): Promise<EndpointInfo> {
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
  private async retryRequest(url: string, config: import("axios").AxiosRequestConfig, retries: number = 3, delay: number = 1000): Promise<import("axios").AxiosResponse | null> {
    try {
      const response = await axios.get(url, config);
      return response;
    } catch (error) {
      if (axios.isAxiosError(error) && error.response && error.response.status === 429 && retries > 0) {
        logger.warn(`Rate limit hit for ${url}. Retrying in ${delay / 1000}s... (Attempts left: ${retries})`);
        await new Promise(resolve => setTimeout(resolve, delay));
        return this.retryRequest(url, config, retries - 1, delay * 2); // Exponential back-off
      } else if (axios.isAxiosError(error) && error.response) {
        logger.debug(`HTTP Error for ${url}: ${error.response.status}`);
      } else if (error instanceof Error) {
        logger.debug(`Request failed for ${url}: ${error.message}`);
      }
      return null; // Return null on non-retriable errors or after exhausting retries
    }
  }
} 