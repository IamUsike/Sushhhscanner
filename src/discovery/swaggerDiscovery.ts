import axios from 'axios';
import { URL } from 'url';
import { logger } from '../utils/logger';
import { EndpointInfo, ScanTarget, ParameterInfo } from '../types';
import { DiscoveryOptions } from './endpointDiscovery';

interface SwaggerSpec {
  openapi?: string;
  swagger?: string;
  info?: any;
  servers?: Array<{ url: string; description?: string }>;
  paths?: Record<string, Record<string, any>>;
  components?: any;
  definitions?: any;
}

export class SwaggerDiscovery {
  private target: ScanTarget;
  private options: DiscoveryOptions;
  private commonSwaggerPaths = [
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

  constructor(target: ScanTarget, options: DiscoveryOptions) {
    this.target = target;
    this.options = options;
  }

  async discover(): Promise<EndpointInfo[]> {
    const endpoints: EndpointInfo[] = [];
    
    logger.info(`Starting Swagger/OpenAPI discovery for ${this.target.baseUrl}`);

    try {
      // Try user-provided swagger URL first
      if (this.target.swaggerUrl) {
        const swaggerEndpoints = await this.parseSwaggerFromUrl(this.target.swaggerUrl);
        endpoints.push(...swaggerEndpoints);
      }

      // Try common swagger paths
      for (const path of this.commonSwaggerPaths) {
        try {
          const swaggerUrl = new URL(path, this.target.baseUrl).toString();
          const swaggerEndpoints = await this.parseSwaggerFromUrl(swaggerUrl);
          endpoints.push(...swaggerEndpoints);
          
          if (swaggerEndpoints.length > 0) {
            logger.info(`Found Swagger spec at ${swaggerUrl} with ${swaggerEndpoints.length} endpoints`);
            break; // Found a valid spec, no need to check others
          }
        } catch (error) {
          // Continue to next path
        }
      }

      // Try to discover swagger URLs through HTML parsing
      const discoveredSwaggerUrls = await this.discoverSwaggerUrlsFromHtml();
      for (const url of discoveredSwaggerUrls) {
        try {
          const swaggerEndpoints = await this.parseSwaggerFromUrl(url);
          endpoints.push(...swaggerEndpoints);
        } catch (error) {
          // Continue to next URL
        }
      }

      logger.info(`Swagger discovery completed: ${endpoints.length} endpoints found`);
      return this.deduplicateEndpoints(endpoints);
    } catch (error) {
      logger.error('Swagger discovery failed:', error);
      return endpoints;
    }
  }

  private async parseSwaggerFromUrl(swaggerUrl: string): Promise<EndpointInfo[]> {
    try {
      const response = await axios.get(swaggerUrl, {
        timeout: this.options.timeout || 30000,
        headers: {
          'User-Agent': this.options.userAgent || 'API-Risk-Visualizer/1.0',
          'Accept': 'application/json, application/yaml, text/yaml, text/plain',
          ...this.target.headers,
        },
        validateStatus: (status) => status === 200,
      });

      let swaggerSpec: SwaggerSpec;

      // Parse JSON or YAML
      if (typeof response.data === 'object') {
        swaggerSpec = response.data;
      } else {
        // Try to parse as JSON first, then YAML
        try {
          swaggerSpec = JSON.parse(response.data);
        } catch (jsonError) {
          // For YAML parsing, we'd need a YAML library, but for now treat as JSON
          throw new Error('YAML parsing not implemented - use JSON format');
        }
      }

      return this.parseSwaggerSpec(swaggerSpec);
    } catch (error) {
      logger.debug(`Failed to parse swagger from ${swaggerUrl}:`, error);
      throw error;
    }
  }

  private parseSwaggerSpec(spec: SwaggerSpec): EndpointInfo[] {
    const endpoints: EndpointInfo[] = [];

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
      } else if (server.url.startsWith('/')) {
        baseUrl = new URL(server.url, this.target.baseUrl).toString();
      }
    } else if (spec.swagger && (spec as any).host) {
      // Swagger 2.0 host
      const scheme = (spec as any).schemes?.[0] || 'https';
      const basePath = (spec as any).basePath || '';
      baseUrl = `${scheme}://${(spec as any).host}${basePath}`;
    }

    // Parse paths
    for (const [path, pathItem] of Object.entries(spec.paths)) {
      if (!pathItem || typeof pathItem !== 'object') continue;

      for (const [method, operation] of Object.entries(pathItem)) {
        if (!operation || typeof operation !== 'object') continue;
        if (['parameters', 'summary', 'description'].includes(method)) continue;

        const endpoint = this.createEndpointFromOperation(
          baseUrl,
          path,
          method.toUpperCase(),
          operation,
          pathItem.parameters || []
        );

        endpoints.push(endpoint);
      }
    }

    return endpoints;
  }

  private createEndpointFromOperation(
    baseUrl: string,
    path: string,
    method: string,
    operation: any,
    pathParameters: any[] = []
  ): EndpointInfo {
    const fullUrl = new URL(path, baseUrl).toString();
    
    const endpoint: EndpointInfo = {
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

  private parseSwaggerParameters(parameters: any[]): ParameterInfo[] {
    const params: ParameterInfo[] = [];

    for (const param of parameters) {
      if (!param.name) continue;

      const paramInfo: ParameterInfo = {
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

  private mapSwaggerParameterType(swaggerType: string): 'query' | 'path' | 'header' | 'body' {
    switch (swaggerType) {
      case 'query': return 'query';
      case 'path': return 'path';
      case 'header': return 'header';
      case 'body':
      case 'formData': return 'body';
      default: return 'query';
    }
  }

  private mapSwaggerDataType(swaggerType: string): string {
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

  private parseSwaggerAuthentication(operation: any): any {
    const authInfo: {
      required: boolean;
      methods: string[];
      tested: boolean;
      bypassed: boolean;
    } = {
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
          } else if (securityName.toLowerCase().includes('basic')) {
            authInfo.methods.push('Basic');
          } else if (securityName.toLowerCase().includes('api') && securityName.toLowerCase().includes('key')) {
            authInfo.methods.push('API-Key');
          } else {
            authInfo.methods.push('Unknown');
          }
        }
      }
    }

    return authInfo;
  }

  private parseSwaggerResponseTypes(operation: any): string[] {
    const responseTypes: string[] = [];

    if (operation.responses) {
      for (const [statusCode, response] of Object.entries(operation.responses)) {
        if (typeof response === 'object' && response !== null) {
          const responseObj = response as any;
          
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

  private async discoverSwaggerUrlsFromHtml(): Promise<string[]> {
    const discoveredUrls: string[] = [];

    try {
      // Try to get the main page
      const response = await axios.get(this.target.baseUrl, {
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
              const url = new URL(match[1], this.target.baseUrl).toString();
              if (!discoveredUrls.includes(url)) {
                discoveredUrls.push(url);
              }
            } catch (error) {
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
              const url = new URL(match[1], this.target.baseUrl).toString();
              if (!discoveredUrls.includes(url)) {
                discoveredUrls.push(url);
              }
            } catch (error) {
              // Invalid URL, skip
            }
          }
        }
      }
    } catch (error) {
      logger.debug('Failed to discover swagger URLs from HTML:', error);
    }

    return discoveredUrls;
  }

  private deduplicateEndpoints(endpoints: EndpointInfo[]): EndpointInfo[] {
    const seen = new Set<string>();
    const deduplicated: EndpointInfo[] = [];

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