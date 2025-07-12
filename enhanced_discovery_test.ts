import axios from 'axios';

// Types
interface APIEndpoint {
  path: string;
  method: string;
  url: string;
  discoveredBy: string[];
  parameters?: Array<{ name: string; type: string; required?: boolean }>;
  authentication?: {
    required: boolean;
    type: string;
  };
  response?: {
    statusCode: number;
    headers: Record<string, string>;
    contentType: string;
  };
  description?: string;
  timestamp: string;
}

interface DiscoveryProgress {
  phase: string;
  percentage: number;
  currentOperation?: string;
}

// Enhanced Swagger Discovery
class SwaggerDiscovery {
  async discoverEndpoints(
    baseUrl: string,
    options: { timeout?: number } = {},
    progressCallback?: (progress: DiscoveryProgress) => void
  ): Promise<APIEndpoint[]> {
    const { timeout = 10000 } = options;
    const endpoints: APIEndpoint[] = [];
    
    console.log('🔍 Starting Swagger/OpenAPI discovery...');
    
    // Extended list of common OpenAPI/Swagger paths
    const swaggerPaths = [
      // Standard OpenAPI 3.x paths
      '/openapi.json', '/openapi.yaml', '/openapi.yml',
      '/api/openapi.json', '/api/openapi.yaml',
      
      // Swagger 2.0 paths
      '/swagger.json', '/swagger.yaml', '/swagger.yml',
      '/api/swagger.json', '/api/swagger.yaml',
      '/swagger/v1/swagger.json', '/swagger/v2/swagger.json',
      
      // Spring Boot Actuator
      '/v2/api-docs', '/v3/api-docs',
      '/api/v2/api-docs', '/api/v3/api-docs',
      
      // Common API doc paths
      '/api-docs', '/api-docs.json', '/api-docs.yaml',
      '/api/api-docs', '/api/docs', '/docs',
      '/docs/swagger.json', '/docs/openapi.json',
      
      // UI paths that might redirect to specs
      '/swagger-ui.html', '/swagger-ui/',
      '/api/swagger-ui.html', '/api/swagger-ui/',
      '/docs/', '/api/docs/',
      
      // FastAPI default paths
      '/docs', '/redoc', '/openapi.json',
      
      // Other common patterns
      '/api/spec', '/api/specification',
      '/spec.json', '/specification.json',
      '/swagger', '/api/swagger'
    ];

    for (let i = 0; i < swaggerPaths.length; i++) {
      const path = swaggerPaths[i];
      const fullUrl = `${baseUrl.replace(/\/$/, '')}${path}`;
      
      if (progressCallback) {
        progressCallback({
          phase: 'swagger-discovery',
          percentage: (i / swaggerPaths.length) * 100,
          currentOperation: `Testing ${path}`
        });
      }
      
      try {
        const response = await axios.get(fullUrl, { 
          timeout,
          headers: {
            'Accept': 'application/json, application/yaml, text/yaml, text/html, */*',
            'User-Agent': 'API-Discovery-Tool'
          }
        });
        
        if (response.status === 200 && response.data) {
          console.log(`✅ Found spec at: ${path} (${response.headers['content-type']})`);
          
          let parsedEndpoints: APIEndpoint[] = [];
          
          // Handle HTML responses (might contain spec URLs)
          if (typeof response.data === 'string' && response.data.includes('<html')) {
            parsedEndpoints = this.extractSpecUrlsFromHTML(response.data, baseUrl);
            if (parsedEndpoints.length > 0) {
              console.log(`📋 Found ${parsedEndpoints.length} spec URLs in HTML`);
            }
          } else {
            // Handle direct spec responses
            parsedEndpoints = this.parseOpenAPISpec(response.data, baseUrl);
            if (parsedEndpoints.length > 0) {
              console.log(`📋 Extracted ${parsedEndpoints.length} endpoints from OpenAPI spec`);
            }
          }
          
          endpoints.push(...parsedEndpoints);
        }
      } catch (error: any) {
        // Only log non-404 errors for debugging
        if (error.response?.status && error.response.status !== 404 && error.response.status !== 403) {
          console.log(`⚠️ Error accessing ${path} (${error.response.status}): ${error.message}`);
        }
      }
    }
    
    return endpoints;
  }
  
  private extractSpecUrlsFromHTML(html: string, baseUrl: string): APIEndpoint[] {
    const endpoints: APIEndpoint[] = [];
    
    // Look for common spec URL patterns in HTML
    const specPatterns = [
      /(?:href|src)=["']([^"']*(?:openapi|swagger|api-docs)[^"']*)["']/gi,
      /url:\s*["']([^"']*(?:openapi|swagger|api-docs)[^"']*)["']/gi,
      /"specUrl":\s*["']([^"']+)["']/gi
    ];
    
    for (const pattern of specPatterns) {
      let match;
      while ((match = pattern.exec(html)) !== null) {
        let specUrl = match[1];
        
        // Make URL absolute if needed
        if (specUrl.startsWith('/')) {
          specUrl = `${baseUrl.replace(/\/$/, '')}${specUrl}`;
        } else if (!specUrl.startsWith('http')) {
          specUrl = `${baseUrl.replace(/\/$/, '')}/${specUrl}`;
        }
        
        // Try to fetch and parse this spec
        this.fetchAndParseSpec(specUrl).then(specEndpoints => {
          endpoints.push(...specEndpoints);
        }).catch(() => {
          // Ignore errors from spec fetching
        });
      }
    }
    
    return endpoints;
  }
  
  private async fetchAndParseSpec(specUrl: string): Promise<APIEndpoint[]> {
    try {
      const response = await axios.get(specUrl, { 
        timeout: 5000,
        headers: {
          'Accept': 'application/json, application/yaml, */*'
        }
      });
      
      if (response.status === 200 && response.data) {
        return this.parseOpenAPISpec(response.data, specUrl);
      }
    } catch (error) {
      // Silently fail
    }
    
    return [];
  }
  
  private parseOpenAPISpec(spec: any, baseUrl: string): APIEndpoint[] {
    const endpoints: APIEndpoint[] = [];
    
    try {
      let parsedSpec = spec;
      
      // Parse string specs
      if (typeof spec === 'string') {
        try {
          parsedSpec = JSON.parse(spec);
        } catch {
          // Could be YAML, try basic YAML parsing
          if (spec.includes('paths:')) {
            console.log('⚠️ Found YAML spec - limited parsing available');
            return this.parseYAMLSpec(spec, baseUrl);
          }
          return endpoints;
        }
      }
      
      // Determine server base URL
      let serverBase = baseUrl;
      if (parsedSpec.servers && parsedSpec.servers.length > 0) {
        const server = parsedSpec.servers[0];
        if (server.url) {
          if (server.url.startsWith('http')) {
            serverBase = server.url;
          } else if (server.url.startsWith('/')) {
            const baseOrigin = new URL(baseUrl).origin;
            serverBase = `${baseOrigin}${server.url}`;
          } else {
            serverBase = `${baseUrl.replace(/\/$/, '')}/${server.url}`;
          }
        }
      } else if (parsedSpec.host) {
        const scheme = parsedSpec.schemes?.[0] || 'https';
        const basePath = parsedSpec.basePath || '';
        serverBase = `${scheme}://${parsedSpec.host}${basePath}`;
      }
      
      // Parse paths and methods
      if (parsedSpec.paths && typeof parsedSpec.paths === 'object') {
        for (const [path, pathObj] of Object.entries(parsedSpec.paths as any)) {
          if (pathObj && typeof pathObj === 'object') {
            for (const [method, methodObj] of Object.entries(pathObj as any)) {
              if (['get', 'post', 'put', 'delete', 'patch', 'head', 'options'].includes(method.toLowerCase())) {
                const endpoint: APIEndpoint = {
                  path: path,
                  method: method.toUpperCase(),
                  url: `${serverBase.replace(/\/$/, '')}${path}`,
                  discoveredBy: ['swagger'],
                  description: (methodObj as any)?.summary || (methodObj as any)?.description || `${method.toUpperCase()} ${path}`,
                  timestamp: new Date().toISOString()
                };
                
                // Extract parameters
                const parameters: Array<{ name: string; type: string; required?: boolean }> = [];
                
                // Path parameters
                const pathParams = path.match(/{([^}]+)}/g);
                if (pathParams) {
                  pathParams.forEach(param => {
                    const name = param.slice(1, -1);
                    parameters.push({ name, type: 'string', required: true });
                  });
                }
                
                // Method parameters
                if ((methodObj as any)?.parameters) {
                  (methodObj as any).parameters.forEach((param: any) => {
                    parameters.push({
                      name: param.name,
                      type: param.type || param.schema?.type || 'unknown',
                      required: param.required || false
                    });
                  });
                }
                
                if (parameters.length > 0) {
                  endpoint.parameters = parameters;
                }
                
                // Check for authentication requirements
                const requiresAuth = (methodObj as any)?.security || 
                                   parsedSpec.security || 
                                   parsedSpec.securityDefinitions ||
                                   parsedSpec.components?.securitySchemes;
                
                if (requiresAuth) {
                  endpoint.authentication = {
                    required: true,
                    type: this.detectAuthType(parsedSpec)
                  };
                }
                
                endpoints.push(endpoint);
              }
            }
          }
        }
      }
      
    } catch (error: any) {
      console.log(`⚠️ Error parsing OpenAPI spec: ${error.message}`);
    }
    
    return endpoints;
  }
  
  private parseYAMLSpec(yamlContent: string, baseUrl: string): APIEndpoint[] {
    const endpoints: APIEndpoint[] = [];
    
    // Very basic YAML parsing for paths
    const lines = yamlContent.split('\n');
    let currentPath = '';
    let inPaths = false;
    
    for (const line of lines) {
      const trimmed = line.trim();
      
      if (trimmed === 'paths:') {
        inPaths = true;
        continue;
      }
      
      if (inPaths && trimmed.startsWith('/')) {
        currentPath = trimmed.replace(':', '');
      } else if (inPaths && currentPath && /^\s*(get|post|put|delete|patch):/i.test(line)) {
        const method = line.trim().split(':')[0].toUpperCase();
        endpoints.push({
          path: currentPath,
          method,
          url: `${baseUrl.replace(/\/$/, '')}${currentPath}`,
          discoveredBy: ['swagger'],
          description: `${method} ${currentPath} (from YAML)`,
          timestamp: new Date().toISOString()
        });
      }
    }
    
    return endpoints;
  }
  
  private detectAuthType(spec: any): string {
    if (spec.components?.securitySchemes) {
      const schemes = Object.values(spec.components.securitySchemes);
      if (schemes.some((s: any) => s.type === 'http' && s.scheme === 'bearer')) {
        return 'Bearer';
      }
      if (schemes.some((s: any) => s.type === 'http' && s.scheme === 'basic')) {
        return 'Basic';
      }
      if (schemes.some((s: any) => s.type === 'apiKey')) {
        return 'API-Key';
      }
    }
    
    if (spec.securityDefinitions) {
      const schemes = Object.values(spec.securityDefinitions);
      if (schemes.some((s: any) => s.type === 'oauth2')) {
        return 'OAuth2';
      }
      if (schemes.some((s: any) => s.type === 'apiKey')) {
        return 'API-Key';
      }
    }
    
    return 'Unknown';
  }
}

// Enhanced Brute Force Discovery
class BruteForceDiscovery {
  private readonly commonEndpoints = [
    // Core API patterns
    '/api/users', '/api/user', '/users', '/user',
    '/api/auth', '/auth', '/login', '/logout', '/register',
    '/api/profile', '/profile', '/me',
    
    // Data endpoints
    '/api/data', '/data', '/api/items', '/items',
    '/api/products', '/products', '/api/orders', '/orders',
    '/api/posts', '/posts', '/api/comments', '/comments',
    
    // Status and health
    '/api/health', '/health', '/api/status', '/status',
    '/api/ping', '/ping', '/api/version', '/version',
    
    // Versioned APIs
    '/api/v1', '/api/v2', '/api/v3', '/v1', '/v2', '/v3',
    '/api/v1/users', '/api/v2/users',
    
    // Admin and management
    '/admin', '/api/admin', '/api/dashboard', '/dashboard',
    '/api/settings', '/settings', '/api/config', '/config',
    
    // Documentation
    '/docs', '/api-docs', '/api/docs', '/documentation',
    '/swagger', '/api/swagger', '/openapi'
  ];
  
  async discoverEndpoints(
    baseUrl: string,
    options: { timeout?: number, maxEndpoints?: number } = {},
    progressCallback?: (progress: DiscoveryProgress) => void
  ): Promise<APIEndpoint[]> {
    const { timeout = 5000, maxEndpoints = 15 } = options;
    const endpoints: APIEndpoint[] = [];
    
    console.log('🔍 Starting brute force discovery...');
    
    const endpointsToTest = this.commonEndpoints.slice(0, maxEndpoints);
    
    for (let i = 0; i < endpointsToTest.length; i++) {
      const path = endpointsToTest[i];
      const fullUrl = `${baseUrl.replace(/\/$/, '')}${path}`;
      
      if (progressCallback) {
        progressCallback({
          phase: 'brute-force-discovery',
          percentage: (i / endpointsToTest.length) * 100,
          currentOperation: `Testing ${path}`
        });
      }
      
      try {
        const response = await axios.get(fullUrl, { 
          timeout,
          validateStatus: (status) => status < 500,
          headers: {
            'User-Agent': 'API-Discovery-Tool',
            'Accept': 'application/json, */*'
          }
        });
        
        if (response.status !== 404 && response.status !== 405) {
          console.log(`✅ Found endpoint: ${path} (${response.status})`);
          
          endpoints.push({
            path: path,
            method: 'GET',
            url: fullUrl,
            discoveredBy: ['brute-force'],
            response: {
              statusCode: response.status,
              headers: {
                'content-type': response.headers['content-type'] || 'unknown'
              },
              contentType: response.headers['content-type'] || 'unknown'
            },
            description: `Discovered via brute force (${response.status})`,
            timestamp: new Date().toISOString()
          });
        }
      } catch (error: any) {
        // Silently continue - most endpoints won't exist
      }
    }
    
    return endpoints;
  }
}

// Main discovery engine
class EndpointDiscovery {
  private swaggerDiscovery = new SwaggerDiscovery();
  private bruteForceDiscovery = new BruteForceDiscovery();
  
  async discoverEndpoints(
    baseUrl: string,
    options: {
      depth?: 'basic' | 'comprehensive' | 'deep';
      timeout?: number;
    } = {},
    progressCallback?: (progress: DiscoveryProgress) => void
  ) {
    const { depth = 'comprehensive', timeout = 10000 } = options;
    
    console.log(`🚀 Starting endpoint discovery for: ${baseUrl}`);
    console.log(`📊 Discovery depth: ${depth}`);
    
    const allEndpoints: APIEndpoint[] = [];
    const discoveryMethods: string[] = [];
    const errors: any[] = [];
    
    try {
      // Swagger discovery
      if (progressCallback) {
        progressCallback({
          phase: 'swagger-discovery',
          percentage: 0,
          currentOperation: 'Starting Swagger/OpenAPI discovery'
        });
      }
      
      const swaggerEndpoints = await this.swaggerDiscovery.discoverEndpoints(baseUrl, { timeout }, progressCallback);
      allEndpoints.push(...swaggerEndpoints);
      if (swaggerEndpoints.length > 0) {
        discoveryMethods.push('swagger');
      }
      
      // Brute force discovery
      if (depth !== 'basic') {
        if (progressCallback) {
          progressCallback({
            phase: 'brute-force-discovery',
            percentage: 50,
            currentOperation: 'Starting brute force discovery'
          });
        }
        
        const maxEndpoints = depth === 'deep' ? 25 : 15;
        const bruteForceEndpoints = await this.bruteForceDiscovery.discoverEndpoints(
          baseUrl, 
          { timeout: timeout / 2, maxEndpoints }, 
          progressCallback
        );
        allEndpoints.push(...bruteForceEndpoints);
        if (bruteForceEndpoints.length > 0) {
          discoveryMethods.push('brute-force');
        }
      }
      
      if (progressCallback) {
        progressCallback({
          phase: 'finalizing',
          percentage: 100,
          currentOperation: 'Processing results'
        });
      }
      
    } catch (error: any) {
      console.error(`❌ Discovery error: ${error.message}`);
      errors.push({ method: 'general', message: error.message });
    }
    
    // Remove duplicates and sort
    const uniqueEndpoints = this.deduplicateEndpoints(allEndpoints);
    uniqueEndpoints.sort((a, b) => a.path.localeCompare(b.path));
    
    return {
      endpoints: uniqueEndpoints,
      discoveryMethods,
      errors,
      metadata: {
        title: 'API Discovery Results',
        baseUrl,
        discoveredAt: new Date().toISOString(),
        totalEndpoints: uniqueEndpoints.length
      }
    };
  }
  
  private deduplicateEndpoints(endpoints: APIEndpoint[]): APIEndpoint[] {
    const seen = new Map<string, APIEndpoint>();
    
    for (const endpoint of endpoints) {
      const key = `${endpoint.method}:${endpoint.path}`;
      if (!seen.has(key)) {
        seen.set(key, endpoint);
      } else {
        // Merge discovery methods
        const existing = seen.get(key)!;
        existing.discoveredBy = [...new Set([...existing.discoveredBy, ...endpoint.discoveredBy])];
      }
    }
    
    return Array.from(seen.values());
  }
}

// Enhanced test with more targets
async function testEnhancedDiscovery() {
    console.log('🚀 Enhanced API Endpoint Discovery Test\n');
    
    const discovery = new EndpointDiscovery();
    
    // More diverse test targets
    const testTargets = [
        {
            name: 'Swagger Petstore (OpenAPI 3.0)',
            url: 'https://petstore3.swagger.io',
            description: 'OpenAPI 3.0 specification example'
        },
        {
            name: 'JSONPlaceholder',
            url: 'https://jsonplaceholder.typicode.com',
            description: 'Simple REST API for testing'
        },
        {
            name: 'ReqRes.in',
            url: 'https://reqres.in',
            description: 'REST API for testing with users and authentication'
        },
        {
            name: 'httpbin.org',
            url: 'https://httpbin.org',
            description: 'HTTP testing service'
        }
    ];

    for (const target of testTargets) {
        console.log(`\n🎯 Testing: ${target.name}`);
        console.log(`📍 URL: ${target.url}`);
        console.log(`📋 Description: ${target.description}`);
        console.log('─'.repeat(70));
        
        try {
            const startTime = Date.now();
            
            const options = {
                depth: 'comprehensive' as const,
                timeout: 12000
            };
            
            let lastProgress = '';
            const progressCallback = (progress: DiscoveryProgress) => {
                const bar = '█'.repeat(Math.floor(progress.percentage / 5)) + 
                           '░'.repeat(20 - Math.floor(progress.percentage / 5));
                const progressLine = `[${bar}] ${progress.percentage.toFixed(1)}% - ${progress.phase}`;
                if (progressLine !== lastProgress) {
                    process.stdout.write(`\r${progressLine}`);
                    lastProgress = progressLine;
                }
            };
            
            console.log('\n🔍 Starting enhanced discovery...');
            const results = await discovery.discoverEndpoints(target.url, options, progressCallback);
            
            const duration = ((Date.now() - startTime) / 1000).toFixed(2);
            console.log(`\n\n✅ Discovery completed in ${duration}s`);
            
            // Enhanced results display
            console.log('\n📊 DISCOVERY SUMMARY:');
            console.log(`Total endpoints found: ${results.endpoints.length}`);
            console.log(`Discovery methods: ${results.discoveryMethods.join(', ') || 'none'}`);
            
            if (results.endpoints.length > 0) {
                // Method breakdown
                const methodBreakdown: Record<string, number> = {};
                results.endpoints.forEach(endpoint => {
                    endpoint.discoveredBy.forEach(method => {
                        methodBreakdown[method] = (methodBreakdown[method] || 0) + 1;
                    });
                });
                
                console.log('\n🔬 Discovery method breakdown:');
                Object.entries(methodBreakdown).forEach(([method, count]) => {
                    console.log(`  ${method}: ${count} endpoints`);
                });
                
                // HTTP methods
                const httpMethods = [...new Set(results.endpoints.map(e => e.method))];
                console.log(`\n🌐 HTTP methods: ${httpMethods.join(', ')}`);
                
                // Authentication requirements
                const authRequired = results.endpoints.filter(e => e.authentication?.required).length;
                if (authRequired > 0) {
                    console.log(`🔐 Endpoints requiring authentication: ${authRequired}`);
                }
                
                // Sample endpoints
                console.log('\n📝 Discovered endpoints:');
                results.endpoints.forEach((endpoint, index) => {
                    const authIndicator = endpoint.authentication?.required ? ' 🔒' : '';
                    const methods = endpoint.discoveredBy.join(',');
                    console.log(`  ${index + 1}. ${endpoint.method} ${endpoint.path}${authIndicator} [${methods}]`);
                    
                    if (endpoint.description && endpoint.description !== `${endpoint.method} ${endpoint.path}`) {
                        console.log(`     📄 ${endpoint.description}`);
                    }
                    
                    if (endpoint.parameters && endpoint.parameters.length > 0) {
                        const paramList = endpoint.parameters.map(p => {
                            const req = p.required ? '*' : '';
                            return `${p.name}${req}(${p.type})`;
                        }).join(', ');
                        console.log(`     📊 Parameters: ${paramList}`);
                    }
                });
            } else {
                console.log('\n⚠️ No endpoints discovered');
            }
            
            if (results.errors && results.errors.length > 0) {
                console.log('\n❌ Errors encountered:');
                results.errors.forEach(error => {
                    console.log(`  ${error.method}: ${error.message}`);
                });
            }
            
        } catch (error: any) {
            console.log(`\n💥 Discovery failed: ${error.message}`);
            if (error.stack) {
                console.log(`Stack: ${error.stack.split('\n').slice(0, 3).join('\n')}`);
            }
        }
        
        console.log('\n' + '='.repeat(70));
        
        // Small delay between tests
        await new Promise(resolve => setTimeout(resolve, 1500));
    }
    
    console.log('\n🎉 Enhanced discovery tests completed!');
    console.log('\n💡 Key findings:');
    console.log('   • Swagger/OpenAPI discovery finds comprehensive endpoint lists');
    console.log('   • Brute force discovery finds additional undocumented endpoints');
    console.log('   • Real-world APIs vary greatly in their discoverability');
    console.log('   • Authentication requirements can be detected from specs');
}

// Run the enhanced test
if (require.main === module) {
    testEnhancedDiscovery().catch(console.error);
} 