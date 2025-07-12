import axios from 'axios';

// Simplified types for testing
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

// Simplified Swagger Discovery for testing
class SwaggerDiscovery {
  async discoverEndpoints(
    baseUrl: string,
    options: { timeout?: number } = {},
    progressCallback?: (progress: DiscoveryProgress) => void
  ): Promise<APIEndpoint[]> {
    const { timeout = 10000 } = options;
    const endpoints: APIEndpoint[] = [];
    
    console.log('🔍 Starting Swagger/OpenAPI discovery...');
    
    // Common OpenAPI/Swagger paths to check
    const swaggerPaths = [
      '/swagger.json',
      '/swagger.yaml', 
      '/api-docs',
      '/api/swagger.json',
      '/api/swagger.yaml',
      '/api/api-docs',
      '/swagger/v1/swagger.json',
      '/v2/api-docs',
      '/v3/api-docs',
      '/openapi.json',
      '/openapi.yaml',
      '/docs/swagger.json',
      '/swagger-ui.html',
      '/api/swagger-ui.html',
      '/swagger/index.html'
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
            'Accept': 'application/json, application/yaml, text/yaml, */*',
            'User-Agent': 'API-Discovery-Tool'
          }
        });
        
        if (response.status === 200 && response.data) {
          console.log(`✅ Found OpenAPI spec at: ${path}`);
          
          const parsedEndpoints = this.parseOpenAPISpec(response.data, baseUrl);
          endpoints.push(...parsedEndpoints);
          
          // If we found a spec, we can break (or continue to find more)
          if (parsedEndpoints.length > 0) {
            console.log(`📋 Extracted ${parsedEndpoints.length} endpoints from OpenAPI spec`);
          }
        }
      } catch (error: any) {
        // Silently continue - most paths won't exist
        if (error.response?.status !== 404) {
          console.log(`⚠️ Error accessing ${path}: ${error.message}`);
        }
      }
    }
    
    return endpoints;
  }
  
  private parseOpenAPISpec(spec: any, baseUrl: string): APIEndpoint[] {
    const endpoints: APIEndpoint[] = [];
    
    try {
      let parsedSpec = spec;
      
      // If it's a string, try to parse as JSON
      if (typeof spec === 'string') {
        try {
          parsedSpec = JSON.parse(spec);
        } catch {
          // Might be YAML - for now skip parsing
          console.log('⚠️ Found spec but could not parse (might be YAML)');
          return endpoints;
        }
      }
      
      // Extract server base URL
      let serverBase = baseUrl;
      if (parsedSpec.servers && parsedSpec.servers.length > 0) {
        const server = parsedSpec.servers[0];
        if (server.url) {
          serverBase = server.url.startsWith('http') ? server.url : baseUrl + server.url;
        }
      } else if (parsedSpec.host) {
        const scheme = parsedSpec.schemes?.[0] || 'https';
        const basePath = parsedSpec.basePath || '';
        serverBase = `${scheme}://${parsedSpec.host}${basePath}`;
      }
      
      // Parse paths
      if (parsedSpec.paths) {
        for (const [path, pathObj] of Object.entries(parsedSpec.paths as any)) {
          for (const [method, methodObj] of Object.entries(pathObj as any)) {
            if (['get', 'post', 'put', 'delete', 'patch', 'head', 'options'].includes(method.toLowerCase())) {
              const endpoint: APIEndpoint = {
                path: path,
                method: method.toUpperCase(),
                url: `${serverBase.replace(/\/$/, '')}${path}`,
                discoveredBy: ['swagger'],
                description: (methodObj as any)?.summary || (methodObj as any)?.description,
                timestamp: new Date().toISOString()
              };
              
              // Extract parameters
              if ((methodObj as any)?.parameters) {
                endpoint.parameters = (methodObj as any).parameters.map((param: any) => ({
                  name: param.name,
                  type: param.type || param.schema?.type || 'unknown',
                  required: param.required || false
                }));
              }
              
              // Check for authentication
              if ((methodObj as any)?.security || parsedSpec.security) {
                endpoint.authentication = {
                  required: true,
                  type: 'Unknown'
                };
              }
              
              endpoints.push(endpoint);
            }
          }
        }
      }
      
    } catch (error: any) {
      console.log(`⚠️ Error parsing OpenAPI spec: ${error.message}`);
    }
    
    return endpoints;
  }
}

// Simple brute force discovery
class BruteForceDiscovery {
  private readonly commonEndpoints = [
    '/api/users', '/api/user', '/users', '/user',
    '/api/auth', '/auth', '/login', '/logout',
    '/api/data', '/data', '/api/items', '/items',
    '/api/health', '/health', '/api/status', '/status',
    '/api/v1', '/api/v2', '/v1', '/v2',
    '/admin', '/api/admin',
    '/docs', '/api-docs', '/swagger'
  ];
  
  async discoverEndpoints(
    baseUrl: string,
    options: { timeout?: number, maxEndpoints?: number } = {},
    progressCallback?: (progress: DiscoveryProgress) => void
  ): Promise<APIEndpoint[]> {
    const { timeout = 5000, maxEndpoints = 10 } = options;
    const endpoints: APIEndpoint[] = [];
    
    console.log('🔍 Starting brute force discovery...');
    
    for (let i = 0; i < Math.min(this.commonEndpoints.length, maxEndpoints); i++) {
      const path = this.commonEndpoints[i];
      const fullUrl = `${baseUrl.replace(/\/$/, '')}${path}`;
      
      if (progressCallback) {
        progressCallback({
          phase: 'brute-force-discovery',
          percentage: (i / Math.min(this.commonEndpoints.length, maxEndpoints)) * 100,
          currentOperation: `Testing ${path}`
        });
      }
      
      try {
        const response = await axios.get(fullUrl, { 
          timeout,
          validateStatus: (status) => status < 500,
          headers: {
            'User-Agent': 'API-Discovery-Tool'
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
              headers: {},
              contentType: response.headers['content-type'] || 'unknown'
            },
            timestamp: new Date().toISOString()
          });
        }
      } catch (error: any) {
        // Silently continue
      }
    }
    
    return endpoints;
  }
}

// Main discovery orchestrator
class EndpointDiscovery {
  private swaggerDiscovery = new SwaggerDiscovery();
  private bruteForceDiscovery = new BruteForceDiscovery();
  
  async discoverEndpoints(
    baseUrl: string,
    options: {
      depth?: 'basic' | 'comprehensive' | 'deep';
      timeout?: number;
      maxConcurrent?: number;
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
          phase: 'Starting discovery',
          percentage: 0,
          currentOperation: 'Initializing Swagger discovery'
        });
      }
      
      const swaggerEndpoints = await this.swaggerDiscovery.discoverEndpoints(baseUrl, { timeout }, progressCallback);
      allEndpoints.push(...swaggerEndpoints);
      if (swaggerEndpoints.length > 0) {
        discoveryMethods.push('swagger');
      }
      
      // Brute force discovery (limited for basic testing)
      if (depth !== 'basic') {
        if (progressCallback) {
          progressCallback({
            phase: 'brute-force-discovery',
            percentage: 50,
            currentOperation: 'Starting brute force discovery'
          });
        }
        
        const bruteForceEndpoints = await this.bruteForceDiscovery.discoverEndpoints(
          baseUrl, 
          { timeout, maxEndpoints: depth === 'deep' ? 20 : 10 }, 
          progressCallback
        );
        allEndpoints.push(...bruteForceEndpoints);
        if (bruteForceEndpoints.length > 0) {
          discoveryMethods.push('brute-force');
        }
      }
      
      if (progressCallback) {
        progressCallback({
          phase: 'Discovery complete',
          percentage: 100,
          currentOperation: 'Finalizing results'
        });
      }
      
    } catch (error: any) {
      console.error(`❌ Discovery error: ${error.message}`);
      errors.push({ method: 'general', message: error.message });
    }
    
    // Remove duplicates
    const uniqueEndpoints = this.deduplicateEndpoints(allEndpoints);
    
    return {
      endpoints: uniqueEndpoints,
      discoveryMethods,
      errors,
      metadata: {
        title: 'API Discovery Results',
        baseUrl,
        discoveredAt: new Date().toISOString()
      }
    };
  }
  
  private deduplicateEndpoints(endpoints: APIEndpoint[]): APIEndpoint[] {
    const seen = new Set<string>();
    const unique: APIEndpoint[] = [];
    
    for (const endpoint of endpoints) {
      const key = `${endpoint.method}:${endpoint.path}`;
      if (!seen.has(key)) {
        seen.add(key);
        unique.push(endpoint);
      }
    }
    
    return unique;
  }
}

// Test function
async function testRealAPIs() {
    console.log('🚀 Testing API Endpoint Discovery Engine on Real APIs\n');
    
    const discovery = new EndpointDiscovery();
    
    // Test targets
    const testTargets = [
        {
            name: 'Swagger Petstore (OpenAPI)',
            url: 'https://petstore.swagger.io',
            description: 'Classic example with full OpenAPI spec'
        },
        {
            name: 'JSONPlaceholder',
            url: 'https://jsonplaceholder.typicode.com',
            description: 'Simple REST API for testing'
        }
    ];

    for (const target of testTargets) {
        console.log(`\n🎯 Testing: ${target.name}`);
        console.log(`📍 URL: ${target.url}`);
        console.log(`📋 Description: ${target.description}`);
        console.log('─'.repeat(60));
        
        try {
            const startTime = Date.now();
            
            const options = {
                depth: 'comprehensive' as const,
                timeout: 10000,
                maxConcurrent: 5
            };
            
            const progressCallback = (progress: DiscoveryProgress) => {
                const bar = '█'.repeat(Math.floor(progress.percentage / 5)) + 
                           '░'.repeat(20 - Math.floor(progress.percentage / 5));
                process.stdout.write(`\r[${bar}] ${progress.percentage.toFixed(1)}% - ${progress.phase}`);
            };
            
            console.log('\n🔍 Starting discovery...');
            const results = await discovery.discoverEndpoints(target.url, options, progressCallback);
            
            const duration = ((Date.now() - startTime) / 1000).toFixed(2);
            console.log(`\n\n✅ Discovery completed in ${duration}s`);
            
            console.log('\n📊 DISCOVERY SUMMARY:');
            console.log(`Total endpoints found: ${results.endpoints.length}`);
            console.log(`Discovery methods used: ${results.discoveryMethods.join(', ')}`);
            
            const methodBreakdown: Record<string, number> = {};
            results.endpoints.forEach(endpoint => {
                endpoint.discoveredBy.forEach(method => {
                    methodBreakdown[method] = (methodBreakdown[method] || 0) + 1;
                });
            });
            
            console.log('\n🔬 Endpoints by discovery method:');
            Object.entries(methodBreakdown).forEach(([method, count]) => {
                console.log(`  ${method}: ${count} endpoints`);
            });
            
            const httpMethods = [...new Set(results.endpoints.map(e => e.method))];
            console.log(`\n🌐 HTTP methods found: ${httpMethods.join(', ')}`);
            
            console.log('\n📝 Sample endpoints found:');
            results.endpoints.slice(0, 10).forEach((endpoint, index) => {
                const authInfo = endpoint.authentication ? ` [Auth Required]` : '';
                console.log(`  ${index + 1}. ${endpoint.method} ${endpoint.path}${authInfo}`);
                if (endpoint.description) {
                    console.log(`     Description: ${endpoint.description}`);
                }
                if (endpoint.parameters && endpoint.parameters.length > 0) {
                    console.log(`     Parameters: ${endpoint.parameters.map(p => p.name).join(', ')}`);
                }
            });
            
            if (results.endpoints.length > 10) {
                console.log(`     ... and ${results.endpoints.length - 10} more endpoints`);
            }
            
            if (results.errors && results.errors.length > 0) {
                console.log('\n⚠️ Errors encountered:');
                results.errors.forEach(error => {
                    console.log(`  ${error.method}: ${error.message}`);
                });
            }
            
        } catch (error: any) {
            console.log(`\n❌ Discovery failed: ${error.message}`);
        }
        
        console.log('\n' + '='.repeat(60));
        await new Promise(resolve => setTimeout(resolve, 2000));
    }
    
    console.log('\n🎉 All API discovery tests completed!');
}

// Run if this is the main module
if (require.main === module) {
    testRealAPIs().catch(console.error);
} 