const { EndpointDiscovery } = require('./dist/discovery/endpointDiscovery');

async function testRealAPIs() {
    console.log('🚀 Testing API Endpoint Discovery Engine on Real APIs\n');
    
    const discovery = new EndpointDiscovery();
    
    // Test targets with different characteristics
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
        },
        {
            name: 'GitHub API',
            url: 'https://api.github.com',
            description: 'Enterprise API with comprehensive documentation'
        },
        {
            name: 'ReqRes API',
            url: 'https://reqres.in',
            description: 'Testing API with mock data'
        }
    ];

    for (const target of testTargets) {
        console.log(`\n🎯 Testing: ${target.name}`);
        console.log(`📍 URL: ${target.url}`);
        console.log(`📋 Description: ${target.description}`);
        console.log('─'.repeat(60));
        
        try {
            const startTime = Date.now();
            
            // Configure discovery options
            const options = {
                depth: 'comprehensive', // basic, comprehensive, deep
                timeout: 10000,
                maxConcurrent: 5,
                includeAuthenticated: true,
                followRedirects: true
            };
            
            // Progress callback for real-time updates
            const progressCallback = (progress) => {
                const bar = '█'.repeat(Math.floor(progress.percentage / 5)) + 
                           '░'.repeat(20 - Math.floor(progress.percentage / 5));
                process.stdout.write(`\r[${bar}] ${progress.percentage.toFixed(1)}% - ${progress.phase}`);
            };
            
            console.log('\n🔍 Starting discovery...');
            const results = await discovery.discoverEndpoints(target.url, options, progressCallback);
            
            const duration = ((Date.now() - startTime) / 1000).toFixed(2);
            console.log(`\n\n✅ Discovery completed in ${duration}s`);
            
            // Display results summary
            console.log('\n📊 DISCOVERY SUMMARY:');
            console.log(`Total endpoints found: ${results.endpoints.length}`);
            console.log(`Discovery methods used: ${results.discoveryMethods.length}`);
            
            // Breakdown by discovery method
            const methodBreakdown = {};
            results.endpoints.forEach(endpoint => {
                endpoint.discoveredBy.forEach(method => {
                    methodBreakdown[method] = (methodBreakdown[method] || 0) + 1;
                });
            });
            
            console.log('\n🔬 Endpoints by discovery method:');
            Object.entries(methodBreakdown).forEach(([method, count]) => {
                console.log(`  ${method}: ${count} endpoints`);
            });
            
            // Show HTTP methods found
            const httpMethods = [...new Set(results.endpoints.map(e => e.method))];
            console.log(`\n🌐 HTTP methods found: ${httpMethods.join(', ')}`);
            
            // Show some example endpoints
            console.log('\n📝 Sample endpoints found:');
            results.endpoints.slice(0, 10).forEach((endpoint, index) => {
                const authInfo = endpoint.authentication ? ` [Auth: ${endpoint.authentication.type}]` : '';
                console.log(`  ${index + 1}. ${endpoint.method} ${endpoint.path}${authInfo}`);
                if (endpoint.parameters && endpoint.parameters.length > 0) {
                    console.log(`     Parameters: ${endpoint.parameters.map(p => p.name).join(', ')}`);
                }
            });
            
            if (results.endpoints.length > 10) {
                console.log(`     ... and ${results.endpoints.length - 10} more endpoints`);
            }
            
            // Show metadata if available
            if (results.metadata) {
                console.log('\n📋 API Metadata:');
                if (results.metadata.title) console.log(`  Title: ${results.metadata.title}`);
                if (results.metadata.version) console.log(`  Version: ${results.metadata.version}`);
                if (results.metadata.description) console.log(`  Description: ${results.metadata.description}`);
                if (results.metadata.baseUrl) console.log(`  Base URL: ${results.metadata.baseUrl}`);
            }
            
            // Show any errors encountered
            if (results.errors && results.errors.length > 0) {
                console.log('\n⚠️ Errors encountered:');
                results.errors.forEach(error => {
                    console.log(`  ${error.method}: ${error.message}`);
                });
            }
            
        } catch (error) {
            console.log(`\n❌ Discovery failed: ${error.message}`);
            console.log(`Error details: ${error.stack}`);
        }
        
        console.log('\n' + '='.repeat(60));
        
        // Add a small delay between tests
        await new Promise(resolve => setTimeout(resolve, 2000));
    }
    
    console.log('\n🎉 All API discovery tests completed!');
}

// Additional function to test a custom API if provided
async function testCustomAPI(url) {
    console.log(`\n🔧 Testing custom API: ${url}`);
    console.log('─'.repeat(60));
    
    const discovery = new EndpointDiscovery();
    
    try {
        const options = {
            depth: 'deep',
            timeout: 15000,
            maxConcurrent: 3,
            includeAuthenticated: true,
            followRedirects: true
        };
        
        const progressCallback = (progress) => {
            console.log(`[${progress.percentage.toFixed(1)}%] ${progress.phase} - ${progress.currentOperation || ''}`);
        };
        
        const results = await discovery.discoverEndpoints(url, options, progressCallback);
        
        console.log('\n✅ Custom API discovery completed!');
        console.log(`Found ${results.endpoints.length} endpoints`);
        
        // Show all endpoints for custom API
        if (results.endpoints.length > 0) {
            console.log('\n📝 All endpoints found:');
            results.endpoints.forEach((endpoint, index) => {
                console.log(`  ${index + 1}. ${endpoint.method} ${endpoint.path}`);
                if (endpoint.description) {
                    console.log(`     Description: ${endpoint.description}`);
                }
                if (endpoint.parameters && endpoint.parameters.length > 0) {
                    console.log(`     Parameters: ${endpoint.parameters.map(p => `${p.name} (${p.type})`).join(', ')}`);
                }
            });
        }
        
        return results;
        
    } catch (error) {
        console.log(`\n❌ Custom API discovery failed: ${error.message}`);
        throw error;
    }
}

// Main execution
async function main() {
    try {
        // Check if a custom URL was provided as command line argument
        const customUrl = process.argv[2];
        
        if (customUrl) {
            await testCustomAPI(customUrl);
        } else {
            await testRealAPIs();
        }
        
    } catch (error) {
        console.error('\n💥 Test execution failed:', error.message);
        process.exit(1);
    }
}

// Run the tests
if (require.main === module) {
    main();
}

module.exports = { testRealAPIs, testCustomAPI }; 