import { SecurityTester, SecurityTestConfig, SecurityTestResult } from './src/security/securityTester';
import { UserContext } from './src/security/authorizationTester';
import { APIEndpoint } from './src/types';

// Sample endpoints for testing
const testEndpoints: APIEndpoint[] = [
  {
    path: '/api/users',
    method: 'GET',
    url: 'https://jsonplaceholder.typicode.com/users',
    discoveredBy: ['swagger'],
    timestamp: new Date().toISOString()
  },
  {
    path: '/api/users/{id}',
    method: 'GET',
    url: 'https://jsonplaceholder.typicode.com/users/1',
    discoveredBy: ['swagger'],
    parameters: [
      { name: 'id', type: 'integer', required: true }
    ],
    timestamp: new Date().toISOString()
  },
  {
    path: '/api/posts',
    method: 'POST',
    url: 'https://jsonplaceholder.typicode.com/posts',
    discoveredBy: ['swagger'],
    timestamp: new Date().toISOString()
  },
  {
    path: '/basic-auth/{user}/{passwd}',
    method: 'GET',
    url: 'https://httpbin.org/basic-auth/user/pass',
    discoveredBy: ['swagger'],
    parameters: [
      { name: 'user', type: 'string', required: true },
      { name: 'passwd', type: 'string', required: true }
    ],
    authentication: {
      required: true,
      type: 'Basic'
    },
    timestamp: new Date().toISOString()
  },
  {
    path: '/bearer',
    method: 'GET',
    url: 'https://httpbin.org/bearer',
    discoveredBy: ['swagger'],
    authentication: {
      required: true,
      type: 'Bearer'
    },
    timestamp: new Date().toISOString()
  }
];

// Sample user contexts for authorization testing
const userContexts: UserContext[] = [
  {
    role: 'admin',
    authHeader: 'Bearer admin_token_12345',
    userId: '1',
    permissions: ['read', 'write', 'delete', 'admin']
  },
  {
    role: 'user',
    authHeader: 'Bearer user_token_67890',
    userId: '2',
    permissions: ['read', 'write']
  },
  {
    role: 'guest',
    authHeader: 'Bearer guest_token_abcde',
    userId: '3',
    permissions: ['read']
  },
  {
    role: 'anonymous',
    authHeader: '',
    permissions: []
  }
];

async function demonstrateSecurityTesting() {
  console.log('🛡️  API Security Testing Framework Demonstration\n');
  
  const securityTester = new SecurityTester();
  
  // Configuration for comprehensive security testing
  const testConfig: SecurityTestConfig = {
    includeAuthentication: true,
    includeAuthorization: true,
    includeDestructiveTesting: false, // Set to false for demo safety
    maxBruteForceAttempts: 3,
    timeout: 10000,
    userContexts: userContexts,
    testTypes: [
      'auth_bypass',
      'weak_credentials',
      'jwt_vulnerabilities',
      'privilege_escalation',
      'idor',
      'missing_access_control',
      'information_disclosure'
    ]
  };
  
  console.log('📋 Test Configuration:');
  console.log(`  • Authentication Testing: ${testConfig.includeAuthentication ? '✅' : '❌'}`);
  console.log(`  • Authorization Testing: ${testConfig.includeAuthorization ? '✅' : '❌'}`);
  console.log(`  • Destructive Testing: ${testConfig.includeDestructiveTesting ? '✅' : '❌'}`);
  console.log(`  • User Contexts: ${testConfig.userContexts.length}`);
  console.log(`  • Test Types: ${testConfig.testTypes.length}`);
  console.log(`  • Timeout: ${testConfig.timeout}ms\n`);
  
  // Test individual endpoints
  console.log('🔍 Testing Individual Endpoints:\n');
  
  for (let i = 0; i < testEndpoints.length; i++) {
    const endpoint = testEndpoints[i];
    
    console.log(`\n${i + 1}. Testing: ${endpoint.method} ${endpoint.path}`);
    console.log(`   URL: ${endpoint.url}`);
    console.log(`   Auth Required: ${endpoint.authentication?.required ? '🔒 Yes' : '🔓 No'}`);
    console.log('   ' + '─'.repeat(60));
    
    try {
      const startTime = Date.now();
      
      // Progress tracking
      let lastProgressUpdate = '';
      const progressCallback = (progress: any) => {
        const progressLine = `   [${progress.percentage.toFixed(0).padStart(3)}%] ${progress.phase} - ${progress.currentTest || ''}`;
        if (progressLine !== lastProgressUpdate) {
          process.stdout.write(`\r${progressLine}`);
          lastProgressUpdate = progressLine;
        }
      };
      
      const result = await securityTester.testEndpointSecurity(endpoint, testConfig, progressCallback);
      
      const duration = Date.now() - startTime;
      console.log(`\n   ✅ Testing completed in ${duration}ms`);
      
      // Display results summary
      console.log('\n   📊 SECURITY TEST RESULTS:');
      console.log(`   Total Tests Run: ${result.summary.totalTests}`);
      console.log(`   Vulnerabilities Found: ${result.summary.vulnerabilitiesFound}`);
      
      if (result.summary.vulnerabilitiesFound > 0) {
        console.log('   Severity Distribution:');
        if (result.summary.criticalVulns > 0) console.log(`     🔴 Critical: ${result.summary.criticalVulns}`);
        if (result.summary.highVulns > 0) console.log(`     🟠 High: ${result.summary.highVulns}`);
        if (result.summary.mediumVulns > 0) console.log(`     🟡 Medium: ${result.summary.mediumVulns}`);
        if (result.summary.lowVulns > 0) console.log(`     🟢 Low: ${result.summary.lowVulns}`);
      }
      
      console.log(`   Risk Score: ${result.summary.overallRiskScore}/100`);
      
      // Show detailed findings
      if (result.authenticationResults.some(r => r.vulnerable)) {
        console.log('\n   🔐 AUTHENTICATION VULNERABILITIES:');
        result.authenticationResults.filter(r => r.vulnerable).forEach((vuln, idx) => {
          console.log(`     ${idx + 1}. ${vuln.test.name} (${vuln.test.severity})`);
          console.log(`        ${vuln.test.description}`);
          console.log(`        Confidence: ${(vuln.confidence * 100).toFixed(0)}%`);
          console.log(`        CWE: ${vuln.test.cwe}`);
        });
      }
      
      if (result.authorizationResults.some(r => r.vulnerable)) {
        console.log('\n   🛡️  AUTHORIZATION VULNERABILITIES:');
        result.authorizationResults.filter(r => r.vulnerable).forEach((vuln, idx) => {
          console.log(`     ${idx + 1}. ${vuln.test.name} (${vuln.test.severity})`);
          console.log(`        ${vuln.test.description}`);
          console.log(`        Confidence: ${(vuln.confidence * 100).toFixed(0)}%`);
          console.log(`        Risk Level: ${vuln.riskLevel}`);
        });
      }
      
      if (result.summary.vulnerabilitiesFound === 0) {
        console.log('   ✅ No security vulnerabilities detected!');
      }
      
      // Show top recommendations
      if (result.recommendations.length > 0) {
        console.log('\n   💡 TOP RECOMMENDATIONS:');
        result.recommendations.slice(0, 3).forEach((rec, idx) => {
          console.log(`     ${idx + 1}. ${rec}`);
        });
      }
      
    } catch (error: any) {
      console.log(`\n   ❌ Testing failed: ${error.message}`);
    }
    
    console.log('\n' + '='.repeat(70));
    
    // Small delay between tests
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  
  // Bulk testing demonstration
  console.log('\n\n🔄 Bulk Security Testing Demonstration:\n');
  
  try {
    const bulkStartTime = Date.now();
    
    const bulkProgressCallback = (progress: any) => {
      const overallProgress = progress.overallProgress || progress.percentage;
      const endpointProgress = `${progress.endpointIndex + 1}/${progress.totalEndpoints}`;
      const progressLine = `[${overallProgress.toFixed(0).padStart(3)}%] Endpoint ${endpointProgress} - ${progress.phase}`;
      process.stdout.write(`\r${progressLine}`);
    };
    
    console.log('🔍 Testing all endpoints in bulk...');
    const bulkResults = await securityTester.testMultipleEndpoints(
      testEndpoints.slice(0, 3), // Test first 3 endpoints for demo
      testConfig,
      bulkProgressCallback
    );
    
    const bulkDuration = Date.now() - bulkStartTime;
    console.log(`\n✅ Bulk testing completed in ${(bulkDuration / 1000).toFixed(2)}s`);
    
    // Generate comprehensive security report
    console.log('\n📋 Generating Comprehensive Security Report...\n');
    
    const securityReport = securityTester.generateSecurityReport(bulkResults);
    
    console.log('🏢 EXECUTIVE SUMMARY:');
    console.log(`   Endpoints Tested: ${securityReport.executive_summary.total_endpoints_tested}`);
    console.log(`   Total Vulnerabilities: ${securityReport.executive_summary.total_vulnerabilities}`);
    console.log(`   Overall Security Score: ${securityReport.executive_summary.overall_security_score.toFixed(1)}/100`);
    
    console.log('\n📊 RISK DISTRIBUTION:');
    Object.entries(securityReport.executive_summary.risk_distribution).forEach(([severity, count]) => {
      if (count > 0) {
        const emoji = {
          critical: '🔴',
          high: '🟠', 
          medium: '🟡',
          low: '🟢'
        }[severity] || '⚪';
        console.log(`   ${emoji} ${severity.toUpperCase()}: ${count}`);
      }
    });
    
    console.log('\n🔍 DETAILED FINDINGS:');
    securityReport.detailed_findings.forEach((finding, idx) => {
      console.log(`   ${idx + 1}. ${finding.method} ${finding.endpoint}`);
      if (finding.vulnerabilities.length > 0) {
        finding.vulnerabilities.forEach(vuln => {
          console.log(`      🚨 ${vuln.type}: ${vuln.description} (${vuln.severity})`);
        });
      } else {
        console.log('      ✅ No vulnerabilities found');
      }
    });
    
    console.log('\n📋 OWASP API SECURITY TOP 10 COMPLIANCE:');
    securityReport.compliance_status.owasp_api_top_10.forEach(compliance => {
      const statusEmoji = {
        'PASS': '✅',
        'FAIL': '❌',
        'WARNING': '⚠️'
      }[compliance.status];
      
      console.log(`   ${statusEmoji} ${compliance.requirement}: ${compliance.status}`);
      if (compliance.findings.length > 0 && compliance.status !== 'PASS') {
        compliance.findings.slice(0, 2).forEach(finding => {
          console.log(`      • ${finding}`);
        });
      }
    });
    
    console.log('\n💡 SECURITY RECOMMENDATIONS:');
    securityReport.recommendations.slice(0, 5).forEach((rec, idx) => {
      console.log(`   ${idx + 1}. ${rec}`);
    });
    
  } catch (error: any) {
    console.log(`\n❌ Bulk testing failed: ${error.message}`);
  }
  
  console.log('\n🎉 Security Testing Framework Demonstration Complete!');
  
  console.log('\n🔬 FRAMEWORK CAPABILITIES DEMONSTRATED:');
  console.log('   ✅ Authentication Vulnerability Detection');
  console.log('   ✅ Authorization & Access Control Testing');
  console.log('   ✅ JWT & Token Vulnerability Analysis');
  console.log('   ✅ IDOR (Insecure Direct Object Reference) Testing');
  console.log('   ✅ Privilege Escalation Detection');
  console.log('   ✅ Brute Force Protection Analysis');
  console.log('   ✅ Information Disclosure Detection');
  console.log('   ✅ OWASP API Top 10 Compliance Checking');
  console.log('   ✅ Real-time Progress Tracking');
  console.log('   ✅ Comprehensive Security Reporting');
  console.log('   ✅ Risk Scoring & Prioritization');
  
  console.log('\n🚀 Next Steps:');
  console.log('   • Integrate with discovered endpoints from endpoint discovery');
  console.log('   • Add parameter vulnerability testing');
  console.log('   • Implement AI-enhanced threat analysis');
  console.log('   • Create visual risk dashboard');
  console.log('   • Add compliance reporting for multiple standards');
}

// Run the demonstration
if (require.main === module) {
  demonstrateSecurityTesting().catch(console.error);
} 