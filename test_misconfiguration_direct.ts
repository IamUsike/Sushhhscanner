import axios from 'axios';

// Simplified types for testing
interface MisconfigurationResult {
  category: string;
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence: number;
  title: string;
  description: string;
  evidence: {
    url?: string;
    response?: string;
    headers?: Record<string, string>;
    statusCode?: number;
    file?: string;
    content?: string;
  };
  cwe: string;
  owasp: string;
  recommendation: string;
  impact: string;
}

// Simplified Misconfiguration Detector
class MisconfigurationDetector {
  private readonly sensitiveFiles = [
    '.env', '.env.local', '.env.production', 
    'config.json', 'package.json', 'composer.json',
    'web.config', 'robots.txt', 'sitemap.xml',
    'phpinfo.php', 'admin', 'login', 'config'
  ];

  private readonly sensitivePaths = [
    '/admin', '/administrator', '/login', '/config',
    '/backup', '/logs', '/test', '/debug',
    '/api/docs', '/swagger', '/docs',
    '/.git', '/.env', '/server-status'
  ];

  async scanTarget(baseUrl: string): Promise<MisconfigurationResult[]> {
    console.log(`🔍 Starting misconfiguration scan for: ${baseUrl}`);
    const results: MisconfigurationResult[] = [];

    try {
      // 1. Check HTTP Security Headers
      console.log('🛡️ Checking HTTP security headers...');
      const headerResults = await this.checkSecurityHeaders(baseUrl);
      results.push(...headerResults);

      // 2. Check for Sensitive File Exposure
      console.log('📄 Scanning for exposed sensitive files...');
      const fileResults = await this.checkSensitiveFiles(baseUrl);
      results.push(...fileResults);

      // 3. Check Directory Configurations
      console.log('📁 Checking directory configurations...');
      const directoryResults = await this.checkDirectoryMisconfigurations(baseUrl);
      results.push(...directoryResults);

      // 4. Check Server Information Disclosure
      console.log('🖥️ Analyzing server information disclosure...');
      const serverResults = await this.checkServerInformation(baseUrl);
      results.push(...serverResults);

      // 5. Check CORS Configuration
      console.log('🌐 Testing CORS configurations...');
      const corsResults = await this.checkCORSMisconfiguration(baseUrl);
      results.push(...corsResults);

      return results;

    } catch (error: any) {
      console.log(`❌ Misconfiguration scan failed: ${error.message}`);
      return results;
    }
  }

  private async checkSecurityHeaders(baseUrl: string): Promise<MisconfigurationResult[]> {
    const results: MisconfigurationResult[] = [];

    try {
      const response = await this.makeRequest(baseUrl);
      const headers = response.headers;

      // Security headers to check
      const securityHeaders = {
        'strict-transport-security': {
          name: 'HTTP Strict Transport Security (HSTS)',
          severity: 'HIGH' as const
        },
        'content-security-policy': {
          name: 'Content Security Policy (CSP)',
          severity: 'MEDIUM' as const
        },
        'x-frame-options': {
          name: 'X-Frame-Options',
          severity: 'MEDIUM' as const
        },
        'x-content-type-options': {
          name: 'X-Content-Type-Options',
          severity: 'LOW' as const
        },
        'referrer-policy': {
          name: 'Referrer Policy',
          severity: 'LOW' as const
        }
      };

      for (const [headerName, headerInfo] of Object.entries(securityHeaders)) {
        if (!headers[headerName] && !headers[headerName.toLowerCase()]) {
          results.push({
            category: 'HTTP Security Headers',
            type: 'missing_security_header',
            severity: headerInfo.severity,
            confidence: 0.9,
            title: `Missing ${headerInfo.name}`,
            description: `The response is missing the ${headerInfo.name} header.`,
            evidence: {
              url: baseUrl,
              headers: { 'status': response.status.toString() },
              statusCode: response.status
            },
            cwe: 'CWE-693',
            owasp: 'A05:2021 – Security Misconfiguration',
            recommendation: `Implement the ${headerInfo.name} header with appropriate values.`,
            impact: `Missing ${headerInfo.name} header can expose the application to security vulnerabilities.`
          });
        }
      }

      // Check for information disclosure headers
      const disclosureHeaders = ['server', 'x-powered-by', 'x-aspnet-version'];
      for (const headerName of disclosureHeaders) {
        const headerValue = headers[headerName] || headers[headerName.toLowerCase()];
        if (headerValue) {
          results.push({
            category: 'Information Disclosure',
            type: 'server_information_disclosure',
            severity: 'LOW',
            confidence: 0.8,
            title: `Server Information Disclosure in ${headerName.toUpperCase()} Header`,
            description: `The ${headerName.toUpperCase()} header reveals server information.`,
            evidence: {
              url: baseUrl,
              headers: { [headerName]: headerValue },
              statusCode: response.status
            },
            cwe: 'CWE-200',
            owasp: 'A05:2021 – Security Misconfiguration',
            recommendation: `Remove or minimize information in the ${headerName.toUpperCase()} header.`,
            impact: 'Information disclosure can help attackers identify vulnerabilities.'
          });
        }
      }

    } catch (error: any) {
      console.log(`⚠️ Failed to check security headers: ${error.message}`);
    }

    return results;
  }

  private async checkSensitiveFiles(baseUrl: string): Promise<MisconfigurationResult[]> {
    const results: MisconfigurationResult[] = [];

    for (const file of this.sensitiveFiles) {
      try {
        const fileUrl = `${baseUrl.replace(/\/$/, '')}/${file}`;
        const response = await this.makeRequest(fileUrl);

        if (response.status === 200 && response.data && this.isValidContent(response.data)) {
          const severity = this.getSensitiveFileSeverity(file);
          
          results.push({
            category: 'Sensitive File Exposure',
            type: 'exposed_sensitive_file',
            severity,
            confidence: 0.9,
            title: `Exposed Sensitive File: ${file}`,
            description: `The sensitive file "${file}" is publicly accessible.`,
            evidence: {
              url: fileUrl,
              response: this.truncateContent(response.data),
              statusCode: response.status,
              file: file
            },
            cwe: 'CWE-200',
            owasp: 'A05:2021 – Security Misconfiguration',
            recommendation: `Remove or restrict access to the sensitive file "${file}".`,
            impact: 'Exposed sensitive files can reveal configuration details or credentials.'
          });
        }
      } catch (error: any) {
        // Expected for most files
      }
    }

    return results;
  }

  private async checkDirectoryMisconfigurations(baseUrl: string): Promise<MisconfigurationResult[]> {
    const results: MisconfigurationResult[] = [];

    for (const path of this.sensitivePaths) {
      try {
        const dirUrl = `${baseUrl.replace(/\/$/, '')}${path}`;
        const response = await this.makeRequest(dirUrl);

        // Check for directory listing
        if (response.status === 200 && this.isDirectoryListing(response.data)) {
          results.push({
            category: 'Directory Misconfiguration',
            type: 'directory_listing_enabled',
            severity: 'MEDIUM',
            confidence: 0.85,
            title: `Directory Listing Enabled: ${path}`,
            description: `Directory listing is enabled for "${path}".`,
            evidence: {
              url: dirUrl,
              response: this.truncateContent(response.data),
              statusCode: response.status
            },
            cwe: 'CWE-548',
            owasp: 'A05:2021 – Security Misconfiguration',
            recommendation: `Disable directory listing for "${path}".`,
            impact: 'Directory listings can reveal sensitive files and directory structure.'
          });
        }

        // Check for accessible admin interfaces
        if (response.status === 200 && this.isAdminInterface(response.data, path)) {
          results.push({
            category: 'Administrative Interface',
            type: 'exposed_admin_interface',
            severity: 'HIGH',
            confidence: 0.8,
            title: `Exposed Administrative Interface: ${path}`,
            description: `An administrative interface is accessible at "${path}".`,
            evidence: {
              url: dirUrl,
              response: this.truncateContent(response.data),
              statusCode: response.status
            },
            cwe: 'CWE-284',
            owasp: 'A01:2021 – Broken Access Control',
            recommendation: `Restrict access to the administrative interface "${path}".`,
            impact: 'Exposed administrative interfaces can provide unauthorized access.'
          });
        }

      } catch (error: any) {
        // Expected for most paths
      }
    }

    return results;
  }

  private async checkServerInformation(baseUrl: string): Promise<MisconfigurationResult[]> {
    const results: MisconfigurationResult[] = [];

    try {
      // Check for server info pages
      const infoPages = ['/server-status', '/info', '/phpinfo.php'];
      
      for (const page of infoPages) {
        try {
          const infoUrl = `${baseUrl.replace(/\/$/, '')}${page}`;
          const response = await this.makeRequest(infoUrl);

          if (response.status === 200 && this.isServerInfoPage(response.data)) {
            results.push({
              category: 'Information Disclosure',
              type: 'server_info_page',
              severity: 'MEDIUM',
              confidence: 0.9,
              title: `Server Information Page Exposed: ${page}`,
              description: `A server information page is accessible at "${page}".`,
              evidence: {
                url: infoUrl,
                response: this.truncateContent(response.data),
                statusCode: response.status
              },
              cwe: 'CWE-200',
              owasp: 'A05:2021 – Security Misconfiguration',
              recommendation: `Remove or restrict access to the server information page "${page}".`,
              impact: 'Server information pages can reveal system details.'
            });
          }
        } catch (error: any) {
          // Expected for most pages
        }
      }

    } catch (error: any) {
      console.log(`⚠️ Failed to check server information: ${error.message}`);
    }

    return results;
  }

  private async checkCORSMisconfiguration(baseUrl: string): Promise<MisconfigurationResult[]> {
    const results: MisconfigurationResult[] = [];

    try {
      const testOrigins = ['https://evil.com', 'http://malicious.com', 'null'];

      for (const origin of testOrigins) {
        try {
          const response = await this.makeRequest(baseUrl, {
            headers: { 'Origin': origin }
          });

          const corsHeader = response.headers['access-control-allow-origin'];
          
          if (corsHeader === '*' || corsHeader === origin) {
            const severity = corsHeader === '*' ? 'HIGH' : 'MEDIUM';
            
            results.push({
              category: 'CORS Misconfiguration',
              type: 'cors_wildcard_or_reflection',
              severity,
              confidence: 0.9,
              title: `CORS Misconfiguration: ${corsHeader === '*' ? 'Wildcard Origin' : 'Origin Reflection'}`,
              description: `The server accepts ${corsHeader === '*' ? 'wildcard origins' : `reflected origin "${origin}"`}.`,
              evidence: {
                url: baseUrl,
                headers: {
                  'Origin': origin,
                  'Access-Control-Allow-Origin': corsHeader
                },
                statusCode: response.status
              },
              cwe: 'CWE-346',
              owasp: 'A05:2021 – Security Misconfiguration',
              recommendation: 'Configure CORS to only allow trusted origins.',
              impact: 'Misconfigured CORS can enable cross-origin attacks.'
            });
          }
        } catch (error: any) {
          // Expected for some requests
        }
      }

    } catch (error: any) {
      console.log(`⚠️ Failed to check CORS configuration: ${error.message}`);
    }

    return results;
  }

  private async makeRequest(url: string, config: { headers?: Record<string, string> } = {}): Promise<any> {
    return await axios({
      method: 'GET',
      url,
      timeout: 10000,
      validateStatus: () => true,
      headers: {
        'User-Agent': 'API-Security-Scanner/1.0',
        'Accept': 'text/html,application/json,*/*',
        ...config.headers
      }
    });
  }

  private isValidContent(content: string): boolean {
    if (!content || content.length < 10) return false;
    const errorIndicators = ['404', 'not found', 'error', 'forbidden'];
    const lowerContent = content.toLowerCase();
    return !errorIndicators.some(indicator => lowerContent.includes(indicator));
  }

  private isDirectoryListing(content: string): boolean {
    if (!content) return false;
    const listingIndicators = ['index of', 'directory listing', 'parent directory', '<pre>', '[dir]'];
    const lowerContent = content.toLowerCase();
    return listingIndicators.some(indicator => lowerContent.includes(indicator));
  }

  private isAdminInterface(content: string, path: string): boolean {
    if (!content) return false;
    const adminIndicators = ['admin', 'login', 'username', 'password', 'dashboard'];
    const lowerContent = content.toLowerCase();
    const hasAdminContent = adminIndicators.some(indicator => lowerContent.includes(indicator));
    const isAdminPath = ['/admin', '/login'].some(p => path.includes(p));
    return hasAdminContent && isAdminPath;
  }

  private isServerInfoPage(content: string): boolean {
    if (!content) return false;
    const infoIndicators = ['phpinfo()', 'apache status', 'server status', 'system information'];
    const lowerContent = content.toLowerCase();
    return infoIndicators.some(indicator => lowerContent.includes(indicator));
  }

  private getSensitiveFileSeverity(filename: string): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
    const criticalFiles = ['.env', 'config.json'];
    const highFiles = ['package.json', 'composer.json', 'web.config'];
    const mediumFiles = ['robots.txt', 'phpinfo.php'];
    
    if (criticalFiles.some(f => filename.includes(f))) return 'CRITICAL';
    if (highFiles.some(f => filename.includes(f))) return 'HIGH';
    if (mediumFiles.some(f => filename.includes(f))) return 'MEDIUM';
    return 'LOW';
  }

  private truncateContent(content: string): string {
    const str = typeof content === 'string' ? content : JSON.stringify(content);
    return str.length > 300 ? str.substring(0, 300) + '...[truncated]' : str;
  }
}

// Demonstration Function
async function demonstrateMisconfigurationScanning() {
  console.log('🛡️ Misconfiguration Detection System - Live Demonstration\n');

  // Test targets with different configurations
  const testTargets = [
    'https://httpbin.org',
    'https://jsonplaceholder.typicode.com',
    'https://reqres.in',
    'https://example.com'
  ];

  const detector = new MisconfigurationDetector();
  const allResults: any[] = [];

  console.log(`🎯 Testing ${testTargets.length} targets for misconfigurations...\n`);

  for (let i = 0; i < testTargets.length; i++) {
    const target = testTargets[i];
    
    console.log(`\n${'='.repeat(60)}`);
    console.log(`🔍 SCANNING TARGET ${i + 1}/${testTargets.length}: ${target}`);
    console.log(`${'='.repeat(60)}`);
    
    const startTime = Date.now();
    
    try {
      const findings = await detector.scanTarget(target);
      const duration = Date.now() - startTime;
      
      console.log(`\n📊 SCAN RESULTS FOR ${target}:`);
      console.log(`⏱️ Scan Duration: ${duration}ms`);
      console.log(`🔍 Total Issues Found: ${findings.length}`);
      
      // Group by severity
      const severityCount = {
        CRITICAL: findings.filter(f => f.severity === 'CRITICAL').length,
        HIGH: findings.filter(f => f.severity === 'HIGH').length,
        MEDIUM: findings.filter(f => f.severity === 'MEDIUM').length,
        LOW: findings.filter(f => f.severity === 'LOW').length
      };
      
      console.log(`🚨 Severity Breakdown:`);
      if (severityCount.CRITICAL > 0) console.log(`  🔴 CRITICAL: ${severityCount.CRITICAL}`);
      if (severityCount.HIGH > 0) console.log(`  🟠 HIGH: ${severityCount.HIGH}`);
      if (severityCount.MEDIUM > 0) console.log(`  🟡 MEDIUM: ${severityCount.MEDIUM}`);
      if (severityCount.LOW > 0) console.log(`  🟢 LOW: ${severityCount.LOW}`);
      
      if (findings.length > 0) {
        console.log(`\n🔥 DETECTED MISCONFIGURATIONS:`);
        findings.forEach((finding, idx) => {
          const severityEmoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'INFO': '🔵'
          }[finding.severity] || '⚪';
          
          console.log(`\n  ${idx + 1}. ${severityEmoji} ${finding.title} (${finding.severity})`);
          console.log(`     📂 Category: ${finding.category}`);
          console.log(`     📝 Description: ${finding.description}`);
          console.log(`     🎯 Confidence: ${(finding.confidence * 100).toFixed(0)}%`);
          console.log(`     🔗 CWE: ${finding.cwe}`);
          console.log(`     📋 Impact: ${finding.impact}`);
          console.log(`     💡 Recommendation: ${finding.recommendation}`);
          
          if (finding.evidence.url) {
            console.log(`     🌐 URL: ${finding.evidence.url}`);
          }
          if (finding.evidence.statusCode) {
            console.log(`     📊 Status Code: ${finding.evidence.statusCode}`);
          }
        });
      } else {
        console.log(`\n✅ No misconfigurations detected for ${target}!`);
      }
      
      allResults.push({
        target,
        findings,
        scanDuration: duration,
        severityBreakdown: severityCount
      });
      
    } catch (error: any) {
      console.log(`\n❌ Scan failed for ${target}: ${error.message}`);
    }
    
    // Small delay between scans
    if (i < testTargets.length - 1) {
      console.log('\n⏳ Waiting before next scan...');
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
  }

  // Summary Report
  console.log(`\n\n${'='.repeat(70)}`);
  console.log('📊 COMPREHENSIVE MISCONFIGURATION SCAN SUMMARY');
  console.log(`${'='.repeat(70)}`);
  
  const totalIssues = allResults.reduce((sum, r) => sum + r.findings.length, 0);
  const avgDuration = allResults.reduce((sum, r) => sum + r.scanDuration, 0) / allResults.length;
  
  console.log(`🎯 Targets Scanned: ${allResults.length}`);
  console.log(`🔍 Total Issues Found: ${totalIssues}`);
  console.log(`⏱️ Average Scan Duration: ${avgDuration.toFixed(0)}ms`);
  
  // Overall severity breakdown
  const overallSeverity = {
    CRITICAL: allResults.reduce((sum, r) => sum + r.severityBreakdown.CRITICAL, 0),
    HIGH: allResults.reduce((sum, r) => sum + r.severityBreakdown.HIGH, 0),
    MEDIUM: allResults.reduce((sum, r) => sum + r.severityBreakdown.MEDIUM, 0),
    LOW: allResults.reduce((sum, r) => sum + r.severityBreakdown.LOW, 0)
  };
  
  if (totalIssues > 0) {
    console.log(`\n🚨 OVERALL SEVERITY DISTRIBUTION:`);
    if (overallSeverity.CRITICAL > 0) console.log(`  🔴 CRITICAL: ${overallSeverity.CRITICAL}`);
    if (overallSeverity.HIGH > 0) console.log(`  🟠 HIGH: ${overallSeverity.HIGH}`);
    if (overallSeverity.MEDIUM > 0) console.log(`  🟡 MEDIUM: ${overallSeverity.MEDIUM}`);
    if (overallSeverity.LOW > 0) console.log(`  🟢 LOW: ${overallSeverity.LOW}`);
    
    // Category analysis
    const categoryCount: Record<string, number> = {};
    allResults.forEach(result => {
      result.findings.forEach((finding: MisconfigurationResult) => {
        categoryCount[finding.category] = (categoryCount[finding.category] || 0) + 1;
      });
    });
    
    console.log(`\n📂 TOP MISCONFIGURATION CATEGORIES:`);
    Object.entries(categoryCount)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 5)
      .forEach(([category, count], idx) => {
        console.log(`  ${idx + 1}. ${category}: ${count} issues`);
      });
  }
  
  console.log(`\n🔬 DETECTION CAPABILITIES DEMONSTRATED:`);
  console.log('  ✅ HTTP Security Headers Analysis');
  console.log('  ✅ Sensitive File Exposure Detection');
  console.log('  ✅ Directory Listing & Access Control');
  console.log('  ✅ Server Information Disclosure');
  console.log('  ✅ CORS Misconfiguration Testing');
  console.log('  ✅ Administrative Interface Discovery');
  console.log('  ✅ Real-time Vulnerability Classification');
  console.log('  ✅ CWE & OWASP Mapping');
  console.log('  ✅ Risk-based Prioritization');
  
  console.log('\n🎉 Misconfiguration Detection System Demonstration Complete!');
  console.log('💡 This system can identify critical security misconfigurations');
  console.log('   that could expose sensitive data or create attack vectors.');
}

// Run the demonstration
if (require.main === module) {
  demonstrateMisconfigurationScanning().catch(console.error);
} 