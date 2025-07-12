import axios, { AxiosResponse } from 'axios';
import { logger } from '../utils/logger';

export interface MisconfigurationResult {
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
  references: string[];
}

export interface MisconfigurationScanOptions {
  timeout?: number;
  followRedirects?: boolean;
  checkSSL?: boolean;
  checkHeaders?: boolean;
  checkFiles?: boolean;
  checkDirectories?: boolean;
  checkServerInfo?: boolean;
  checkCORS?: boolean;
  checkCSP?: boolean;
  maxRedirects?: number;
  userAgent?: string;
}

export class MisconfigurationDetector {
  private readonly defaultOptions: MisconfigurationScanOptions = {
    timeout: 15000,
    followRedirects: true,
    checkSSL: true,
    checkHeaders: true,
    checkFiles: true,
    checkDirectories: true,
    checkServerInfo: true,
    checkCORS: true,
    checkCSP: true,
    maxRedirects: 5,
    userAgent: 'API-Security-Scanner/1.0'
  };

  // Common sensitive files and directories to check
  private readonly sensitiveFiles = [
    '.env', '.env.local', '.env.production', '.env.development',
    'config.php', 'config.yml', 'config.yaml', 'config.json',
    'database.yml', 'database.json', 'db.json',
    'secrets.json', 'secrets.yml', 'secrets.yaml',
    'private.key', 'private.pem', 'id_rsa', 'id_dsa',
    'backup.sql', 'dump.sql', 'database.sql',
    'web.config', 'htaccess', '.htaccess',
    'robots.txt', 'sitemap.xml',
    'phpinfo.php', 'info.php', 'test.php',
    'readme.txt', 'README', 'CHANGELOG',
    'package.json', 'composer.json', 'requirements.txt',
    'Dockerfile', 'docker-compose.yml',
    'swagger.json', 'swagger.yml', 'openapi.json',
    'admin', 'administrator', 'management',
    'login', 'auth', 'authentication'
  ];

  private readonly sensitivePaths = [
    '/admin', '/administrator', '/management', '/manager',
    '/login', '/auth', '/authentication', '/signin', '/signon',
    '/config', '/configuration', '/settings',
    '/backup', '/backups', '/dump', '/dumps',
    '/logs', '/log', '/access.log', '/error.log',
    '/tmp', '/temp', '/temporary',
    '/test', '/tests', '/testing', '/debug',
    '/api/v1', '/api/v2', '/api/docs', '/api-docs',
    '/swagger', '/swagger-ui', '/docs', '/documentation',
    '/health', '/status', '/info', '/metrics',
    '/.git', '/.svn', '/.hg', '/.bzr',
    '/.well-known', '/.aws', '/.ssh'
  ];

  constructor(private options: MisconfigurationScanOptions = {}) {
    this.options = { ...this.defaultOptions, ...options };
  }

  async scanTarget(baseUrl: string, progressCallback?: (progress: string) => void): Promise<MisconfigurationResult[]> {
    logger.info(`Starting misconfiguration scan for: ${baseUrl}`);
    const results: MisconfigurationResult[] = [];

    try {
      // Normalize base URL
      const normalizedUrl = this.normalizeUrl(baseUrl);
      
      if (progressCallback) progressCallback('🔍 Starting misconfiguration detection...');

      // 1. HTTP Security Headers Check
      if (this.options.checkHeaders) {
        if (progressCallback) progressCallback('🛡️ Checking HTTP security headers...');
        const headerResults = await this.checkSecurityHeaders(normalizedUrl);
        results.push(...headerResults);
      }

      // 2. Sensitive File Exposure Check
      if (this.options.checkFiles) {
        if (progressCallback) progressCallback('📄 Scanning for exposed sensitive files...');
        const fileResults = await this.checkSensitiveFiles(normalizedUrl);
        results.push(...fileResults);
      }

      // 3. Directory Traversal & Listing Check
      if (this.options.checkDirectories) {
        if (progressCallback) progressCallback('📁 Checking directory listings and traversal...');
        const directoryResults = await this.checkDirectoryMisconfigurations(normalizedUrl);
        results.push(...directoryResults);
      }

      // 4. Server Information Disclosure
      if (this.options.checkServerInfo) {
        if (progressCallback) progressCallback('🖥️ Analyzing server information disclosure...');
        const serverResults = await this.checkServerInformation(normalizedUrl);
        results.push(...serverResults);
      }

      // 5. CORS Misconfiguration
      if (this.options.checkCORS) {
        if (progressCallback) progressCallback('🌐 Testing CORS configurations...');
        const corsResults = await this.checkCORSMisconfiguration(normalizedUrl);
        results.push(...corsResults);
      }

      // 6. Content Security Policy Issues
      if (this.options.checkCSP) {
        if (progressCallback) progressCallback('🔒 Evaluating Content Security Policy...');
        const cspResults = await this.checkCSPMisconfiguration(normalizedUrl);
        results.push(...cspResults);
      }

      // 7. SSL/TLS Configuration Issues
      if (this.options.checkSSL && normalizedUrl.startsWith('https://')) {
        if (progressCallback) progressCallback('🔐 Analyzing SSL/TLS configuration...');
        const sslResults = await this.checkSSLConfiguration(normalizedUrl);
        results.push(...sslResults);
      }

      // 8. Insecure Cookie Directives Check
      if (progressCallback) progressCallback('🍪 Checking for insecure cookie directives...');
      const cookieResults = await this.checkInsecureCookieDirectives(normalizedUrl);
      results.push(...cookieResults);

      // 9. Robots.txt and Sitemap.xml for sensitive paths
      if (progressCallback) progressCallback('🤖 Checking robots.txt and sitemap.xml for exposed sensitive paths...');
      const robotsSitemapResults = await this.checkRobotsAndSitemap(normalizedUrl);
      results.push(...robotsSitemapResults);

      if (progressCallback) progressCallback('✅ Misconfiguration scan completed');
      logger.info(`Misconfiguration scan completed. Found ${results.length} issues.`);

      return results;

    } catch (error: any) {
      logger.error(`Misconfiguration scan failed: ${error.message}`);
      throw error;
    }
  }

  private async checkSecurityHeaders(baseUrl: string): Promise<MisconfigurationResult[]> {
    const results: MisconfigurationResult[] = [];

    try {
      const response = await this.makeRequest(baseUrl);
      const headers = response.headers;

      // Check for missing security headers
      const securityHeaders = {
        'strict-transport-security': {
          name: 'HTTP Strict Transport Security (HSTS)',
          severity: 'HIGH' as const,
          cwe: 'CWE-319',
          owasp: 'A06:2021 – Vulnerable and Outdated Components',
          checkValue: (value: string) => {
            const maxAgeMatch = value.match(/max-age=(\d+)/);
            if (maxAgeMatch && parseInt(maxAgeMatch[1]) < 31536000) return 'max-age is too short (less than 1 year)';
            return null;
          }
        },
        'content-security-policy': {
          name: 'Content Security Policy (CSP)',
          severity: 'MEDIUM' as const,
          cwe: 'CWE-79',
          owasp: 'A03:2021 – Injection'
        },
        'x-frame-options': {
          name: 'X-Frame-Options',
          severity: 'MEDIUM' as const,
          cwe: 'CWE-1021',
          owasp: 'A04:2021 – Insecure Design',
          checkValue: (value: string) => {
            if (!['DENY', 'SAMEORIGIN'].includes(value.toUpperCase())) return 'value is not DENY or SAMEORIGIN';
            return null;
          }
        },
        'x-content-type-options': {
          name: 'X-Content-Type-Options',
          severity: 'LOW' as const,
          cwe: 'CWE-79',
          owasp: 'A03:2021 – Injection',
          checkValue: (value: string) => {
            if (value.toLowerCase() !== 'nosniff') return 'value is not nosniff';
            return null;
          }
        },
        'referrer-policy': {
          name: 'Referrer Policy',
          severity: 'LOW' as const,
          cwe: 'CWE-200',
          owasp: 'A01:2021 – Broken Access Control'
        },
        'permissions-policy': {
          name: 'Permissions Policy',
          severity: 'LOW' as const,
          cwe: 'CWE-200',
          owasp: 'A05:2021 – Security Misconfiguration'
        }
      };

      for (const [headerName, headerInfo] of Object.entries(securityHeaders)) {
        const headerValue = headers[headerName] || headers[headerName.toLowerCase()];

        if (!headerValue) {
          results.push({
            category: 'HTTP Security Headers',
            type: 'missing_security_header',
            severity: headerInfo.severity,
            confidence: 0.9,
            title: `Missing ${headerInfo.name}`,
            description: `The response is missing the ${headerInfo.name} header, which could expose the application to security vulnerabilities.`,
            evidence: {
              url: baseUrl,
              headers: Object.fromEntries(
                Object.entries(headers).map(([key, value]) => [key, String(value)])
              ),
              statusCode: response.status
            },
            cwe: headerInfo.cwe,
            owasp: headerInfo.owasp,
            recommendation: `Implement the ${headerInfo.name} header with appropriate values to enhance security.`,
            impact: `Without ${headerName}, the application may be vulnerable to various attacks.`,
            references: [
              'https://owasp.org/www-project-secure-headers/',
              'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers'
            ]
          });
        } else if (headerInfo.checkValue) {
            const checkResult = headerInfo.checkValue(String(headerValue));
            if (checkResult) {
                results.push({
                    category: 'HTTP Security Headers',
                    type: `${headerName.replace(/-/g, '_-')}_misconfiguration`,
                    severity: headerInfo.severity,
                    confidence: 0.8,
                    title: `${headerInfo.name} Misconfiguration: ${checkResult}`,
                    description: `The ${headerInfo.name} header is present but misconfigured: ${checkResult}.`,
                    evidence: {
                        url: baseUrl,
                        headers: { [headerName]: String(headerValue) },
                        statusCode: response.status
                    },
                    cwe: headerInfo.cwe,
                    owasp: headerInfo.owasp,
                    recommendation: `Correct the ${headerInfo.name} header configuration: ${checkResult}.`,
                    impact: `A misconfigured ${headerInfo.name} can weaken security protections.`,
                    references: [
                        'https://owasp.org/www-project-secure-headers/',
                        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers'
                    ]
                });
            }
        }
      }

      // Check for information disclosure in headers
      const disclosureHeaders = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'];
      
      for (const headerName of disclosureHeaders) {
        const headerValue = headers[headerName] || headers[headerName.toLowerCase()];
        if (headerValue) {
          results.push({
            category: 'Information Disclosure',
            type: 'server_information_disclosure',
            severity: 'LOW',
            confidence: 0.8,
            title: `Server Information Disclosure in ${headerName.toUpperCase()} Header`,
            description: `The ${headerName.toUpperCase()} header reveals server/technology information that could aid attackers.`,
            evidence: {
              url: baseUrl,
              headers: { [headerName]: headerValue },
              statusCode: response.status
            },
            cwe: 'CWE-200',
            owasp: 'A05:2021 – Security Misconfiguration',
            recommendation: `Remove or minimize information in the ${headerName.toUpperCase()} header.`,
            impact: 'Information disclosure can help attackers identify vulnerabilities and plan targeted attacks.',
            references: [
              'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server'
            ]
          });
        }
      }

    } catch (error: any) {
      logger.warn(`Failed to check security headers: ${error.message}`);
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
            description: `The sensitive file "${file}" is publicly accessible and may contain confidential information.`,
            evidence: {
              url: fileUrl,
              response: this.truncateContent(response.data),
              statusCode: response.status,
              file: file
            },
            cwe: 'CWE-200',
            owasp: 'A05:2021 – Security Misconfiguration',
            recommendation: `Remove or restrict access to the sensitive file "${file}".`,
            impact: 'Exposed sensitive files can reveal configuration details, credentials, or other confidential information.',
            references: [
              'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information'
            ]
          });
        }
      } catch (error: any) {
        // Expected for most files - they should not be accessible
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
            description: `Directory listing is enabled for "${path}", potentially exposing sensitive files and directory structure.`,
            evidence: {
              url: dirUrl,
              response: this.truncateContent(response.data),
              statusCode: response.status
            },
            cwe: 'CWE-548',
            owasp: 'A05:2021 – Security Misconfiguration',
            recommendation: `Disable directory listing for "${path}" and implement proper access controls.`,
            impact: 'Directory listings can reveal sensitive files and provide reconnaissance information to attackers.',
            references: [
              'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information'
            ]
          });
        }

        // Check for accessible admin/management interfaces
        if (response.status === 200 && this.isAdminInterface(response.data, path)) {
          results.push({
            category: 'Administrative Interface',
            type: 'exposed_admin_interface',
            severity: 'HIGH',
            confidence: 0.8,
            title: `Exposed Administrative Interface: ${path}`,
            description: `An administrative interface is accessible at "${path}" without proper access restrictions.`,
            evidence: {
              url: dirUrl,
              response: this.truncateContent(response.data),
              statusCode: response.status
            },
            cwe: 'CWE-284',
            owasp: 'A01:2021 – Broken Access Control',
            recommendation: `Restrict access to the administrative interface "${path}" using proper authentication and IP restrictions.`,
            impact: 'Exposed administrative interfaces can provide unauthorized access to sensitive functionality.',
            references: [
              'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration'
            ]
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
      // Check for server status/info pages
      const infoPages = ['/server-status', '/server-info', '/info', '/phpinfo.php', '/info.php'];
      
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
              description: `A server information page is accessible at "${page}", revealing detailed system information.`,
              evidence: {
                url: infoUrl,
                response: this.truncateContent(response.data),
                statusCode: response.status
              },
              cwe: 'CWE-200',
              owasp: 'A05:2021 – Security Misconfiguration',
              recommendation: `Remove or restrict access to the server information page "${page}".`,
              impact: 'Server information pages can reveal system details that aid in targeted attacks.',
              references: [
                'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server'
              ]
            });
          }
        } catch (error: any) {
          // Expected for most pages
        }
      }

      // Check for error pages with detailed information
      try {
        const errorUrl = `${baseUrl.replace(/\/$/, '')}/nonexistent-page-${Date.now()}`;
        const response = await this.makeRequest(errorUrl);

        if (response.status >= 400 && this.hasDetailedErrorInfo(response.data)) {
          results.push({
            category: 'Information Disclosure',
            type: 'detailed_error_pages',
            severity: 'LOW',
            confidence: 0.7,
            title: 'Detailed Error Pages Enabled',
            description: 'Error pages contain detailed information that could aid attackers in reconnaissance.',
            evidence: {
              url: errorUrl,
              response: this.truncateContent(response.data),
              statusCode: response.status
            },
            cwe: 'CWE-209',
            owasp: 'A05:2021 – Security Misconfiguration',
            recommendation: 'Configure custom error pages that do not reveal detailed system information.',
            impact: 'Detailed error information can reveal system paths, software versions, and other sensitive details.',
            references: [
              'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling'
            ]
          });
        }
      } catch (error: any) {
        // Expected
      }

    } catch (error: any) {
      logger.warn(`Failed to check server information: ${error.message}`);
    }

    return results;
  }

  private async checkCORSMisconfiguration(baseUrl: string): Promise<MisconfigurationResult[]> {
    const results: MisconfigurationResult[] = [];

    try {
      // Test CORS with various origins
      const testOrigins = [
        'https://evil.com',
        'http://malicious.com',
        'null',
        '*'
      ];

      for (const origin of testOrigins) {
        try {
          const response = await this.makeRequest(baseUrl, { 'Origin': String(origin) });

          const corsHeader = response.headers['access-control-allow-origin'];
          
          if (corsHeader === '*' || corsHeader === origin) {
            const severity = corsHeader === '*' ? 'HIGH' : 'MEDIUM';
            
            results.push({
              category: 'CORS Misconfiguration',
              type: 'cors_wildcard_or_reflection',
              severity,
              confidence: 0.9,
              title: `CORS Misconfiguration: ${corsHeader === '*' ? 'Wildcard Origin' : 'Origin Reflection'}`,
              description: `The server accepts ${corsHeader === '*' ? 'wildcard (*) origins' : `reflected origin "${origin}"`}, which could enable cross-origin attacks.`,
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
              recommendation: 'Configure CORS to only allow trusted origins and avoid wildcard or reflected origins.',
              impact: 'Misconfigured CORS can enable cross-origin attacks and data theft.',
              references: [
                'https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny'
              ]
            });
          }
        } catch (error: any) {
          // Expected for some requests
        }
      }

    } catch (error: any) {
      logger.warn(`Failed to check CORS configuration: ${error.message}`);
    }

    return results;
  }

  private async checkCSPMisconfiguration(baseUrl: string): Promise<MisconfigurationResult[]> {
    const results: MisconfigurationResult[] = [];

    try {
      const response = await this.makeRequest(baseUrl);
      const cspHeader = response.headers['content-security-policy'] || 
                       response.headers['content-security-policy-report-only'];

      if (cspHeader) {
        // Check for unsafe CSP directives
        const unsafeDirectives = [
          { pattern: /unsafe-inline/, severity: 'MEDIUM' as const, issue: 'unsafe-inline' },
          { pattern: /unsafe-eval/, severity: 'MEDIUM' as const, issue: 'unsafe-eval' },
          { pattern: /\*/, severity: 'HIGH' as const, issue: 'wildcard source' },
          { pattern: /data:/, severity: 'LOW' as const, issue: 'data: protocol allowed' },
          { pattern: /http:\/\//, severity: 'MEDIUM' as const, issue: 'HTTP sources in HTTPS context' }
        ];

        for (const directive of unsafeDirectives) {
          if (directive.pattern.test(cspHeader)) {
            results.push({
              category: 'Content Security Policy',
              type: 'csp_misconfiguration',
              severity: directive.severity,
              confidence: 0.8,
              title: `CSP Misconfiguration: ${directive.issue}`,
              description: `The Content Security Policy contains ${directive.issue}, which weakens security protections.`,
              evidence: {
                url: baseUrl,
                headers: { 'Content-Security-Policy': cspHeader },
                statusCode: response.status
              },
              cwe: 'CWE-79',
              owasp: 'A03:2021 – Injection',
              recommendation: `Review and strengthen the CSP policy to remove ${directive.issue}.`,
              impact: 'Weak CSP policies can allow XSS attacks and other content injection vulnerabilities.',
              references: [
                'https://owasp.org/www-community/controls/Content_Security_Policy'
              ]
            });
          }
        }
      }

    } catch (error: any) {
      logger.warn(`Failed to check CSP configuration: ${error.message}`);
    }

    return results;
  }

  private async checkSSLConfiguration(baseUrl: string): Promise<MisconfigurationResult[]> {
    const results: MisconfigurationResult[] = [];

    try {
      // Test SSL/TLS redirect
      const httpUrl = baseUrl.replace('https://', 'http://');
      
      try {
        const response = await this.makeRequest(httpUrl, {}, false); // Don't follow redirects
        
        if (response.status !== 301 && response.status !== 302) {
          results.push({
            category: 'SSL/TLS Configuration',
            type: 'missing_https_redirect',
            severity: 'MEDIUM',
            confidence: 0.8,
            title: 'Missing HTTPS Redirect',
            description: 'The server does not automatically redirect HTTP requests to HTTPS.',
            evidence: {
              url: httpUrl,
              statusCode: response.status
            },
            cwe: 'CWE-319',
            owasp: 'A02:2021 – Cryptographic Failures',
            recommendation: 'Configure the server to automatically redirect all HTTP requests to HTTPS.',
            impact: 'Missing HTTPS redirects can allow man-in-the-middle attacks and data interception.',
            references: [
              'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security'
            ]
          });
        }
      } catch (error: any) {
        // Expected if HTTP is completely disabled
      }

    } catch (error: any) {
      logger.warn(`Failed to check SSL configuration: ${error.message}`);
    }

    return results;
  }

  private async checkRobotsAndSitemap(baseUrl: string): Promise<MisconfigurationResult[]> {
    const results: MisconfigurationResult[] = [];

    try {
      const normalizedBaseUrl = this.normalizeUrl(baseUrl);

      // Fetch and parse robots.txt
      const robotsTxtUrl = `${normalizedBaseUrl}/robots.txt`;
      let robotsTxtContent = '';
      try {
        const robotsResponse = await this.makeRequest(robotsTxtUrl);
        if (robotsResponse.status === 200 && this.isValidContent(robotsResponse.data)) {
          robotsTxtContent = String(robotsResponse.data);

          // Parse Disallow rules
          const disallowedPaths = new Set<string>();
          const lines = robotsTxtContent.split(/\r?\n/);
          for (const line of lines) {
            const match = line.match(/^Disallow:\s*(.*)/i);
            if (match && match[1] && match[1] !== '/') {
              disallowedPaths.add(match[1]);
            }
          }

          // Check if disallowed paths are actually accessible
          for (const disallowedPath of Array.from(disallowedPaths)) {
            const fullDisallowedUrl = `${normalizedBaseUrl}${disallowedPath}`;
            try {
              const disallowedResponse = await this.makeRequest(fullDisallowedUrl, {}, false); // Do not follow redirects
              if (disallowedResponse.status === 200 && this.isValidContent(disallowedResponse.data)) {
                results.push({
                  category: 'Information Disclosure',
                  type: 'exposed_disallowed_path',
                  severity: 'MEDIUM',
                  confidence: 0.7,
                  title: `Exposed Disallowed Path in robots.txt: ${disallowedPath}`,
                  description: `The path '${disallowedPath}' is disallowed in robots.txt but is still publicly accessible, potentially exposing sensitive information. ` + this.truncateContent(disallowedResponse.data),
                  evidence: {
                    url: fullDisallowedUrl,
                    file: 'robots.txt',
                    content: `Disallow: ${disallowedPath}`,
                    statusCode: disallowedResponse.status
                  },
                  cwe: 'CWE-538',
                  owasp: 'A05:2021 – Security Misconfiguration',
                  recommendation: `Ensure that paths disallowed in robots.txt are properly secured and not publicly accessible. Use server-side access controls (e.g., authentication, authorization) in addition to robots.txt.`,
                  impact: 'Sensitive information or functionalities may be exposed to unauthorized users or search engines.',
                  references: [
                    'https://developers.google.com/search/docs/crawling-indexing/block-indexing',
                    'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/10-Search_Engine_Discovery_and_Reconnaissance',                 ]
                });
              }
            } catch (pathError: any) {
              // Path is truly inaccessible or other error, which is good for security
            }
          }
        }
      } catch (error: any) {
        logger.warn(`Failed to fetch or parse robots.txt for ${baseUrl}: ${error.message}`);
      }

      // Fetch and parse sitemap.xml
      const sitemapXmlUrl = `${normalizedBaseUrl}/sitemap.xml`;
      let sitemapXmlContent = '';
      try {
        const sitemapResponse = await this.makeRequest(sitemapXmlUrl);
        if (sitemapResponse.status === 200 && this.isValidContent(sitemapResponse.data)) {
          sitemapXmlContent = String(sitemapResponse.data);
          
          // Check for sensitive paths in sitemap.xml that might be overlooked
          // A simple regex to find potential paths, more robust XML parsing might be needed for complex sitemaps
          const sensitivePathPatterns = this.sensitivePaths.map(p => p.replace(/\//g, '\\/')).join('|');
          const sensitiveSitemapRegex = new RegExp(`(${sensitivePathPatterns})`, 'gi');

          let match;
          while ((match = sensitiveSitemapRegex.exec(sitemapXmlContent)) !== null) {
              const foundPath = match[1];
              // Double-check if this path is actually accessible, if not already caught by robots.txt check
              const fullSensitiveUrl = `${normalizedBaseUrl}${foundPath}`;
              try {
                  const sensitivePathResponse = await this.makeRequest(fullSensitiveUrl, {}, false);
                  if (sensitivePathResponse.status === 200 && this.isValidContent(sensitivePathResponse.data)) {
                      results.push({
                          category: 'Information Disclosure',
                          type: 'exposed_sensitive_path_in_sitemap',
                          severity: 'MEDIUM',
                          confidence: 0.6,
                          title: `Exposed Sensitive Path in sitemap.xml: ${foundPath}`,
                          description: `A sensitive path '${foundPath}' is listed in sitemap.xml and is publicly accessible, potentially exposing internal structure or sensitive functionalities.`,
                          evidence: {
                              url: fullSensitiveUrl,
                              file: 'sitemap.xml',
                              content: `<loc>${fullSensitiveUrl}</loc>`,
                              statusCode: sensitivePathResponse.status
                          },
                          cwe: 'CWE-200',
                          owasp: 'A05:2021 – Security Misconfiguration',
                          recommendation: `Remove sensitive paths from sitemap.xml and ensure they are protected by access controls.`,
                          impact: 'Sensitive parts of the application may be indexed by search engines or discovered by attackers.',
                          references: [
                              'https://developers.google.com/search/docs/crawling-indexing/sitemaps/overview',
                              'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/10-Search_Engine_Discovery_and_Reconnaissance',
                          ]
                      });
                  }
              } catch (sitemapPathError: any) {
                  // Path is truly inaccessible
              }
          }
        }
      } catch (error: any) {
        logger.warn(`Failed to fetch or parse sitemap.xml for ${baseUrl}: ${error.message}`);
      }

    } catch (error: any) {
      logger.warn(`Failed to perform robots.txt and sitemap.xml checks: ${error.message}`);
    }

    return results;
  }

  private async checkInsecureCookieDirectives(baseUrl: string): Promise<MisconfigurationResult[]> {
    const results: MisconfigurationResult[] = [];

    try {
      const response = await this.makeRequest(baseUrl);
      const setCookieHeaders = response.headers['set-cookie'];

      if (setCookieHeaders && Array.isArray(setCookieHeaders)) {
        for (const cookieString of setCookieHeaders) {
          if (typeof cookieString !== 'string') continue;

          let issues = [];
          if (baseUrl.startsWith('https://') && !cookieString.includes('Secure')) {
            issues.push('Missing Secure attribute (cookie sent over HTTP)');
          }
          if (!cookieString.includes('HttpOnly')) {
            issues.push('Missing HttpOnly attribute (cookie accessible by JavaScript)');
          }
          // Check for SameSite attribute (consider Lax as default secure, but flag None without Secure)
          if (!cookieString.includes('SameSite')) {
            issues.push('Missing SameSite attribute (vulnerable to CSRF)');
          } else {
            const sameSiteMatch = cookieString.match(/SameSite=(Lax|Strict|None)/i);
            if (sameSiteMatch && sameSiteMatch[1].toLowerCase() === 'none' && !cookieString.includes('Secure')) {
                issues.push('SameSite=None without Secure attribute (insecure cross-site cookies)');
            }
          }

          if (issues.length > 0) {
            results.push({
              category: 'Cookie Security',
              type: 'insecure_cookie_directive',
              severity: issues.some(i => i.includes('Secure')) ? 'MEDIUM' : 'LOW', // Secure is more critical
              confidence: 0.9,
              title: `Insecure Cookie Directives: ${cookieString.split(';')[0]}`,
              description: `The cookie '${cookieString.split(';')[0]}' has insecure directives: ${issues.join(', ')}.`,
              evidence: {
                url: baseUrl,
                headers: { 'Set-Cookie': cookieString },
              },
              cwe: 'CWE-614',
              owasp: 'A05:2021 – Security Misconfiguration',
              recommendation: 'Ensure all sensitive cookies use Secure, HttpOnly, and SameSite=Lax/Strict attributes. Use SameSite=None only with Secure.',
              impact: 'Insecure cookies can lead to session hijacking, cross-site request forgery (CSRF), or sensitive information disclosure.',
              references: [
                'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie',
                'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes'
              ]
            });
          }
        }
      }
    } catch (error: any) {
      logger.warn(`Failed to check insecure cookie directives for ${baseUrl}: ${error.message}`);
    }

    return results;
  }

  private async makeRequest(url: string, headers: Record<string, string> = {}, followRedirects: boolean = true): Promise<AxiosResponse> {
    return await axios({
      method: 'GET',
      url,
      timeout: this.options.timeout,
      maxRedirects: followRedirects ? this.options.maxRedirects : 0,
      validateStatus: () => true,
      headers: {
        'User-Agent': this.options.userAgent,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        ...headers
      }
    });
  }

  private normalizeUrl(url: string): string {
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://' + url;
    }
    return url.replace(/\/$/, '');
  }

  private isValidContent(content: string): boolean {
    if (!content || content.length < 10) return false;
    
    // Check if it's not an error page
    const errorIndicators = ['404', 'not found', 'error', 'forbidden', 'access denied'];
    const lowerContent = content.toLowerCase();
    
    return !errorIndicators.some(indicator => lowerContent.includes(indicator));
  }

  private isDirectoryListing(content: string): boolean {
    if (!content) return false;
    
    const listingIndicators = [
      'index of',
      'directory listing',
      'parent directory',
      '<pre>',
      'last modified',
      'size</th>',
      '[dir]'
    ];
    
    const lowerContent = content.toLowerCase();
    return listingIndicators.some(indicator => lowerContent.includes(indicator));
  }

  private isAdminInterface(content: string, path: string): boolean {
    if (!content) return false;
    
    const adminIndicators = [
      'admin', 'administrator', 'management', 'dashboard',
      'login', 'username', 'password', 'sign in',
      'control panel', 'admin panel'
    ];
    
    const lowerContent = content.toLowerCase();
    const hasAdminContent = adminIndicators.some(indicator => lowerContent.includes(indicator));
    const isAdminPath = ['/admin', '/administrator', '/management', '/login'].some(p => path.includes(p));
    
    return hasAdminContent && isAdminPath;
  }

  private isServerInfoPage(content: string): boolean {
    if (!content) return false;
    
    const infoIndicators = [
      'phpinfo()', 'php version', 'apache status', 'server status',
      'system information', 'server information', 'configuration',
      'loaded modules', 'environment', 'build date'
    ];
    
    const lowerContent = content.toLowerCase();
    return infoIndicators.some(indicator => lowerContent.includes(indicator));
  }

  private hasDetailedErrorInfo(content: string): boolean {
    if (!content) return false;
    
    const errorDetailIndicators = [
      'stack trace', 'exception', 'error in', 'line number',
      'file path', 'debug info', 'call stack', 'traceback'
    ];
    
    const lowerContent = content.toLowerCase();
    return errorDetailIndicators.some(indicator => lowerContent.includes(indicator));
  }

  private getSensitiveFileSeverity(filename: string): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
    const criticalFiles = ['.env', 'private.key', 'id_rsa', 'database.sql', 'backup.sql'];
    const highFiles = ['config.php', 'config.json', 'secrets.json', 'web.config'];
    const mediumFiles = ['robots.txt', 'phpinfo.php', 'package.json'];
    
    if (criticalFiles.some(f => filename.includes(f))) return 'CRITICAL';
    if (highFiles.some(f => filename.includes(f))) return 'HIGH';
    if (mediumFiles.some(f => filename.includes(f))) return 'MEDIUM';
    return 'LOW';
  }

  private truncateContent(content: string): string {
    const str = typeof content === 'string' ? content : JSON.stringify(content);
    return str.length > 500 ? str.substring(0, 500) + '...[truncated]' : str;
  }
} 