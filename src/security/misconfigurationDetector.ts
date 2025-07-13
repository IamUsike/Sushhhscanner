import axios, { AxiosResponse } from 'axios';
import { logger } from '../utils/logger';
import { VulnerabilitySeverity, VulnerabilityType, Vulnerability, RemediationGuidance } from '../types';
import { RecommendationService } from '../recommendations/RecommendationService';

export interface MisconfigurationResult {
  category: string;
  type: string;
  severity: VulnerabilitySeverity;
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
  recommendation: RemediationGuidance; // Changed from string
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

interface SecurityHeaderConfig {
  name: string;
  severity: VulnerabilitySeverity;
  cwe: string;
  owasp: string;
  checkValue?: (value: string) => string | null;
}

export class MisconfigurationDetector {
  private recommendationService: RecommendationService;

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
    this.recommendationService = new RecommendationService();
  }

  async scanTarget(baseUrl: string, progressCallback?: (progress: string) => void): Promise<MisconfigurationResult[]> {
    logger.info(`Starting misconfiguration scan for: ${baseUrl}`);
    const results: MisconfigurationResult[] = [];

    try {
      const normalizedUrl = this.normalizeUrl(baseUrl);
      
      if (progressCallback) progressCallback('🔍 Starting misconfiguration detection...');

      if (this.options.checkHeaders) {
        if (progressCallback) progressCallback('🛡️ Checking HTTP security headers...');
        const headerResults = await this.checkSecurityHeaders(normalizedUrl);
        results.push(...headerResults);
      }

      if (this.options.checkFiles) {
        if (progressCallback) progressCallback('📄 Scanning for exposed sensitive files...');
        const fileResults = await this.checkSensitiveFiles(normalizedUrl);
        results.push(...fileResults);
      }

      if (this.options.checkDirectories) {
        if (progressCallback) progressCallback('📁 Checking directory listings and traversal...');
        const directoryResults = await this.checkDirectoryMisconfigurations(normalizedUrl);
        results.push(...directoryResults);
      }

      if (this.options.checkServerInfo) {
        if (progressCallback) progressCallback('🖥️ Analyzing server information disclosure...');
        const serverResults = await this.checkServerInformation(normalizedUrl);
        results.push(...serverResults);
      }

      if (this.options.checkCORS) {
        if (progressCallback) progressCallback('🌐 Testing CORS configurations...');
        const corsResults = await this.checkCORSMisconfiguration(normalizedUrl);
        results.push(...corsResults);
      }

      if (this.options.checkCSP) {
        if (progressCallback) progressCallback('🔒 Evaluating Content Security Policy...');
        const cspResults = await this.checkCSPMisconfiguration(normalizedUrl);
        results.push(...cspResults);
      }

      if (this.options.checkSSL && normalizedUrl.startsWith('https://')) {
        if (progressCallback) progressCallback('🔐 Analyzing SSL/TLS configuration...');
        const sslResults = await this.checkSSLConfiguration(normalizedUrl);
        results.push(...sslResults);
      }

      if (progressCallback) progressCallback('🍪 Checking for insecure cookie directives...');
      const cookieResults = await this.checkInsecureCookieDirectives(normalizedUrl);
      results.push(...cookieResults);

      if (progressCallback) progressCallback('🤖 Checking robots.txt and sitemap.xml for exposed sensitive paths...');
      const robotsSitemapResults = await this.checkRobotsAndSitemap(normalizedUrl);
      results.push(...robotsSitemapResults);

      if (progressCallback) progressCallback('🚦 Checking HTTP method enforcement...');
      const methodEnforcementResults = await this.checkHttpMethodEnforcement(normalizedUrl);
      results.push(...methodEnforcementResults);

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

      const securityHeaders: Record<string, SecurityHeaderConfig> = {
        'strict-transport-security': {
          name: 'HTTP Strict Transport Security (HSTS)',
          severity: 'HIGH',
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
          severity: 'MEDIUM',
          cwe: 'CWE-79',
          owasp: 'A03:2021 – Injection'
        },
        'x-frame-options': {
          name: 'X-Frame-Options',
          severity: 'MEDIUM',
          cwe: 'CWE-1021',
          owasp: 'A04:2021 – Insecure Design',
          checkValue: (value: string) => {
            if (!['DENY', 'SAMEORIGIN'].includes(value.toUpperCase())) return 'value is not DENY or SAMEORIGIN';
            return null;
          }
        },
        'x-content-type-options': {
          name: 'X-Content-Type-Options',
          severity: 'LOW',
          cwe: 'CWE-79',
          owasp: 'A03:2021 – Injection',
          checkValue: (value: string) => {
            if (value.toLowerCase() !== 'nosniff') return 'value is not nosniff';
            return null;
          }
        },
        'referrer-policy': {
          name: 'Referrer Policy',
          severity: 'LOW',
          cwe: 'CWE-200',
          owasp: 'A01:2021 – Broken Access Control'
        },
        'permissions-policy': {
          name: 'Permissions Policy',
          severity: 'LOW',
          cwe: 'CWE-200',
          owasp: 'A05:2021 – Security Misconfiguration'
        }
      };

      for (const [headerName, headerInfo] of Object.entries(securityHeaders)) {
        const headerValue = headers[headerName] || headers[headerName.toLowerCase()];

        if (!headerValue) {
          results.push({
            category: 'HTTP Security Headers',
            type: 'MISSING_SECURITY_HEADERS',
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
            impact: `Reduced defense-in-depth against attacks like XSS, clickjacking, or content sniffing.`,
            references: [],
            recommendation: this.generateRecommendationForMisconfiguration(
              'MISSING_SECURITY_HEADERS', 
              headerInfo.severity,
              `Ensure the ${headerInfo.name} header is present in all responses to enhance security.`
            )
          });
        } else {
          if (headerInfo.checkValue) {
            const issue = headerInfo.checkValue(String(headerValue));
            if (issue) {
          results.push({
                category: 'HTTP Security Headers',
                type: `insecure_${headerName.replace(/-/g, '_').toUpperCase()}` as VulnerabilityType,
                severity: headerInfo.severity,
            confidence: 0.8,
                title: `${headerInfo.name} Misconfiguration`,
                description: `The ${headerInfo.name} header is present but misconfigured: ${issue}.`,
            evidence: {
              url: baseUrl,
                  headers: Object.fromEntries(
                    Object.entries(headers).map(([key, value]) => [key, String(value)])
                  ),
              statusCode: response.status
            },
                cwe: headerInfo.cwe,
                owasp: headerInfo.owasp,
                impact: `Increased susceptibility to attacks related to ${headerInfo.name}.`,
                references: [],
                recommendation: this.generateRecommendationForMisconfiguration(
                  `insecure_${headerName.replace(/-/g, '_').toUpperCase()}` as VulnerabilityType,
                  headerInfo.severity,
                  `Correct the configuration of the ${headerInfo.name} header. Refer to documentation for best practices.`
                )
          });
        }
      }
        }
    }

    return results;

    } catch (error: any) {
      logger.error(`Error checking security headers for ${baseUrl}: ${error.message}`);
      return [];
    }
  }

  private async checkSensitiveFiles(baseUrl: string): Promise<MisconfigurationResult[]> {
    const results: MisconfigurationResult[] = [];

    for (const file of this.sensitiveFiles) {
      try {
        const fileUrl = `${baseUrl.replace(/\/$/, '')}/${file}`;
        const response = await this.makeRequest(fileUrl);

        if (response.status === 200 && response.data) {
          const type = this.getSensitiveFileSeverity(file);
          results.push({
            category: 'Sensitive File Exposure',
            type: 'FILE_EXPOSURE',
            severity: type,
            confidence: 0.9,
            title: `Exposed Sensitive File: ${file}`,
            description: `The sensitive file "${file}" is publicly accessible at ${fileUrl}. This could lead to information disclosure.`,
            evidence: {
              url: fileUrl,
              statusCode: response.status,
              response: this.truncateContent(response.data),
              file: file
            },
            cwe: 'CWE-538',
            owasp: 'A01:2021 – Broken Access Control',
            impact: `Unauthorized access to sensitive information or credentials.`,
            references: [],
            recommendation: this.generateRecommendationForMisconfiguration(
              'FILE_EXPOSURE',
              type,
              `Restrict access to sensitive files like "${file}" using server configurations (e.g., .htaccess, Nginx rules) or by placing them outside the web root.`
            )
          });
        }
      } catch (error: any) {
        logger.debug(`Failed to check sensitive file ${file}: ${error.message}`);
      }
    }
    return results;
  }

  private async checkDirectoryMisconfigurations(baseUrl: string): Promise<MisconfigurationResult[]> {
    const results: MisconfigurationResult[] = [];
    const testPaths = ['/', '/app/', '/src/', '/dist/', '/assets/', '/static/', '/data/'];

    for (const path of testPaths) {
      try {
        const fullUrl = `${baseUrl.replace(/\/$/, '')}${path}`;
        const response = await this.makeRequest(fullUrl);

        if (response.status === 200 && response.data) {
          if (this.isDirectoryListing(response.data)) {
          results.push({
              category: 'Directory Listing',
              type: 'DIRECTORY_LISTING_ENABLED',
            severity: 'MEDIUM',
              confidence: 0.8,
              title: `Directory Listing Enabled at ${path}`,
              description: `Directory listing is enabled at ${fullUrl}, which allows attackers to view the contents of directories and potentially discover sensitive files or application structure.`,
            evidence: {
                url: fullUrl,
                statusCode: response.status,
                response: this.truncateContent(response.data)
            },
            cwe: 'CWE-548',
            owasp: 'A05:2021 – Security Misconfiguration',
              impact: `Information disclosure, aiding attackers in reconnaissance.`,
              references: [],
              recommendation: this.generateRecommendationForMisconfiguration(
                'DIRECTORY_LISTING_ENABLED',
                'MEDIUM',
                `Disable directory listing on your web server for all directories. Configure the server to return a 403 Forbidden or redirect to an error page.`
              )
          });
        }
        }
      } catch (error: any) {
        logger.debug(`Error checking directory ${path}: ${error.message}`);
      }
    }
    return results;
  }

  private async checkServerInformation(baseUrl: string): Promise<MisconfigurationResult[]> {
    const results: MisconfigurationResult[] = [];

    try {
      const response = await this.makeRequest(baseUrl);
      const headers = response.headers;

      const serverHeader = headers['server'] || headers['Server'];
      if (serverHeader && serverHeader !== 'unknown') {
            results.push({
              category: 'Information Disclosure',
          type: 'SERVER_INFO_DISCLOSURE',
          severity: 'LOW',
          confidence: 0.7,
          title: `Server Information Disclosure: ${serverHeader}`,
          description: `The 'Server' header is disclosing specific server software and version (${serverHeader}). This information can be used by attackers to identify known vulnerabilities.`,
              evidence: {
            url: baseUrl,
            headers: { 'Server': String(serverHeader) },
                statusCode: response.status
              },
              cwe: 'CWE-200',
          owasp: 'A01:2021 – Broken Access Control',
          impact: `Facilitates attacker reconnaissance and exploitation of known vulnerabilities.`,
          references: [],
          recommendation: this.generateRecommendationForMisconfiguration(
            'SERVER_INFO_DISCLOSURE',
            'LOW',
            'Configure your web server to remove or generalize the \'Server\' header (e.g., set to \'Web Server\').'
          )
        });
      }

      const poweredByHeader = headers['x-powered-by'] || headers['X-Powered-By'];
      if (poweredByHeader) {
          results.push({
            category: 'Information Disclosure',
          type: 'X_POWERED_BY_HEADER_DISCLOSURE',
            severity: 'LOW',
            confidence: 0.7,
          title: `X-Powered-By Header Disclosure: ${poweredByHeader}`,
          description: `The 'X-Powered-By' header is disclosing the technology stack (${poweredByHeader}). This information can be used by attackers to identify known vulnerabilities.`,
            evidence: {
            url: baseUrl,
            headers: { 'X-Powered-By': String(poweredByHeader) },
              statusCode: response.status
            },
          cwe: 'CWE-200',
          owasp: 'A01:2021 – Broken Access Control',
          impact: `Facilitates attacker reconnaissance and exploitation of known vulnerabilities.`,
          references: [],
          recommendation: this.generateRecommendationForMisconfiguration(
            'X_POWERED_BY_HEADER_DISCLOSURE',
            'LOW',
            'Remove the \'X-Powered-By\' header from server responses to prevent technology stack disclosure.'
          )
        });
      }

      if (this.hasDetailedErrorInfo(response.data)) {
        results.push({
          category: 'Error Handling',
          type: 'DETAILED_ERROR_MESSAGES',
          severity: 'MEDIUM',
          confidence: 0.8,
          title: 'Detailed Error Messages Disclosure',
          description: 'The application is revealing detailed error messages (e.g., stack traces, database errors) which could contain sensitive information or internal application details.',
          evidence: {
            url: baseUrl,
            statusCode: response.status,
            response: this.truncateContent(response.data)
            },
            cwe: 'CWE-209',
          owasp: 'A04:2021 – Insecure Design',
          impact: `Information disclosure, aiding attackers in understanding application logic or database structure.`,
          references: [],
          recommendation: this.generateRecommendationForMisconfiguration(
            'DETAILED_ERROR_MESSAGES',
            'MEDIUM',
            'Configure the application to suppress detailed error messages in production environments. Use generic error messages and log full details securely on the server side.'
          )
        });
      }

    } catch (error: any) {
      logger.error(`Error checking server information for ${baseUrl}: ${error.message}`);
    }
    return results;
  }

  private async checkCORSMisconfiguration(baseUrl: string): Promise<MisconfigurationResult[]> {
    const results: MisconfigurationResult[] = [];
    const testOrigins = ['https://evil.com', 'http://attacker.com'];

      for (const origin of testOrigins) {
        try {
        const response = await axios.options(baseUrl, {
          timeout: this.options.timeout,
          validateStatus: (status) => status < 500,
          headers: {
            'Origin': origin,
            'Access-Control-Request-Method': 'GET',
            'Access-Control-Request-Headers': 'Content-Type, Authorization'
          }
        });

        const acao = response.headers['access-control-allow-origin'] || response.headers['Access-Control-Allow-Origin'];
        const exposeHeaders = response.headers['access-control-expose-headers'] || response.headers['Access-Control-Expose-Headers'];
        const allowCredentials = response.headers['access-control-allow-credentials'] || response.headers['Access-Control-Allow-Credentials'];
        const allowMethods = response.headers['access-control-allow-methods'] || response.headers['Access-Control-Allow-Methods'];

        if (acao === '*' || (acao && acao.includes(origin))) {
          if (allowCredentials === 'true') {
            results.push({
              category: 'CORS Misconfiguration',
              type: 'PERMISSIVE_CORS_WITH_CREDENTIALS',
              severity: 'CRITICAL',
              confidence: 0.9,
              title: `Overly Permissive CORS with Credentials for Origin: ${origin}`,
              description: `The API at ${baseUrl} is configured with an overly permissive CORS policy (Access-Control-Allow-Origin: ${acao}) while also allowing credentials. This makes it vulnerable to Cross-Site Request Forgery (CSRF) and information disclosure from malicious origins.`,
              evidence: {
                url: baseUrl,
                headers: {
                  'Access-Control-Allow-Origin': String(acao),
                  'Access-Control-Allow-Credentials': String(allowCredentials)
                },
                statusCode: response.status
              },
              cwe: 'CWE-346',
              owasp: 'A07:2021 – Identification and Authentication Failures',
              impact: `Cross-site scripting (XSS) attacks, sensitive data exposure, and unauthorized actions.`,
              references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS', 'https://portswigger.net/web-security/cors'],
              recommendation: this.generateRecommendationForMisconfiguration(
                'PERMISSIVE_CORS_WITH_CREDENTIALS',
                'CRITICAL',
                `Restrict Access-Control-Allow-Origin to explicitly trusted domains. Never use '*' with 'Access-Control-Allow-Credentials: true'.`
              )
            });
          } else if (acao === '*') {
            results.push({
              category: 'CORS Misconfiguration',
              type: 'PERMISSIVE_CORS',
              severity: 'HIGH',
              confidence: 0.8,
              title: `Overly Permissive CORS for Origin: ${origin}`,
              description: `The API at ${baseUrl} is configured with an overly permissive CORS policy (Access-Control-Allow-Origin: ${acao}), allowing any domain to access resources. This can lead to information disclosure or unintended cross-origin interactions.`,
              evidence: {
                url: baseUrl,
                headers: { 'Access-Control-Allow-Origin': String(acao) },
                statusCode: response.status
              },
              cwe: 'CWE-346',
              owasp: 'A07:2021 – Identification and Authentication Failures',
              impact: `Information disclosure, enabling attacks like CSRF or XSS.`,
              references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS', 'https://portswigger.net/web-security/cors'],
              recommendation: this.generateRecommendationForMisconfiguration(
                'PERMISSIVE_CORS',
                'HIGH',
                `Restrict Access-Control-Allow-Origin to explicitly trusted domains. Avoid using '*'.`
              )
            });
        }
      }

    } catch (error: any) {
        logger.error(`Error checking CORS for ${baseUrl}: ${error.message}`);
    }
    }
    return results;
  }

  private async checkCSPMisconfiguration(baseUrl: string): Promise<MisconfigurationResult[]> {
    const results: MisconfigurationResult[] = [];
    try {
      const response = await this.makeRequest(baseUrl);
      const headers = response.headers;
      const cspHeader = headers['content-security-policy'] || headers['Content-Security-Policy'];

      if (cspHeader) {
        const unsafeInlineRegex = /(script-src|style-src)[^;]*\'unsafe-inline\'/i;
        const unsafeEvalRegex = /(script-src)[^;]*\'unsafe-eval\'/i;

        if (unsafeInlineRegex.test(String(cspHeader))) {
            results.push({
              category: 'Content Security Policy',
            type: 'CSP_UNSAFE_INLINE',
            severity: 'HIGH',
            confidence: 0.9,
            title: 'CSP Allows Unsafe Inline Scripts/Styles',
            description: `The Content Security Policy (CSP) includes 'unsafe-inline' for script-src or style-src, which can allow Cross-Site Scripting (XSS) attacks.`,
              evidence: {
                url: baseUrl,
              headers: { 'Content-Security-Policy': String(cspHeader) },
                statusCode: response.status
              },
              cwe: 'CWE-79',
              owasp: 'A03:2021 – Injection',
            impact: `Increased risk of XSS attacks.`,
            references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy', 'https://csp.withgoogle.com/'],
            recommendation: this.generateRecommendationForMisconfiguration(
              'CSP_UNSAFE_INLINE',
              'HIGH',
              'Remove \'unsafe-inline\' from your Content Security Policy. Use nonces or hashes for inline scripts/styles, or move them to external files.'
            )
          });
        }
        if (unsafeEvalRegex.test(String(cspHeader))) {
          results.push({
            category: 'Content Security Policy',
            type: 'CSP_UNSAFE_EVAL',
            severity: 'HIGH',
            confidence: 0.9,
            title: 'CSP Allows Unsafe Eval',
            description: `The Content Security Policy (CSP) includes 'unsafe-eval' for script-src, which can allow Cross-Site Scripting (XSS) attacks through dynamic code execution.`,
            evidence: {
              url: baseUrl,
              headers: { 'Content-Security-Policy': String(cspHeader) },
              statusCode: response.status
            },
            cwe: 'CWE-79',
            owasp: 'A03:2021 – Injection',
            impact: `Increased risk of XSS attacks.`,
            references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy', 'https://csp.withgoogle.com/'],
            recommendation: this.generateRecommendationForMisconfiguration(
              'CSP_UNSAFE_EVAL',
              'HIGH',
              'Remove \'unsafe-eval\' from your Content Security Policy. Refactor code to avoid dynamic code execution where possible.'
            )
          });
        }

        const defaultSrcRegex = /default-src\s*[^;]*/i;
        const defaultSrcMatch = String(cspHeader).match(defaultSrcRegex);
        if (!defaultSrcMatch || defaultSrcMatch[0].toLowerCase().includes('*')) {
          results.push({
            category: 'Content Security Policy',
            type: 'CSP_WEAK_DEFAULT_SRC',
            severity: 'MEDIUM',
            confidence: 0.7,
            title: 'CSP Has Weak Default Source or is Missing',
            description: 'The Content Security Policy (CSP) either does not define a default-src, or uses an overly broad wildcard (*), which reduces its effectiveness in mitigating XSS and other content injection attacks.',
            evidence: {
              url: baseUrl,
              headers: { 'Content-Security-Policy': String(cspHeader) },
              statusCode: response.status
            },
            cwe: 'CWE-79',
            owasp: 'A03:2021 – Injection',
            impact: `Reduced protection against content injection attacks.`,
            references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy', 'https://csp.withgoogle.com/'],
            recommendation: this.generateRecommendationForMisconfiguration(
              'CSP_WEAK_DEFAULT_SRC',
              'MEDIUM',
              'Define a strict `default-src` directive in your CSP, restricting content sources to trusted origins. Avoid wildcards.'
            )
          });
        }
      } else {
        results.push({
          category: 'Content Security Policy',
          type: 'CSP_MISSING',
          severity: 'HIGH',
          confidence: 0.9,
          title: 'Content Security Policy (CSP) Missing',
          description: 'The Content Security Policy (CSP) header is missing, which leaves the application vulnerable to Cross-Site Scripting (XSS) and other client-side injection attacks.',
          evidence: {
            url: baseUrl,
            statusCode: response.status
          },
          cwe: 'CWE-79',
          owasp: 'A03:2021 – Injection',
          impact: `High risk of XSS and other client-side attacks.`,
          references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy', 'https://csp.withgoogle.com/'],
          recommendation: this.generateRecommendationForMisconfiguration(
            'CSP_MISSING',
            'HIGH',
            'Implement a strong Content Security Policy (CSP) to mitigate client-side attacks. Define trusted sources for all types of content (scripts, styles, images, etc.).'
          )
            });
          }
    } catch (error: any) {
      logger.error(`Error checking CSP for ${baseUrl}: ${error.message}`);
    }
    return results;
  }

  private async checkSSLConfiguration(baseUrl: string): Promise<MisconfigurationResult[]> {
    const results: MisconfigurationResult[] = [];
    try {
      const response = await this.makeRequest(baseUrl);

      const hstsHeader = response.headers['strict-transport-security'] || response.headers['Strict-Transport-Security'];
      if (!hstsHeader) {
        results.push({
          category: 'SSL/TLS Configuration',
          type: 'MISSING_HSTS',
          severity: 'HIGH',
          confidence: 0.9,
          title: 'Missing HTTP Strict Transport Security (HSTS) Header',
          description: 'The application is not enforcing HSTS, making it vulnerable to SSL stripping attacks and cookie hijacking on insecure connections.',
          evidence: {
            url: baseUrl,
            statusCode: response.status,
            headers: response.headers as Record<string, string>
          },
          cwe: 'CWE-319',
          owasp: 'A06:2021 – Vulnerable and Outdated Components',
          impact: `Increased risk of man-in-the-middle attacks and data interception.`,
          references: ['https://owasp.org/www-project-top-10/2021/A06_2021_Vulnerable_and_Outdated_Components.html', 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'],
          recommendation: this.generateRecommendationForMisconfiguration(
            'MISSING_HSTS',
            'HIGH',
            'Implement HSTS with a long max-age and includeSubDomains directive to force secure connections.'
          )
        });
      }

    } catch (error: any) {
      logger.error(`Error checking SSL configuration for ${baseUrl}: ${error.message}`);
      if (axios.isAxiosError(error) && error.code === 'ERR_TLS_CERT_ALTNAME_MISMATCH') {
        results.push({
          category: 'SSL/TLS Configuration',
          type: 'TLS_CERT_HOSTNAME_MISMATCH',
          severity: 'CRITICAL',
          confidence: 1.0,
          title: 'TLS Certificate Hostname Mismatch',
          description: `The TLS certificate for ${baseUrl} does not match the hostname. This indicates a severe misconfiguration or a potential man-in-the-middle attack.`,
          evidence: {
            url: baseUrl,
            response: (error.message || '').substring(0, 200)
          },
          cwe: 'CWE-295',
          owasp: 'A06:2021 – Vulnerable and Outdated Components',
          impact: `Enables man-in-the-middle attacks, compromising data confidentiality and integrity.`,
          references: [],
          recommendation: this.generateRecommendationForMisconfiguration(
            'TLS_CERT_HOSTNAME_MISMATCH',
            'CRITICAL',
            'Ensure your TLS certificate is valid and issued for the correct hostname. Immediately investigate any hostname mismatches.'
          )
        });
      } else if (axios.isAxiosError(error) && error.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE') {
        results.push({
          category: 'SSL/TLS Configuration',
          type: 'TLS_CERT_UNTRUSTED',
          severity: 'HIGH',
          confidence: 0.9,
          title: 'Untrusted TLS Certificate',
          description: `The TLS certificate for ${baseUrl} is untrusted. This could indicate a self-signed certificate, an expired certificate, or a malicious certificate.`,
          evidence: {
            url: baseUrl,
            response: (error.message || '').substring(0, 200)
          },
          cwe: 'CWE-295',
          owasp: 'A06:2021 – Vulnerable and Outdated Components',
          impact: `Compromises data confidentiality and integrity, leading to man-in-the-middle attacks.`,
          references: [],
          recommendation: this.generateRecommendationForMisconfiguration(
            'TLS_CERT_UNTRUSTED',
            'HIGH',
            'Install a valid TLS certificate from a trusted Certificate Authority. Ensure certificates are not expired and are correctly configured.'
          )
        });
      }
    }
    return results;
  }

  private async checkRobotsAndSitemap(baseUrl: string): Promise<MisconfigurationResult[]> {
    const results: MisconfigurationResult[] = [];
    const robotsTxtUrl = `${baseUrl.replace(/\/$/, '')}/robots.txt`;
    const sitemapXmlUrl = `${baseUrl.replace(/\/$/, '')}/sitemap.xml`;

    const sensitivePathsRegex = new RegExp(this.sensitivePaths.map(p => p.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&')).join('|'), 'i');

    const checkFileForSensitivePaths = async (fileUrl: string, fileName: string) => {
      try {
        const response = await this.makeRequest(fileUrl);
        if (response.status === 200 && response.data) {
          const content = String(response.data);
          let match;
          while ((match = sensitivePathsRegex.exec(content)) !== null) {
            results.push({
              category: 'Information Disclosure',
              type: 'EXPOSED_SENSITIVE_PATH_IN_ROBOTS_OR_SITEMAP',
              severity: 'MEDIUM',
              confidence: 0.8,
              title: `Sensitive Path Exposed in ${fileName}: ${match[0]}`,
              description: `The ${fileName} file exposes a sensitive path (${match[0]}) which might be intended for exclusion from search engines but is still discoverable.`,
              evidence: {
                url: fileUrl,
                statusCode: response.status,
                response: this.truncateContent(content),
                content: match[0]
              },
              cwe: 'CWE-200',
              owasp: 'A05:2021 – Security Misconfiguration',
              impact: `Facilitates attacker reconnaissance, revealing hidden or sensitive areas.`,
              references: [],
              recommendation: this.generateRecommendationForMisconfiguration(
                'EXPOSED_SENSITIVE_PATH_IN_ROBOTS_OR_SITEMAP',
                'MEDIUM',
                `Review your ${fileName} file. While robots.txt is advisory for search engines, sensitive paths should not be discoverable by other means. Ensure these paths are properly secured.`
              )
            });
          }
        }
      } catch (error: any) {
        logger.debug(`Error checking ${fileName} for sensitive paths: ${error.message}`);
      }
    };

    await checkFileForSensitivePaths(robotsTxtUrl, 'robots.txt');
    await checkFileForSensitivePaths(sitemapXmlUrl, 'sitemap.xml');

    return results;
  }

  private async checkInsecureCookieDirectives(baseUrl: string): Promise<MisconfigurationResult[]> {
    const results: MisconfigurationResult[] = [];
    try {
      const response = await this.makeRequest(baseUrl);
      const setCookieHeaders = response.headers['set-cookie'] || response.headers['Set-Cookie'];

      if (setCookieHeaders && Array.isArray(setCookieHeaders)) {
        setCookieHeaders.forEach(cookie => {
          if (typeof cookie === 'string') {
            if (!cookie.includes('Secure')) {
          results.push({
                category: 'Insecure Cookie',
                type: 'MISSING_SECURE_COOKIE_FLAG',
                severity: 'HIGH',
                confidence: 0.9,
                title: 'Missing Secure Flag for Cookie',
                description: `A cookie (${cookie.split(';')[0]}) is being set without the 'Secure' flag. This means the cookie can be transmitted over unencrypted HTTP connections, potentially exposing sensitive information.`,
                evidence: {
                  url: baseUrl,
                  headers: { 'Set-Cookie': cookie },
                  statusCode: response.status
                },
                cwe: 'CWE-614',
                owasp: 'A07:2021 – Identification and Authentication Failures',
                impact: `Cookie interception and session hijacking on unencrypted networks.`,
                references: [],
                recommendation: this.generateRecommendationForMisconfiguration(
                  'MISSING_SECURE_COOKIE_FLAG',
                  'HIGH',
                  'Ensure all cookies containing sensitive information or session identifiers are set with the \'Secure\' flag. This requires the application to be served over HTTPS.'
                )
              });
            }
            if (!cookie.includes('HttpOnly')) {
              results.push({
                category: 'Insecure Cookie',
                type: 'MISSING_HTTPONLY_COOKIE_FLAG',
            severity: 'MEDIUM',
            confidence: 0.8,
                title: 'Missing HttpOnly Flag for Cookie',
                description: `A cookie (${cookie.split(';')[0]}) is being set without the 'HttpOnly' flag. This makes the cookie accessible to client-side scripts, increasing the risk of Cross-Site Scripting (XSS) attacks leading to session hijacking.`,
            evidence: {
                  url: baseUrl,
                  headers: { 'Set-Cookie': cookie },
              statusCode: response.status
            },
                cwe: 'CWE-79',
                owasp: 'A03:2021 – Injection',
                impact: `Increased risk of session hijacking via XSS.`,
                references: [],
                recommendation: this.generateRecommendationForMisconfiguration(
                  'MISSING_HTTPONLY_COOKIE_FLAG',
                  'MEDIUM',
                  'Ensure all cookies that do not need to be accessed by client-side scripts are set with the \'HttpOnly\' flag.'
                )
              });
            }
            if (!cookie.includes('SameSite')) {
              results.push({
                category: 'Insecure Cookie',
                type: 'MISSING_SAMESITE_COOKIE_FLAG',
                severity: 'MEDIUM',
                confidence: 0.7,
                title: 'Missing SameSite Flag for Cookie',
                description: `A cookie (${cookie.split(';')[0]}) is being set without the 'SameSite' flag. This makes the cookie vulnerable to Cross-Site Request Forgery (CSRF) attacks.`,
                evidence: {
                  url: baseUrl,
                  headers: { 'Set-Cookie': cookie },
                  statusCode: response.status
                },
                cwe: 'CWE-352',
                owasp: 'A04:2021 – Insecure Design',
                impact: `Increased risk of CSRF attacks.`,
                references: [],
                recommendation: this.generateRecommendationForMisconfiguration(
                  'MISSING_SAMESITE_COOKIE_FLAG',
                  'MEDIUM',
                  'Set the \'SameSite\' flag (e.g., `Lax` or `Strict`) for all cookies to mitigate CSRF attacks.'
                )
              });
            }
          }
          });
        }
      } catch (error: any) {
      logger.error(`Error checking insecure cookie directives for ${baseUrl}: ${error.message}`);
    }
    return results;
  }

  private async checkHttpMethodEnforcement(url: string): Promise<MisconfigurationResult[]> {
    const findings: MisconfigurationResult[] = [];
    const methodsToTest = ['PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'];
    const allowedMethods = ['GET', 'POST'];

    for (const method of methodsToTest) {
      try {
        const response = await axios({ method, url, validateStatus: (status) => status < 400 || status === 405 || status === 501 });
        
        if ((response.status >= 200 && response.status < 300) || response.status === 304) {
          findings.push({
            category: 'HTTP Method Enforcement',
            type: 'UNSAFE_HTTP_METHOD_ALLOWED',
            severity: 'HIGH',
            confidence: 0.8,
            title: `Unsafe HTTP Method ${method.toUpperCase()} Allowed`,
            description: `The endpoint ${url} allows the ${method.toUpperCase()} method, which could lead to unintended data modification or deletion if not properly secured. Expected methods: ${allowedMethods.join(', ')}.`,
            evidence: {
              url: url,
              statusCode: response.status,
              response: this.truncateContent(response.data),
              headers: response.headers as Record<string, string>
            },
            cwe: 'CWE-352',
            owasp: 'A01:2021 – Broken Access Control',
            impact: `Unintended data modification, deletion, or information disclosure.`,
            references: ['https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Methods_Cheat_Sheet.html'],
            recommendation: this.generateRecommendationForMisconfiguration(
              'UNSAFE_HTTP_METHOD_ALLOWED',
              'HIGH',
              `Restrict HTTP methods on ${url} to only those strictly necessary (e.g., GET for retrieval, POST for creation). Implement proper access control checks for all allowed methods.`
            )
          });
        } else if (response.status === 403 || response.status === 401) {
            findings.push({
                category: 'HTTP Method Enforcement',
                type: 'HTTP_METHOD_ALLOWED_WITH_AUTH',
                severity: 'MEDIUM',
                confidence: 0.6,
                title: `HTTP Method ${method.toUpperCase()} Allowed (Requires Auth)`,
                description: `The endpoint ${url} allows the ${method.toUpperCase()} method but requires authentication/authorization. If this method should be completely disallowed, it indicates a misconfiguration.`,
                evidence: {
                    url: url,
                    statusCode: response.status,
                    headers: response.headers as Record<string, string>
                },
                cwe: 'CWE-284',
                owasp: 'A01:2021 – Broken Access Control',
                impact: `Potential for authenticated users to perform unintended actions.`,
                references: [],
                recommendation: this.generateRecommendationForMisconfiguration(
                  'HTTP_METHOD_ALLOWED_WITH_AUTH',
                  'MEDIUM',
                  `If the ${method.toUpperCase()} method should not be used on ${url} at all, explicitly disallow it at the server or API gateway level instead of relying solely on authentication/authorization.`
                )
            });
        }
    } catch (error: any) {
        logger.debug(`Error checking method ${method} for ${url}:`, (error as Error).message);
      }
    }

    return findings;
  }

  private async makeRequest(url: string, headers: Record<string, string> = {}, followRedirects: boolean = true): Promise<AxiosResponse> {
    const axiosConfig: any = {
      timeout: this.options.timeout,
      validateStatus: (status: number) => status < 500,
      maxRedirects: this.options.followRedirects ? this.options.maxRedirects : 0,
      headers: {
        'User-Agent': this.options.userAgent,
        ...headers
      }
    };
    return axios.get(url, axiosConfig);
  }

  private normalizeUrl(url: string): string {
    try {
      const urlObj = new URL(url);
      return urlObj.origin + urlObj.pathname.replace(/\/?$/, '');
    } catch (error) {
      logger.error(`Invalid URL provided: ${url}`);
      throw new Error(`Invalid URL: ${url}`);
    }
  }

  private isValidContent(content: string): boolean {
    return content && content.length > 0 && !content.includes('404 Not Found') && !content.includes('Page Not Found');
  }

  private isDirectoryListing(content: string): boolean {
    return (
      content.includes('<title>Index of /</title>') ||
      content.includes('<h1>Index of /</h1>') ||
      content.includes('<pre><a href="?C=N;O=D">Name</a></pre>') ||
      content.includes('<img src="/icons/folder.gif" alt="[DIR]">')
    );
  }

  private isAdminInterface(content: string, path: string): boolean {
    return (
      path.includes('/admin') ||
      path.includes('/administrator') ||
      content.includes('Admin Panel') ||
      content.includes('Login to Dashboard')
    );
  }

  private isServerInfoPage(content: string): boolean {
    return (
      content.includes('phpinfo()') ||
      content.includes('Apache Status') ||
      content.includes('Nginx Status')
    );
  }

  private hasDetailedErrorInfo(content: string): boolean {
    const errorPatterns = [
      'stack trace', 'on line', 'error in', 'exception', 'syntax error',
      'mysql_connect()', 'sql error', 'pg_connect()', 'failed to connect',
      'at Function.Module._resolveFilename'
    ];
    return errorPatterns.some(pattern => content.toLowerCase().includes(pattern));
  }

  private getSensitiveFileSeverity(filename: string): VulnerabilitySeverity {
    if (filename.includes('.env') || filename.includes('private.key') || filename.includes('secrets')) {
      return 'CRITICAL';
    }
    if (filename.includes('sql') || filename.includes('dump')) {
      return 'HIGH';
    }
    if (filename.includes('phpinfo') || filename.includes('test.php')) {
      return 'MEDIUM';
    }
    return 'LOW';
  }

  private truncateContent(content: string): string {
    const maxLength = 500;
    return content.length > maxLength ? content.substring(0, maxLength) + '...' : content;
  }

  private generateRecommendationForMisconfiguration(type: VulnerabilityType | string, severity: VulnerabilitySeverity, description: string): RemediationGuidance {
    const dummyVulnerability: Vulnerability = {
      id: '',
      scanId: '',
      type: type as VulnerabilityType, // Cast to VulnerabilityType
      severity: severity,
      endpoint: '',
      method: '',
      description: description,
      impact: '',
      confidence: 0,
      evidence: {},
      remediation: {
        priority: 0,
        effort: 'low',
        steps: [],
        automatable: false
      },
      discoveredAt: new Date()
    };
    return this.recommendationService.generateRecommendation(dummyVulnerability);
  }
} 