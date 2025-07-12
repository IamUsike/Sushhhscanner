"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.MisconfigurationDetector = void 0;
const axios_1 = __importDefault(require("axios"));
const logger_1 = require("../utils/logger");
class MisconfigurationDetector {
    constructor(options = {}) {
        this.options = options;
        this.defaultOptions = {
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
        this.sensitiveFiles = [
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
        this.sensitivePaths = [
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
        this.options = { ...this.defaultOptions, ...options };
    }
    async scanTarget(baseUrl, progressCallback) {
        logger_1.logger.info(`Starting misconfiguration scan for: ${baseUrl}`);
        const results = [];
        try {
            // Normalize base URL
            const normalizedUrl = this.normalizeUrl(baseUrl);
            if (progressCallback)
                progressCallback('🔍 Starting misconfiguration detection...');
            // 1. HTTP Security Headers Check
            if (this.options.checkHeaders) {
                if (progressCallback)
                    progressCallback('🛡️ Checking HTTP security headers...');
                const headerResults = await this.checkSecurityHeaders(normalizedUrl);
                results.push(...headerResults);
            }
            // 2. Sensitive File Exposure Check
            if (this.options.checkFiles) {
                if (progressCallback)
                    progressCallback('📄 Scanning for exposed sensitive files...');
                const fileResults = await this.checkSensitiveFiles(normalizedUrl);
                results.push(...fileResults);
            }
            // 3. Directory Traversal & Listing Check
            if (this.options.checkDirectories) {
                if (progressCallback)
                    progressCallback('📁 Checking directory listings and traversal...');
                const directoryResults = await this.checkDirectoryMisconfigurations(normalizedUrl);
                results.push(...directoryResults);
            }
            // 4. Server Information Disclosure
            if (this.options.checkServerInfo) {
                if (progressCallback)
                    progressCallback('🖥️ Analyzing server information disclosure...');
                const serverResults = await this.checkServerInformation(normalizedUrl);
                results.push(...serverResults);
            }
            // 5. CORS Misconfiguration
            if (this.options.checkCORS) {
                if (progressCallback)
                    progressCallback('🌐 Testing CORS configurations...');
                const corsResults = await this.checkCORSMisconfiguration(normalizedUrl);
                results.push(...corsResults);
            }
            // 6. Content Security Policy Issues
            if (this.options.checkCSP) {
                if (progressCallback)
                    progressCallback('🔒 Evaluating Content Security Policy...');
                const cspResults = await this.checkCSPMisconfiguration(normalizedUrl);
                results.push(...cspResults);
            }
            // 7. SSL/TLS Configuration Issues
            if (this.options.checkSSL && normalizedUrl.startsWith('https://')) {
                if (progressCallback)
                    progressCallback('🔐 Analyzing SSL/TLS configuration...');
                const sslResults = await this.checkSSLConfiguration(normalizedUrl);
                results.push(...sslResults);
            }
            if (progressCallback)
                progressCallback('✅ Misconfiguration scan completed');
            logger_1.logger.info(`Misconfiguration scan completed. Found ${results.length} issues.`);
            return results;
        }
        catch (error) {
            logger_1.logger.error(`Misconfiguration scan failed: ${error.message}`);
            throw error;
        }
    }
    async checkSecurityHeaders(baseUrl) {
        const results = [];
        try {
            const response = await this.makeRequest(baseUrl);
            const headers = response.headers;
            // Check for missing security headers
            const securityHeaders = {
                'strict-transport-security': {
                    name: 'HTTP Strict Transport Security (HSTS)',
                    severity: 'HIGH',
                    cwe: 'CWE-319',
                    owasp: 'A06:2021 – Vulnerable and Outdated Components'
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
                    owasp: 'A04:2021 – Insecure Design'
                },
                'x-content-type-options': {
                    name: 'X-Content-Type-Options',
                    severity: 'LOW',
                    cwe: 'CWE-79',
                    owasp: 'A03:2021 – Injection'
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
                if (!headers[headerName] && !headers[headerName.toLowerCase()]) {
                    results.push({
                        category: 'HTTP Security Headers',
                        type: 'missing_security_header',
                        severity: headerInfo.severity,
                        confidence: 0.9,
                        title: `Missing ${headerInfo.name}`,
                        description: `The response is missing the ${headerInfo.name} header, which could expose the application to security vulnerabilities.`,
                        evidence: {
                            url: baseUrl,
                            headers: Object.fromEntries(Object.entries(headers).map(([key, value]) => [key, String(value)])),
                            statusCode: response.status
                        },
                        cwe: headerInfo.cwe,
                        owasp: headerInfo.owasp,
                        recommendation: `Implement the ${headerInfo.name} header with appropriate values to enhance security.`,
                        impact: `Without ${headerInfo.name}, the application may be vulnerable to various attacks.`,
                        references: [
                            'https://owasp.org/www-project-secure-headers/',
                            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers'
                        ]
                    });
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
        }
        catch (error) {
            logger_1.logger.warn(`Failed to check security headers: ${error.message}`);
        }
        return results;
    }
    async checkSensitiveFiles(baseUrl) {
        const results = [];
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
            }
            catch (error) {
                // Expected for most files - they should not be accessible
            }
        }
        return results;
    }
    async checkDirectoryMisconfigurations(baseUrl) {
        const results = [];
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
            }
            catch (error) {
                // Expected for most paths
            }
        }
        return results;
    }
    async checkServerInformation(baseUrl) {
        const results = [];
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
                }
                catch (error) {
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
            }
            catch (error) {
                // Expected
            }
        }
        catch (error) {
            logger_1.logger.warn(`Failed to check server information: ${error.message}`);
        }
        return results;
    }
    async checkCORSMisconfiguration(baseUrl) {
        const results = [];
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
                }
                catch (error) {
                    // Expected for some requests
                }
            }
        }
        catch (error) {
            logger_1.logger.warn(`Failed to check CORS configuration: ${error.message}`);
        }
        return results;
    }
    async checkCSPMisconfiguration(baseUrl) {
        const results = [];
        try {
            const response = await this.makeRequest(baseUrl);
            const cspHeader = response.headers['content-security-policy'] ||
                response.headers['content-security-policy-report-only'];
            if (cspHeader) {
                // Check for unsafe CSP directives
                const unsafeDirectives = [
                    { pattern: /unsafe-inline/, severity: 'MEDIUM', issue: 'unsafe-inline' },
                    { pattern: /unsafe-eval/, severity: 'MEDIUM', issue: 'unsafe-eval' },
                    { pattern: /\*/, severity: 'HIGH', issue: 'wildcard source' },
                    { pattern: /data:/, severity: 'LOW', issue: 'data: protocol allowed' },
                    { pattern: /http:\/\//, severity: 'MEDIUM', issue: 'HTTP sources in HTTPS context' }
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
        }
        catch (error) {
            logger_1.logger.warn(`Failed to check CSP configuration: ${error.message}`);
        }
        return results;
    }
    async checkSSLConfiguration(baseUrl) {
        const results = [];
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
            }
            catch (error) {
                // Expected if HTTP is completely disabled
            }
        }
        catch (error) {
            logger_1.logger.warn(`Failed to check SSL configuration: ${error.message}`);
        }
        return results;
    }
    async makeRequest(url, headers = {}, followRedirects = true) {
        return await (0, axios_1.default)({
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
    normalizeUrl(url) {
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'https://' + url;
        }
        return url.replace(/\/$/, '');
    }
    isValidContent(content) {
        if (!content || content.length < 10)
            return false;
        // Check if it's not an error page
        const errorIndicators = ['404', 'not found', 'error', 'forbidden', 'access denied'];
        const lowerContent = content.toLowerCase();
        return !errorIndicators.some(indicator => lowerContent.includes(indicator));
    }
    isDirectoryListing(content) {
        if (!content)
            return false;
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
    isAdminInterface(content, path) {
        if (!content)
            return false;
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
    isServerInfoPage(content) {
        if (!content)
            return false;
        const infoIndicators = [
            'phpinfo()', 'php version', 'apache status', 'server status',
            'system information', 'server information', 'configuration',
            'loaded modules', 'environment', 'build date'
        ];
        const lowerContent = content.toLowerCase();
        return infoIndicators.some(indicator => lowerContent.includes(indicator));
    }
    hasDetailedErrorInfo(content) {
        if (!content)
            return false;
        const errorDetailIndicators = [
            'stack trace', 'exception', 'error in', 'line number',
            'file path', 'debug info', 'call stack', 'traceback'
        ];
        const lowerContent = content.toLowerCase();
        return errorDetailIndicators.some(indicator => lowerContent.includes(indicator));
    }
    getSensitiveFileSeverity(filename) {
        const criticalFiles = ['.env', 'private.key', 'id_rsa', 'database.sql', 'backup.sql'];
        const highFiles = ['config.php', 'config.json', 'secrets.json', 'web.config'];
        const mediumFiles = ['robots.txt', 'phpinfo.php', 'package.json'];
        if (criticalFiles.some(f => filename.includes(f)))
            return 'CRITICAL';
        if (highFiles.some(f => filename.includes(f)))
            return 'HIGH';
        if (mediumFiles.some(f => filename.includes(f)))
            return 'MEDIUM';
        return 'LOW';
    }
    truncateContent(content) {
        const str = typeof content === 'string' ? content : JSON.stringify(content);
        return str.length > 500 ? str.substring(0, 500) + '...[truncated]' : str;
    }
}
exports.MisconfigurationDetector = MisconfigurationDetector;
//# sourceMappingURL=misconfigurationDetector.js.map