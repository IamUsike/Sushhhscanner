import axios, { AxiosResponse, AxiosRequestConfig } from 'axios';
import { APIEndpoint, Vulnerability, VulnerabilityType, VulnerabilitySeverity } from '../types';
import { securityLogger } from '../utils/logger';

export interface AuthenticationTest {
  type: 'no_auth' | 'weak_auth' | 'bypass_auth' | 'token_leak' | 'session_fixation' | 'brute_force';
  name: string;
  description: string;
  severity: VulnerabilitySeverity;
  cwe: string;
}

export interface AuthTestResult {
  test: AuthenticationTest;
  vulnerable: boolean;
  confidence: number;
  evidence: {
    request?: string;
    response?: string;
    statusCode?: number;
    headers?: Record<string, string>;
    timingAttack?: boolean;
    errorMessages?: string[];
  };
  details: string;
  recommendation: string;
}

export interface AuthenticationInfo {
  type: 'none' | 'basic' | 'bearer' | 'api_key' | 'oauth2' | 'jwt' | 'session' | 'digest';
  location: 'header' | 'query' | 'body' | 'cookie';
  parameter?: string;
  detected: boolean;
  bypass_attempts: string[];
}

export class AuthenticationTester {
  private logger = securityLogger;
  
  // Common authentication bypass payloads
  private readonly bypassPayloads = [
    // No authentication
    '',
    
    // Common bypass tokens
    'admin',
    'test',
    'null',
    'undefined',
    'Bearer null',
    'Bearer undefined',
    'Bearer admin',
    'Bearer test',
    
    // SQL injection attempts in auth
    "' OR '1'='1",
    '" OR "1"="1',
    'admin\' OR \'1\'=\'1',
    
    // JWT manipulation
    'Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.',
    'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.invalid',
    
    // API key bypass attempts
    'test',
    'admin',
    'api_key',
    'key',
    '12345',
    'password',
    
    // Basic auth bypass
    'Basic YWRtaW46YWRtaW4=', // admin:admin
    'Basic dGVzdDp0ZXN0', // test:test
    'Basic YWRtaW46cGFzc3dvcmQ=', // admin:password
    
    // Session manipulation
    'JSESSIONID=admin',
    'session_id=admin',
    'auth_token=admin'
  ];
  
  // Common weak passwords for brute force testing
  private readonly weakPasswords = [
    'password',
    '123456',
    'admin',
    'test',
    'password123',
    'admin123',
    'qwerty',
    'letmein',
    'welcome',
    'monkey'
  ];
  
  async testAuthentication(
    endpoint: APIEndpoint,
    options: {
      timeout?: number;
      includeDestructive?: boolean;
      maxBruteForceAttempts?: number;
    } = {}
  ): Promise<AuthTestResult[]> {
    const {
      timeout = 10000,
      includeDestructive = false,
      maxBruteForceAttempts = 5
    } = options;
    
    this.logger.info('Starting authentication testing', {
      endpoint: `${endpoint.method} ${endpoint.path}`,
      url: endpoint.url
    });
    
    const results: AuthTestResult[] = [];
    
    try {
      // 1. Detect authentication requirements
      const authInfo = await this.detectAuthenticationMethod(endpoint, timeout);
      
      // 2. Test for missing authentication
      const noAuthResult = await this.testNoAuthentication(endpoint, timeout);
      if (noAuthResult) results.push(noAuthResult);
      
      // 3. Test authentication bypass techniques
      const bypassResults = await this.testAuthenticationBypass(endpoint, authInfo, timeout);
      results.push(...bypassResults);
      
      // 4. Test for weak authentication
      const weakAuthResults = await this.testWeakAuthentication(endpoint, authInfo, timeout);
      results.push(...weakAuthResults);
      
      // 5. Test for token/session vulnerabilities
      const tokenResults = await this.testTokenVulnerabilities(endpoint, authInfo, timeout);
      results.push(...tokenResults);
      
      // 6. Test brute force protection (if destructive testing allowed)
      if (includeDestructive && maxBruteForceAttempts > 0) {
        const bruteForceResult = await this.testBruteForceProtection(
          endpoint, 
          authInfo, 
          timeout,
          maxBruteForceAttempts
        );
        if (bruteForceResult) results.push(bruteForceResult);
      }
      
      // 7. Test for information disclosure in error messages
      const infoDisclosureResults = await this.testInformationDisclosure(endpoint, timeout);
      results.push(...infoDisclosureResults);
      
    } catch (error: any) {
      this.logger.error('Authentication testing failed', {
        endpoint: endpoint.url,
        error: error.message
      });
    }
    
    this.logger.info('Authentication testing completed', {
      endpoint: endpoint.url,
      testsRun: results.length,
      vulnerabilities: results.filter(r => r.vulnerable).length
    });
    
    return results;
  }
  
  private async detectAuthenticationMethod(
    endpoint: APIEndpoint,
    timeout: number
  ): Promise<AuthenticationInfo> {
    const authInfo: AuthenticationInfo = {
      type: 'none',
      location: 'header',
      detected: false,
      bypass_attempts: []
    };
    
    try {
      // Test without authentication
      const response = await this.makeRequest(endpoint, {}, timeout);
      
      if (response.status === 401) {
        authInfo.detected = true;
        
        // Analyze WWW-Authenticate header
        const wwwAuth = response.headers['www-authenticate'];
        if (wwwAuth) {
          if (wwwAuth.toLowerCase().includes('bearer')) {
            authInfo.type = 'bearer';
          } else if (wwwAuth.toLowerCase().includes('basic')) {
            authInfo.type = 'basic';
          } else if (wwwAuth.toLowerCase().includes('digest')) {
            authInfo.type = 'digest';
          }
        }
        
        // Check for common API key requirements in response
        const responseText = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
        if (responseText.includes('api_key') || responseText.includes('apikey')) {
          authInfo.type = 'api_key';
          authInfo.location = 'query';
          authInfo.parameter = 'api_key';
        }
      }
      
      // Check if endpoint uses cookies/sessions
      if (response.headers['set-cookie']) {
        authInfo.type = 'session';
        authInfo.location = 'cookie';
      }
      
    } catch (error: any) {
      this.logger.debug('Error detecting authentication method', {
        endpoint: endpoint.url,
        error: error.message
      });
    }
    
    return authInfo;
  }
  
  private async testNoAuthentication(
    endpoint: APIEndpoint,
    timeout: number
  ): Promise<AuthTestResult | null> {
    try {
      const response = await this.makeRequest(endpoint, {}, timeout);
      
      // If we get 200 OK without authentication, it might be a vulnerability
      if (response.status === 200) {
        return {
          test: {
            type: 'no_auth',
            name: 'Missing Authentication',
            description: 'Endpoint accessible without authentication',
            severity: 'HIGH',
            cwe: 'CWE-287'
          },
          vulnerable: true,
          confidence: 0.9,
          evidence: {
            request: `${endpoint.method} ${endpoint.url}`,
            response: this.truncateResponse(response.data),
            statusCode: response.status,
            headers: this.sanitizeHeaders(response.headers)
          },
          details: 'The endpoint responds with 200 OK without any authentication headers or tokens.',
          recommendation: 'Implement proper authentication mechanisms to protect this endpoint.'
        };
      }
      
    } catch (error: any) {
      // Expected for protected endpoints
    }
    
    return null;
  }
  
  private async testAuthenticationBypass(
    endpoint: APIEndpoint,
    authInfo: AuthenticationInfo,
    timeout: number
  ): Promise<AuthTestResult[]> {
    const results: AuthTestResult[] = [];
    
    for (const payload of this.bypassPayloads) {
      try {
        const headers: Record<string, string> = {};
        const params: Record<string, string> = {};
        
        // Apply payload based on detected auth type
        switch (authInfo.type) {
          case 'bearer':
            headers['Authorization'] = payload.startsWith('Bearer ') ? payload : `Bearer ${payload}`;
            break;
          case 'basic':
            headers['Authorization'] = payload.startsWith('Basic ') ? payload : `Basic ${payload}`;
            break;
          case 'api_key':
            if (authInfo.location === 'header') {
              headers[authInfo.parameter || 'X-API-Key'] = payload;
            } else if (authInfo.location === 'query') {
              params[authInfo.parameter || 'api_key'] = payload;
            }
            break;
          default:
            headers['Authorization'] = payload;
        }
        
        const response = await this.makeRequest(endpoint, { headers, params }, timeout);
        
        // Check for successful bypass
        if (response.status === 200 && this.containsSuccessfulData(response.data)) {
          results.push({
            test: {
              type: 'bypass_auth',
              name: 'Authentication Bypass',
              description: `Authentication bypassed using payload: ${payload}`,
              severity: 'CRITICAL',
              cwe: 'CWE-287'
            },
            vulnerable: true,
            confidence: 0.95,
            evidence: {
              request: this.buildRequestString(endpoint, headers, params),
              response: this.truncateResponse(response.data),
              statusCode: response.status,
              headers: this.sanitizeHeaders(response.headers)
            },
            details: `The endpoint accepted the bypass payload "${payload}" and returned successful response.`,
            recommendation: 'Implement proper input validation and authentication verification.'
          });
        }
        
      } catch (error: any) {
        // Expected for most bypass attempts
      }
    }
    
    return results;
  }
  
  private async testWeakAuthentication(
    endpoint: APIEndpoint,
    authInfo: AuthenticationInfo,
    timeout: number
  ): Promise<AuthTestResult[]> {
    const results: AuthTestResult[] = [];
    
    // Test common weak credentials
    const weakCredentials = [
      { username: 'admin', password: 'admin' },
      { username: 'admin', password: 'password' },
      { username: 'admin', password: '123456' },
      { username: 'test', password: 'test' },
      { username: 'user', password: 'user' },
      { username: 'guest', password: 'guest' }
    ];
    
    if (authInfo.type === 'basic') {
      for (const cred of weakCredentials) {
        try {
          const authHeader = `Basic ${Buffer.from(`${cred.username}:${cred.password}`).toString('base64')}`;
          const response = await this.makeRequest(endpoint, {
            headers: { 'Authorization': authHeader }
          }, timeout);
          
          if (response.status === 200) {
            results.push({
              test: {
                type: 'weak_auth',
                name: 'Weak Credentials',
                description: `Weak credentials accepted: ${cred.username}:${cred.password}`,
                severity: 'HIGH',
                cwe: 'CWE-521'
              },
              vulnerable: true,
              confidence: 0.9,
              evidence: {
                request: `${endpoint.method} ${endpoint.url} (Basic Auth: ${cred.username}:${cred.password})`,
                response: this.truncateResponse(response.data),
                statusCode: response.status
              },
              details: `The endpoint accepts weak credentials: ${cred.username}:${cred.password}`,
              recommendation: 'Enforce strong password policies and disable default credentials.'
            });
          }
          
        } catch (error: any) {
          // Expected for wrong credentials
        }
      }
    }
    
    return results;
  }
  
  private async testTokenVulnerabilities(
    endpoint: APIEndpoint,
    authInfo: AuthenticationInfo,
    timeout: number
  ): Promise<AuthTestResult[]> {
    const results: AuthTestResult[] = [];
    
    if (authInfo.type === 'bearer' || authInfo.type === 'jwt') {
      // Test JWT vulnerabilities
      const jwtTests = [
        // None algorithm attack
        'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.',
        
        // Weak secret attack
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.YY_w1clNTpP7w2m9VWB_vc_R_3ZWf6qzx8xzRFqPKbw',
        
        // Empty signature
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.',
        
        // Malformed JWT
        'invalid.jwt.token'
      ];
      
      for (const token of jwtTests) {
        try {
          const response = await this.makeRequest(endpoint, {
            headers: { 'Authorization': `Bearer ${token}` }
          }, timeout);
          
          if (response.status === 200) {
            results.push({
              test: {
                type: 'token_leak',
                name: 'JWT Vulnerability',
                description: 'JWT token accepted with weak/invalid signature',
                severity: 'HIGH',
                cwe: 'CWE-345'
              },
              vulnerable: true,
              confidence: 0.85,
              evidence: {
                request: `${endpoint.method} ${endpoint.url} (JWT: ${token.substring(0, 50)}...)`,
                response: this.truncateResponse(response.data),
                statusCode: response.status
              },
              details: 'The endpoint accepted a JWT token with weak or invalid signature.',
              recommendation: 'Implement proper JWT signature verification and use strong secrets.'
            });
          }
          
        } catch (error: any) {
          // Expected for invalid tokens
        }
      }
    }
    
    return results;
  }
  
  private async testBruteForceProtection(
    endpoint: APIEndpoint,
    authInfo: AuthenticationInfo,
    timeout: number,
    maxAttempts: number
  ): Promise<AuthTestResult | null> {
    if (authInfo.type !== 'basic') {
      return null; // Only test brute force for basic auth
    }
    
    const attempts: { time: number; statusCode: number }[] = [];
    
    try {
      for (let i = 0; i < maxAttempts; i++) {
        const startTime = Date.now();
        const password = this.weakPasswords[i % this.weakPasswords.length];
        const authHeader = `Basic ${Buffer.from(`admin:${password}`).toString('base64')}`;
        
        try {
          const response = await this.makeRequest(endpoint, {
            headers: { 'Authorization': authHeader }
          }, timeout);
          
          attempts.push({
            time: Date.now() - startTime,
            statusCode: response.status
          });
          
        } catch (error: any) {
          attempts.push({
            time: Date.now() - startTime,
            statusCode: error.response?.status || 0
          });
        }
        
        // Small delay between attempts
        await new Promise(resolve => setTimeout(resolve, 100));
      }
      
      // Analyze if there's rate limiting or account lockout
      const consistentTiming = attempts.every(a => Math.abs(a.time - attempts[0].time) < 1000);
      const consistentResponses = attempts.every(a => a.statusCode === attempts[0].statusCode);
      
      if (consistentTiming && consistentResponses) {
        return {
          test: {
            type: 'brute_force',
            name: 'Missing Brute Force Protection',
            description: 'No rate limiting or account lockout detected',
            severity: 'MEDIUM',
            cwe: 'CWE-307'
          },
          vulnerable: true,
          confidence: 0.7,
          evidence: {
            request: `${maxAttempts} authentication attempts to ${endpoint.url}`,
            response: `Consistent response times: ${attempts.map(a => a.time).join(', ')}ms`,
            statusCode: attempts[0].statusCode
          },
          details: `Performed ${maxAttempts} authentication attempts without rate limiting or lockout.`,
          recommendation: 'Implement rate limiting, account lockout, and CAPTCHA after failed attempts.'
        };
      }
      
    } catch (error: any) {
      this.logger.error('Brute force testing failed', {
        endpoint: endpoint.url,
        error: error.message
      });
    }
    
    return null;
  }
  
  private async testInformationDisclosure(
    endpoint: APIEndpoint,
    timeout: number
  ): Promise<AuthTestResult[]> {
    const results: AuthTestResult[] = [];
    
    try {
      // Test with various invalid auth headers to see error messages
      const invalidAuthTests = [
        { header: 'Authorization', value: 'Bearer invalid_token' },
        { header: 'Authorization', value: 'Basic invalid_credentials' },
        { header: 'X-API-Key', value: 'invalid_key' }
      ];
      
      for (const test of invalidAuthTests) {
        try {
          const response = await this.makeRequest(endpoint, {
            headers: { [test.header]: test.value }
          }, timeout);
          
          const responseText = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
          
          // Check for sensitive information in error messages
          const sensitivePatterns = [
            /database/i,
            /sql/i,
            /stack trace/i,
            /internal server/i,
            /debug/i,
            /exception/i,
            /file not found/i,
            /access denied/i
          ];
          
          const foundPatterns = sensitivePatterns.filter(pattern => pattern.test(responseText));
          
          if (foundPatterns.length > 0) {
            results.push({
              test: {
                type: 'token_leak',
                name: 'Information Disclosure in Error Messages',
                description: 'Sensitive information exposed in authentication error messages',
                severity: 'LOW',
                cwe: 'CWE-209'
              },
              vulnerable: true,
              confidence: 0.6,
              evidence: {
                request: `${endpoint.method} ${endpoint.url} (${test.header}: ${test.value})`,
                response: this.truncateResponse(responseText),
                statusCode: response.status,
                errorMessages: foundPatterns.map(p => p.toString())
              },
              details: 'Error messages contain potentially sensitive system information.',
              recommendation: 'Implement generic error messages that do not reveal system details.'
            });
          }
          
        } catch (error: any) {
          // Check error response for information disclosure
          if (error.response && error.response.data) {
            const errorText = typeof error.response.data === 'string' ? 
              error.response.data : JSON.stringify(error.response.data);
            
            if (errorText.includes('stack') || errorText.includes('debug') || errorText.includes('internal')) {
              results.push({
                test: {
                  type: 'token_leak',
                  name: 'Information Disclosure in Error Response',
                  description: 'System information leaked in error responses',
                  severity: 'LOW',
                  cwe: 'CWE-209'
                },
                vulnerable: true,
                confidence: 0.7,
                evidence: {
                  request: `${endpoint.method} ${endpoint.url}`,
                  response: this.truncateResponse(errorText),
                  statusCode: error.response.status
                },
                details: 'Error responses contain system debugging information.',
                recommendation: 'Configure proper error handling to avoid information leakage.'
              });
            }
          }
        }
      }
      
    } catch (error: any) {
      this.logger.error('Information disclosure testing failed', {
        endpoint: endpoint.url,
        error: error.message
      });
    }
    
    return results;
  }
  
  private async makeRequest(
    endpoint: APIEndpoint,
    config: {
      headers?: Record<string, string>;
      params?: Record<string, string>;
      data?: any;
    },
    timeout: number
  ): Promise<AxiosResponse> {
    const axiosConfig: AxiosRequestConfig = {
      method: endpoint.method.toLowerCase() as any,
      url: endpoint.url,
      timeout,
      validateStatus: () => true, // Don't throw on any status code
      headers: {
        'User-Agent': 'API-Security-Scanner/1.0',
        'Accept': 'application/json, */*',
        ...config.headers
      }
    };
    
    if (config.params) {
      axiosConfig.params = config.params;
    }
    
    if (config.data) {
      axiosConfig.data = config.data;
    }
    
    return await axios(axiosConfig);
  }
  
  private containsSuccessfulData(data: any): boolean {
    if (!data) return false;
    
    const dataStr = typeof data === 'string' ? data : JSON.stringify(data);
    
    // Look for indicators of successful API responses
    const successIndicators = [
      'success',
      'data',
      'result',
      'user',
      'users',
      'id',
      'name',
      'email'
    ];
    
    const errorIndicators = [
      'error',
      'unauthorized',
      'forbidden',
      'invalid',
      'denied'
    ];
    
    const hasSuccess = successIndicators.some(indicator => 
      dataStr.toLowerCase().includes(indicator)
    );
    const hasError = errorIndicators.some(indicator => 
      dataStr.toLowerCase().includes(indicator)
    );
    
    return hasSuccess && !hasError;
  }
  
  private truncateResponse(data: any): string {
    const str = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
    return str.length > 500 ? str.substring(0, 500) + '...' : str;
  }
  
  private sanitizeHeaders(headers: any): Record<string, string> {
    const sanitized: Record<string, string> = {};
    const relevantHeaders = [
      'content-type',
      'content-length',
      'server',
      'x-powered-by',
      'www-authenticate',
      'set-cookie',
      'access-control-allow-origin'
    ];
    
    for (const header of relevantHeaders) {
      if (headers[header]) {
        sanitized[header] = headers[header];
      }
    }
    
    return sanitized;
  }
  
  private buildRequestString(
    endpoint: APIEndpoint,
    headers: Record<string, string>,
    params: Record<string, string>
  ): string {
    let request = `${endpoint.method} ${endpoint.url}`;
    
    if (Object.keys(params).length > 0) {
      const paramStr = new URLSearchParams(params).toString();
      request += `?${paramStr}`;
    }
    
    if (Object.keys(headers).length > 0) {
      request += '\nHeaders:\n';
      Object.entries(headers).forEach(([key, value]) => {
        request += `  ${key}: ${value}\n`;
      });
    }
    
    return request;
  }
} 