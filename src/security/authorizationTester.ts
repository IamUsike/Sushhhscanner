import axios, { AxiosResponse, AxiosRequestConfig } from 'axios';
import { APIEndpoint, Vulnerability, VulnerabilityType, VulnerabilitySeverity } from '../types';
import { securityLogger } from '../utils/logger';

export interface AuthorizationTest {
  type: 'horizontal_privilege' | 'vertical_privilege' | 'idor' | 'missing_access_control' | 'role_bypass' | 'path_traversal';
  name: string;
  description: string;
  severity: VulnerabilitySeverity;
  cwe: string;
}

export interface AuthTestCase {
  name: string;
  description: string;
  headers: Record<string, string>;
  params?: Record<string, string>;
  expectedStatus: number[];
  userRole?: string;
}

export interface AuthzTestResult {
  test: AuthorizationTest;
  vulnerable: boolean;
  confidence: number;
  evidence: {
    request?: string;
    response?: string;
    statusCode?: number;
    headers?: Record<string, string>;
    comparisonData?: {
      unauthorizedResponse: string;
      authorizedResponse?: string;
    };
  };
  details: string;
  recommendation: string;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface UserContext {
  role: 'admin' | 'user' | 'guest' | 'anonymous';
  authHeader: string;
  userId?: string;
  permissions?: string[];
}

export class AuthorizationTester {
  private logger = securityLogger;
  
  // Common user IDs for IDOR testing
  private readonly commonUserIds = [
    '1', '2', '3', '10', '100', '1000',
    'admin', 'test', 'user', 'guest',
    '00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000002'
  ];
  
  // Common admin paths
  private readonly adminPaths = [
    '/admin',
    '/dashboard',
    '/settings',
    '/config',
    '/users',
    '/management',
    '/control',
    '/system'
  ];
  
  // Path traversal payloads
  private readonly pathTraversalPayloads = [
    '../',
    '../../',
    '../../../',
    '..../',
    '....//..../',
    '%2e%2e%2f',
    '%2e%2e/',
    '..%2f',
    '%2e%2e%5c',
    '..\\',
    '..%5c'
  ];
  
  async testAuthorization(
    endpoint: APIEndpoint,
    userContexts: UserContext[],
    options: {
      timeout?: number;
      includeDestructive?: boolean;
      testIDOR?: boolean;
      testPathTraversal?: boolean;
    } = {}
  ): Promise<AuthzTestResult[]> {
    const {
      timeout = 10000,
      includeDestructive = false,
      testIDOR = true,
      testPathTraversal = true
    } = options;
    
    this.logger.info('Starting authorization testing', {
      endpoint: `${endpoint.method} ${endpoint.path}`,
      url: endpoint.url,
      contexts: userContexts.length
    });
    
    const results: AuthzTestResult[] = [];
    
    try {
      // 1. Test missing access control
      const missingACResult = await this.testMissingAccessControl(endpoint, timeout);
      if (missingACResult) results.push(missingACResult);
      
      // 2. Test horizontal privilege escalation (if multiple user contexts)
      if (userContexts.length >= 2) {
        const horizontalResults = await this.testHorizontalPrivilegeEscalation(
          endpoint, userContexts, timeout
        );
        results.push(...horizontalResults);
      }
      
      // 3. Test vertical privilege escalation
      const verticalResults = await this.testVerticalPrivilegeEscalation(
        endpoint, userContexts, timeout
      );
      results.push(...verticalResults);
      
      // 4. Test IDOR (Insecure Direct Object References)
      if (testIDOR) {
        const idorResults = await this.testIDOR(endpoint, userContexts, timeout);
        results.push(...idorResults);
      }
      
      // 5. Test role-based access control bypass
      const roleBypassResults = await this.testRoleBypass(endpoint, userContexts, timeout);
      results.push(...roleBypassResults);
      
      // 6. Test path traversal vulnerabilities
      if (testPathTraversal) {
        const pathTraversalResults = await this.testPathTraversal(endpoint, timeout);
        results.push(...pathTraversalResults);
      }
      
      // 7. Test admin functionality access
      const adminAccessResults = await this.testAdminAccess(endpoint, userContexts, timeout);
      results.push(...adminAccessResults);
      
    } catch (error: any) {
      this.logger.error('Authorization testing failed', {
        endpoint: endpoint.url,
        error: error.message
      });
    }
    
    this.logger.info('Authorization testing completed', {
      endpoint: endpoint.url,
      testsRun: results.length,
      vulnerabilities: results.filter(r => r.vulnerable).length
    });
    
    return results;
  }
  
  private async testMissingAccessControl(
    endpoint: APIEndpoint,
    timeout: number
  ): Promise<AuthzTestResult | null> {
    try {
      // Test without any authentication
      const response = await this.makeRequest(endpoint, {}, timeout);
      
      // Check if sensitive operations are accessible without auth
      if (response.status === 200 && this.isSensitiveEndpoint(endpoint)) {
        return {
          test: {
            type: 'missing_access_control',
            name: 'Missing Access Control',
            description: 'Sensitive endpoint accessible without authentication',
            severity: 'HIGH',
            cwe: 'CWE-862'
          },
          vulnerable: true,
          confidence: 0.9,
          evidence: {
            request: `${endpoint.method} ${endpoint.url}`,
            response: this.truncateResponse(response.data),
            statusCode: response.status,
            headers: this.sanitizeHeaders(response.headers)
          },
          details: 'The endpoint allows access to sensitive functionality without proper authentication.',
          recommendation: 'Implement proper authentication and authorization checks for all sensitive endpoints.',
          riskLevel: 'HIGH'
        };
      }
      
    } catch (error: any) {
      // Expected for protected endpoints
    }
    
    return null;
  }
  
  private async testHorizontalPrivilegeEscalation(
    endpoint: APIEndpoint,
    userContexts: UserContext[],
    timeout: number
  ): Promise<AuthzTestResult[]> {
    const results: AuthzTestResult[] = [];
    
    // Test access between users of the same role
    const sameRoleUsers = userContexts.filter(ctx => ctx.role === 'user');
    
    if (sameRoleUsers.length >= 2) {
      const user1 = sameRoleUsers[0];
      const user2 = sameRoleUsers[1];
      
      try {
        // Try to access user1's data with user2's credentials
        const modifiedEndpoint = this.injectUserId(endpoint, user1.userId || '1');
        
        const response = await this.makeRequest(modifiedEndpoint, {
          headers: { 'Authorization': user2.authHeader }
        }, timeout);
        
        if (response.status === 200 && this.containsUserData(response.data, user1.userId)) {
          results.push({
            test: {
              type: 'horizontal_privilege',
              name: 'Horizontal Privilege Escalation',
              description: 'User can access another user\'s data',
              severity: 'HIGH',
              cwe: 'CWE-639'
            },
            vulnerable: true,
            confidence: 0.85,
            evidence: {
              request: `${modifiedEndpoint.method} ${modifiedEndpoint.url} (using ${user2.role} credentials)`,
              response: this.truncateResponse(response.data),
              statusCode: response.status,
              comparisonData: {
                unauthorizedResponse: 'User2 accessing User1 data'
              }
            },
            details: `User with role '${user2.role}' can access data belonging to another user.`,
            recommendation: 'Implement proper user-based access control to prevent horizontal privilege escalation.',
            riskLevel: 'HIGH'
          });
        }
        
      } catch (error: any) {
        // Expected if proper access control is in place
      }
    }
    
    return results;
  }
  
  private async testVerticalPrivilegeEscalation(
    endpoint: APIEndpoint,
    userContexts: UserContext[],
    timeout: number
  ): Promise<AuthzTestResult[]> {
    const results: AuthzTestResult[] = [];
    
    const adminUser = userContexts.find(ctx => ctx.role === 'admin');
    const regularUsers = userContexts.filter(ctx => ctx.role !== 'admin');
    
    if (adminUser && regularUsers.length > 0) {
      for (const user of regularUsers) {
        // Check if admin-only endpoints are accessible by regular users
        if (this.isAdminEndpoint(endpoint)) {
          try {
            const response = await this.makeRequest(endpoint, {
              headers: { 'Authorization': user.authHeader }
            }, timeout);
            
            if (response.status === 200) {
              results.push({
                test: {
                  type: 'vertical_privilege',
                  name: 'Vertical Privilege Escalation',
                  description: 'Non-admin user can access admin functionality',
                  severity: 'CRITICAL',
                  cwe: 'CWE-284'
                },
                vulnerable: true,
                confidence: 0.95,
                evidence: {
                  request: `${endpoint.method} ${endpoint.url} (using ${user.role} credentials)`,
                  response: this.truncateResponse(response.data),
                  statusCode: response.status
                },
                details: `User with role '${user.role}' can access admin-only functionality.`,
                recommendation: 'Implement proper role-based access control (RBAC) to prevent privilege escalation.',
                riskLevel: 'CRITICAL'
              });
            }
            
          } catch (error: any) {
            // Expected if proper access control is in place
          }
        }
      }
    }
    
    return results;
  }
  
  private async testIDOR(
    endpoint: APIEndpoint,
    userContexts: UserContext[],
    timeout: number
  ): Promise<AuthzTestResult[]> {
    const results: AuthzTestResult[] = [];
    
    // Check if endpoint has ID parameters that could be manipulated
    const hasIdParam = this.hasIdParameter(endpoint);
    
    if (hasIdParam && userContexts.length > 0) {
      const userContext = userContexts[0];
      
      for (const testId of this.commonUserIds) {
        try {
          const modifiedEndpoint = this.injectUserId(endpoint, testId);
          
          const response = await this.makeRequest(modifiedEndpoint, {
            headers: { 'Authorization': userContext.authHeader }
          }, timeout);
          
          // Check if we can access data for different user IDs
          if (response.status === 200 && this.containsUserData(response.data, testId)) {
            results.push({
              test: {
                type: 'idor',
                name: 'Insecure Direct Object Reference (IDOR)',
                description: `Access to unauthorized object with ID: ${testId}`,
                severity: 'HIGH',
                cwe: 'CWE-639'
              },
              vulnerable: true,
              confidence: 0.8,
              evidence: {
                request: `${modifiedEndpoint.method} ${modifiedEndpoint.url}`,
                response: this.truncateResponse(response.data),
                statusCode: response.status
              },
              details: `The endpoint allows access to objects by directly manipulating ID parameters.`,
              recommendation: 'Implement proper authorization checks to verify user ownership of resources.',
              riskLevel: 'HIGH'
            });
          }
          
        } catch (error: any) {
          // Expected for non-existent IDs or proper access control
        }
      }
    }
    
    return results;
  }
  
  private async testRoleBypass(
    endpoint: APIEndpoint,
    userContexts: UserContext[],
    timeout: number
  ): Promise<AuthzTestResult[]> {
    const results: AuthzTestResult[] = [];
    
    // Test role manipulation in headers
    const roleBypassHeaders = [
      { 'X-User-Role': 'admin' },
      { 'X-Role': 'administrator' },
      { 'User-Role': 'admin' },
      { 'Role': 'admin' },
      { 'X-Admin': 'true' },
      { 'X-Privilege': 'admin' },
      { 'X-Permission': 'all' }
    ];
    
    for (const userContext of userContexts) {
      if (userContext.role !== 'admin') {
        for (const bypassHeaders of roleBypassHeaders) {
          try {
            const headers = {
              'Authorization': userContext.authHeader,
              ...bypassHeaders
            };
            
            const response = await this.makeRequest(endpoint, { headers }, timeout);
            
            // Check if role bypass was successful
            if (response.status === 200 && this.containsAdminData(response.data)) {
              results.push({
                test: {
                  type: 'role_bypass',
                  name: 'Role Bypass via Headers',
                  description: 'Role escalation through header manipulation',
                  severity: 'HIGH',
                  cwe: 'CWE-284'
                },
                vulnerable: true,
                confidence: 0.8,
                evidence: {
                  request: `${endpoint.method} ${endpoint.url} with headers: ${JSON.stringify(bypassHeaders)}`,
                  response: this.truncateResponse(response.data),
                  statusCode: response.status,
                  headers: bypassHeaders
                },
                details: 'The application trusts client-supplied role information in headers.',
                recommendation: 'Never trust client-supplied role information. Validate roles server-side.',
                riskLevel: 'HIGH'
              });
            }
            
          } catch (error: any) {
            // Expected for proper role validation
          }
        }
      }
    }
    
    return results;
  }
  
  private async testPathTraversal(
    endpoint: APIEndpoint,
    timeout: number
  ): Promise<AuthzTestResult[]> {
    const results: AuthzTestResult[] = [];
    
    // Only test if endpoint has path parameters
    if (!endpoint.path.includes('{') && !endpoint.path.includes(':')) {
      return results;
    }
    
    for (const payload of this.pathTraversalPayloads) {
      try {
        const modifiedEndpoint = {
          ...endpoint,
          url: endpoint.url.replace(/\/[^\/]+$/, `/${payload}admin`),
          path: endpoint.path.replace(/\/[^\/]+$/, `/${payload}admin`)
        };
        
        const response = await this.makeRequest(modifiedEndpoint, {}, timeout);
        
        // Check for signs of successful path traversal
        if (response.status === 200 && this.containsSystemFiles(response.data)) {
          results.push({
            test: {
              type: 'path_traversal',
              name: 'Path Traversal',
              description: `Path traversal successful with payload: ${payload}`,
              severity: 'HIGH',
              cwe: 'CWE-22'
            },
            vulnerable: true,
            confidence: 0.85,
            evidence: {
              request: `${modifiedEndpoint.method} ${modifiedEndpoint.url}`,
              response: this.truncateResponse(response.data),
              statusCode: response.status
            },
            details: 'The endpoint is vulnerable to path traversal attacks.',
            recommendation: 'Implement proper input validation and sanitization for path parameters.',
            riskLevel: 'HIGH'
          });
        }
        
      } catch (error: any) {
        // Expected for most path traversal attempts
      }
    }
    
    return results;
  }
  
  private async testAdminAccess(
    endpoint: APIEndpoint,
    userContexts: UserContext[],
    timeout: number
  ): Promise<AuthzTestResult[]> {
    const results: AuthzTestResult[] = [];
    
    const nonAdminUsers = userContexts.filter(ctx => ctx.role !== 'admin');
    
    // Test access to admin paths
    for (const adminPath of this.adminPaths) {
      const testEndpoint = {
        ...endpoint,
        url: `${endpoint.url.split('?')[0]}${adminPath}`,
        path: `${endpoint.path}${adminPath}`
      };
      
      for (const user of nonAdminUsers) {
        try {
          const response = await this.makeRequest(testEndpoint, {
            headers: { 'Authorization': user.authHeader }
          }, timeout);
          
          if (response.status === 200 && this.containsAdminData(response.data)) {
            results.push({
              test: {
                type: 'vertical_privilege',
                name: 'Unauthorized Admin Access',
                description: `Non-admin user accessed admin path: ${adminPath}`,
                severity: 'CRITICAL',
                cwe: 'CWE-284'
              },
              vulnerable: true,
              confidence: 0.9,
              evidence: {
                request: `${testEndpoint.method} ${testEndpoint.url} (${user.role})`,
                response: this.truncateResponse(response.data),
                statusCode: response.status
              },
              details: `User with role '${user.role}' gained access to admin functionality.`,
              recommendation: 'Implement strict access control for administrative functionality.',
              riskLevel: 'CRITICAL'
            });
          }
          
        } catch (error: any) {
          // Expected for proper access control
        }
      }
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
      validateStatus: () => true,
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
  
  private isSensitiveEndpoint(endpoint: APIEndpoint): boolean {
    const sensitivePaths = [
      '/admin', '/users', '/config', '/settings', '/dashboard',
      '/delete', '/remove', '/update', '/create', '/edit'
    ];
    
    const sensitiveMethods = ['POST', 'PUT', 'DELETE', 'PATCH'];
    
    return sensitivePaths.some(path => endpoint.path.toLowerCase().includes(path)) ||
           sensitiveMethods.includes(endpoint.method.toUpperCase());
  }
  
  private isAdminEndpoint(endpoint: APIEndpoint): boolean {
    const adminPaths = ['/admin', '/dashboard', '/settings', '/config', '/management'];
    return adminPaths.some(path => endpoint.path.toLowerCase().includes(path));
  }
  
  private hasIdParameter(endpoint: APIEndpoint): boolean {
    return endpoint.path.includes('{id}') || 
           endpoint.path.includes(':id') ||
           endpoint.path.includes('{userId}') ||
           endpoint.path.includes(':userId') ||
           /\/\d+/.test(endpoint.path);
  }
  
  private injectUserId(endpoint: APIEndpoint, userId: string): APIEndpoint {
    return {
      ...endpoint,
      url: endpoint.url.replace(/\/\d+/, `/${userId}`).replace(/\{id\}/, userId).replace(/\{userId\}/, userId),
      path: endpoint.path.replace(/\/\d+/, `/${userId}`).replace(/\{id\}/, userId).replace(/\{userId\}/, userId)
    };
  }
  
  private containsUserData(data: any, userId?: string): boolean {
    if (!data) return false;
    
    const dataStr = typeof data === 'string' ? data : JSON.stringify(data);
    const indicators = ['user', 'profile', 'account', 'personal', 'private'];
    
    if (userId) {
      return dataStr.includes(userId);
    }
    
    return indicators.some(indicator => dataStr.toLowerCase().includes(indicator));
  }
  
  private containsAdminData(data: any): boolean {
    if (!data) return false;
    
    const dataStr = typeof data === 'string' ? data : JSON.stringify(data);
    const adminIndicators = [
      'admin', 'administrator', 'management', 'control',
      'system', 'config', 'settings', 'dashboard'
    ];
    
    return adminIndicators.some(indicator => 
      dataStr.toLowerCase().includes(indicator)
    );
  }
  
  private containsSystemFiles(data: any): boolean {
    if (!data) return false;
    
    const dataStr = typeof data === 'string' ? data : JSON.stringify(data);
    const systemIndicators = [
      '/etc/', '/var/', '/usr/', '/root/',
      'passwd', 'shadow', 'hosts', 'config'
    ];
    
    return systemIndicators.some(indicator => 
      dataStr.toLowerCase().includes(indicator)
    );
  }
  
  private truncateResponse(data: any): string {
    const str = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
    return str.length > 500 ? str.substring(0, 500) + '...' : str;
  }
  
  private sanitizeHeaders(headers: any): Record<string, string> {
    const sanitized: Record<string, string> = {};
    const relevantHeaders = [
      'content-type', 'content-length', 'server', 'x-powered-by',
      'www-authenticate', 'set-cookie', 'access-control-allow-origin'
    ];
    
    for (const header of relevantHeaders) {
      if (headers[header]) {
        sanitized[header] = headers[header];
      }
    }
    
    return sanitized;
  }
} 