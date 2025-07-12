import { APIEndpoint, VulnerabilitySeverity } from '../types';
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
export declare class AuthorizationTester {
    private logger;
    private readonly commonUserIds;
    private readonly adminPaths;
    private readonly pathTraversalPayloads;
    testAuthorization(endpoint: APIEndpoint, userContexts: UserContext[], options?: {
        timeout?: number;
        includeDestructive?: boolean;
        testIDOR?: boolean;
        testPathTraversal?: boolean;
    }): Promise<AuthzTestResult[]>;
    private testMissingAccessControl;
    private testHorizontalPrivilegeEscalation;
    private testVerticalPrivilegeEscalation;
    private testIDOR;
    private testRoleBypass;
    private testPathTraversal;
    private testAdminAccess;
    private makeRequest;
    private isSensitiveEndpoint;
    private isAdminEndpoint;
    private hasIdParameter;
    private injectUserId;
    private containsUserData;
    private containsAdminData;
    private containsSystemFiles;
    private truncateResponse;
    private sanitizeHeaders;
}
//# sourceMappingURL=authorizationTester.d.ts.map