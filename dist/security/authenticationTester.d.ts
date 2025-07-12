import { APIEndpoint, VulnerabilitySeverity } from '../types';
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
export declare class AuthenticationTester {
    private logger;
    private readonly bypassPayloads;
    private readonly weakPasswords;
    testAuthentication(endpoint: APIEndpoint, options?: {
        timeout?: number;
        includeDestructive?: boolean;
        maxBruteForceAttempts?: number;
    }): Promise<AuthTestResult[]>;
    private detectAuthenticationMethod;
    private testNoAuthentication;
    private testAuthenticationBypass;
    private testWeakAuthentication;
    private testTokenVulnerabilities;
    private testBruteForceProtection;
    private testInformationDisclosure;
    private makeRequest;
    private containsSuccessfulData;
    private truncateResponse;
    private sanitizeHeaders;
    private buildRequestString;
}
//# sourceMappingURL=authenticationTester.d.ts.map