import { APIEndpoint } from '../types';
import { AuthTestResult } from './authenticationTester';
import { AuthzTestResult, UserContext } from './authorizationTester';
export interface SecurityTestConfig {
    includeAuthentication: boolean;
    includeAuthorization: boolean;
    includeDestructiveTesting: boolean;
    maxBruteForceAttempts: number;
    timeout: number;
    userContexts: UserContext[];
    testTypes: SecurityTestType[];
}
export type SecurityTestType = 'auth_bypass' | 'weak_credentials' | 'jwt_vulnerabilities' | 'brute_force_protection' | 'privilege_escalation' | 'idor' | 'missing_access_control' | 'information_disclosure';
export interface SecurityTestResult {
    endpoint: APIEndpoint;
    authenticationResults: AuthTestResult[];
    authorizationResults: AuthzTestResult[];
    summary: {
        totalTests: number;
        vulnerabilitiesFound: number;
        criticalVulns: number;
        highVulns: number;
        mediumVulns: number;
        lowVulns: number;
        overallRiskScore: number;
    };
    recommendations: string[];
    testDuration: number;
}
export interface SecurityScanProgress {
    phase: 'initializing' | 'auth_testing' | 'authz_testing' | 'analyzing' | 'completed';
    percentage: number;
    currentTest?: string;
    testsCompleted: number;
    totalTests: number;
    vulnerabilitiesFound: number;
    currentEndpoint?: string;
}
export declare class SecurityTester {
    private logger;
    private authTester;
    private authzTester;
    testEndpointSecurity(endpoint: APIEndpoint, config: SecurityTestConfig, progressCallback?: (progress: SecurityScanProgress) => void): Promise<SecurityTestResult>;
    testMultipleEndpoints(endpoints: APIEndpoint[], config: SecurityTestConfig, progressCallback?: (progress: SecurityScanProgress & {
        endpointIndex: number;
        totalEndpoints: number;
        overallProgress: number;
    }) => void): Promise<SecurityTestResult[]>;
    private calculateTotalTests;
    private generateSummary;
    private generateRecommendations;
    generateSecurityReport(results: SecurityTestResult[]): {
        executive_summary: {
            total_endpoints_tested: number;
            total_vulnerabilities: number;
            risk_distribution: Record<string, number>;
            overall_security_score: number;
        };
        detailed_findings: Array<{
            endpoint: string;
            method: string;
            vulnerabilities: Array<{
                type: string;
                severity: string;
                confidence: number;
                description: string;
                recommendation: string;
            }>;
        }>;
        recommendations: string[];
        compliance_status: {
            owasp_api_top_10: Array<{
                requirement: string;
                status: 'PASS' | 'FAIL' | 'WARNING';
                findings: string[];
            }>;
        };
    };
    private assessOwaspCompliance;
}
//# sourceMappingURL=securityTester.d.ts.map