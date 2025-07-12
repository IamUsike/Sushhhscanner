"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecurityTester = void 0;
const authenticationTester_1 = require("./authenticationTester");
const authorizationTester_1 = require("./authorizationTester");
const logger_1 = require("../utils/logger");
class SecurityTester {
    constructor() {
        this.logger = logger_1.securityLogger;
        this.authTester = new authenticationTester_1.AuthenticationTester();
        this.authzTester = new authorizationTester_1.AuthorizationTester();
    }
    async testEndpointSecurity(endpoint, config, progressCallback) {
        const startTime = Date.now();
        this.logger.info('Starting comprehensive security testing', {
            endpoint: `${endpoint.method} ${endpoint.path}`,
            config: {
                auth: config.includeAuthentication,
                authz: config.includeAuthorization,
                destructive: config.includeDestructiveTesting,
                testTypes: config.testTypes
            }
        });
        let authResults = [];
        let authzResults = [];
        let testsCompleted = 0;
        const totalTests = this.calculateTotalTests(config);
        try {
            // Phase 1: Authentication Testing
            if (config.includeAuthentication) {
                if (progressCallback) {
                    progressCallback({
                        phase: 'auth_testing',
                        percentage: 0,
                        currentTest: 'Authentication Security',
                        testsCompleted,
                        totalTests,
                        vulnerabilitiesFound: 0,
                        currentEndpoint: `${endpoint.method} ${endpoint.path}`
                    });
                }
                authResults = await this.authTester.testAuthentication(endpoint, {
                    timeout: config.timeout,
                    includeDestructive: config.includeDestructiveTesting,
                    maxBruteForceAttempts: config.maxBruteForceAttempts
                });
                testsCompleted += authResults.length;
                if (progressCallback) {
                    progressCallback({
                        phase: 'auth_testing',
                        percentage: 40,
                        currentTest: 'Authentication Testing Complete',
                        testsCompleted,
                        totalTests,
                        vulnerabilitiesFound: authResults.filter(r => r.vulnerable).length,
                        currentEndpoint: `${endpoint.method} ${endpoint.path}`
                    });
                }
            }
            // Phase 2: Authorization Testing
            if (config.includeAuthorization && config.userContexts.length > 0) {
                if (progressCallback) {
                    progressCallback({
                        phase: 'authz_testing',
                        percentage: 40,
                        currentTest: 'Authorization Security',
                        testsCompleted,
                        totalTests,
                        vulnerabilitiesFound: authResults.filter(r => r.vulnerable).length,
                        currentEndpoint: `${endpoint.method} ${endpoint.path}`
                    });
                }
                authzResults = await this.authzTester.testAuthorization(endpoint, config.userContexts, {
                    timeout: config.timeout,
                    includeDestructive: config.includeDestructiveTesting,
                    testIDOR: config.testTypes.includes('idor'),
                    testPathTraversal: true
                });
                testsCompleted += authzResults.length;
                if (progressCallback) {
                    progressCallback({
                        phase: 'authz_testing',
                        percentage: 80,
                        currentTest: 'Authorization Testing Complete',
                        testsCompleted,
                        totalTests,
                        vulnerabilitiesFound: authResults.filter(r => r.vulnerable).length +
                            authzResults.filter(r => r.vulnerable).length,
                        currentEndpoint: `${endpoint.method} ${endpoint.path}`
                    });
                }
            }
            // Phase 3: Analysis and Summary
            if (progressCallback) {
                progressCallback({
                    phase: 'analyzing',
                    percentage: 90,
                    currentTest: 'Analyzing Results',
                    testsCompleted,
                    totalTests,
                    vulnerabilitiesFound: authResults.filter(r => r.vulnerable).length +
                        authzResults.filter(r => r.vulnerable).length,
                    currentEndpoint: `${endpoint.method} ${endpoint.path}`
                });
            }
            const summary = this.generateSummary(authResults, authzResults);
            const recommendations = this.generateRecommendations(authResults, authzResults);
            const testDuration = Date.now() - startTime;
            if (progressCallback) {
                progressCallback({
                    phase: 'completed',
                    percentage: 100,
                    currentTest: 'Security Testing Complete',
                    testsCompleted,
                    totalTests,
                    vulnerabilitiesFound: summary.vulnerabilitiesFound,
                    currentEndpoint: `${endpoint.method} ${endpoint.path}`
                });
            }
            const result = {
                endpoint,
                authenticationResults: authResults,
                authorizationResults: authzResults,
                summary,
                recommendations,
                testDuration
            };
            this.logger.info('Security testing completed', {
                endpoint: endpoint.url,
                duration: testDuration,
                vulnerabilities: summary.vulnerabilitiesFound,
                riskScore: summary.overallRiskScore
            });
            return result;
        }
        catch (error) {
            this.logger.error('Security testing failed', {
                endpoint: endpoint.url,
                error: error.message,
                stack: error.stack
            });
            throw new Error(`Security testing failed: ${error.message}`);
        }
    }
    async testMultipleEndpoints(endpoints, config, progressCallback) {
        const results = [];
        this.logger.info('Starting bulk security testing', {
            endpointCount: endpoints.length,
            config
        });
        for (let i = 0; i < endpoints.length; i++) {
            const endpoint = endpoints[i];
            try {
                const result = await this.testEndpointSecurity(endpoint, config, (progress) => {
                    if (progressCallback) {
                        progressCallback({
                            ...progress,
                            endpointIndex: i,
                            totalEndpoints: endpoints.length,
                            overallProgress: ((i / endpoints.length) * 100) + (progress.percentage / endpoints.length)
                        });
                    }
                });
                results.push(result);
            }
            catch (error) {
                this.logger.error('Failed to test endpoint', {
                    endpoint: endpoint.url,
                    error: error.message
                });
                // Create a minimal result for failed tests
                results.push({
                    endpoint,
                    authenticationResults: [],
                    authorizationResults: [],
                    summary: {
                        totalTests: 0,
                        vulnerabilitiesFound: 0,
                        criticalVulns: 0,
                        highVulns: 0,
                        mediumVulns: 0,
                        lowVulns: 0,
                        overallRiskScore: 0
                    },
                    recommendations: ['Failed to complete security testing due to errors'],
                    testDuration: 0
                });
            }
        }
        this.logger.info('Bulk security testing completed', {
            endpointCount: endpoints.length,
            successfulTests: results.filter(r => r.summary.totalTests > 0).length,
            totalVulnerabilities: results.reduce((sum, r) => sum + r.summary.vulnerabilitiesFound, 0)
        });
        return results;
    }
    calculateTotalTests(config) {
        let total = 0;
        if (config.includeAuthentication) {
            total += 7; // Auth tests: no_auth, bypass, weak_auth, tokens, brute_force, info_disclosure
        }
        if (config.includeAuthorization) {
            total += 6; // Authz tests: missing_ac, horizontal, vertical, idor, role_bypass, path_traversal
        }
        return total;
    }
    generateSummary(authResults, authzResults) {
        const allResults = [...authResults, ...authzResults];
        const vulnerabilities = allResults.filter(r => r.vulnerable);
        const severityCounts = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0
        };
        vulnerabilities.forEach(vuln => {
            const severity = vuln.test.severity.toLowerCase();
            if (severity in severityCounts) {
                severityCounts[severity]++;
            }
        });
        // Calculate risk score (0-100)
        const riskScore = Math.min(100, (severityCounts.critical * 25) +
            (severityCounts.high * 15) +
            (severityCounts.medium * 10) +
            (severityCounts.low * 5));
        return {
            totalTests: allResults.length,
            vulnerabilitiesFound: vulnerabilities.length,
            criticalVulns: severityCounts.critical,
            highVulns: severityCounts.high,
            mediumVulns: severityCounts.medium,
            lowVulns: severityCounts.low,
            overallRiskScore: riskScore
        };
    }
    generateRecommendations(authResults, authzResults) {
        const recommendations = new Set();
        // Add authentication recommendations
        authResults.filter(r => r.vulnerable).forEach(result => {
            recommendations.add(result.recommendation);
        });
        // Add authorization recommendations
        authzResults.filter(r => r.vulnerable).forEach(result => {
            recommendations.add(result.recommendation);
        });
        // Add general security recommendations
        if (authResults.some(r => r.vulnerable && r.test.type === 'no_auth')) {
            recommendations.add('Implement comprehensive authentication across all endpoints');
        }
        if (authzResults.some(r => r.vulnerable && r.test.type === 'vertical_privilege')) {
            recommendations.add('Implement Role-Based Access Control (RBAC) with proper privilege separation');
        }
        if (authzResults.some(r => r.vulnerable && r.test.type === 'idor')) {
            recommendations.add('Implement indirect object references and ownership validation');
        }
        // Add OWASP API Top 10 compliance recommendations
        recommendations.add('Review against OWASP API Security Top 10');
        recommendations.add('Implement comprehensive logging and monitoring for security events');
        recommendations.add('Regular security testing and penetration testing');
        recommendations.add('Implement rate limiting and DDoS protection');
        return Array.from(recommendations);
    }
    generateSecurityReport(results) {
        const totalVulns = results.reduce((sum, r) => sum + r.summary.vulnerabilitiesFound, 0);
        const avgRiskScore = results.reduce((sum, r) => sum + r.summary.overallRiskScore, 0) / results.length;
        const riskDistribution = {
            critical: results.reduce((sum, r) => sum + r.summary.criticalVulns, 0),
            high: results.reduce((sum, r) => sum + r.summary.highVulns, 0),
            medium: results.reduce((sum, r) => sum + r.summary.mediumVulns, 0),
            low: results.reduce((sum, r) => sum + r.summary.lowVulns, 0)
        };
        const detailedFindings = results.map(result => ({
            endpoint: result.endpoint.path,
            method: result.endpoint.method,
            vulnerabilities: [
                ...result.authenticationResults.filter(r => r.vulnerable).map(r => ({
                    type: r.test.type,
                    severity: r.test.severity,
                    confidence: r.confidence,
                    description: r.test.description,
                    recommendation: r.recommendation
                })),
                ...result.authorizationResults.filter(r => r.vulnerable).map(r => ({
                    type: r.test.type,
                    severity: r.test.severity,
                    confidence: r.confidence,
                    description: r.test.description,
                    recommendation: r.recommendation
                }))
            ]
        }));
        const allRecommendations = Array.from(new Set(results.flatMap(r => r.recommendations)));
        // OWASP API Top 10 compliance check
        const owaspCompliance = this.assessOwaspCompliance(results);
        return {
            executive_summary: {
                total_endpoints_tested: results.length,
                total_vulnerabilities: totalVulns,
                risk_distribution: riskDistribution,
                overall_security_score: Math.max(0, 100 - avgRiskScore)
            },
            detailed_findings: detailedFindings,
            recommendations: allRecommendations,
            compliance_status: {
                owasp_api_top_10: owaspCompliance
            }
        };
    }
    assessOwaspCompliance(results) {
        const findings = results.flatMap(r => [
            ...r.authenticationResults.filter(ar => ar.vulnerable),
            ...r.authorizationResults.filter(ar => ar.vulnerable)
        ]);
        return [
            {
                requirement: 'API1:2023 - Broken Object Level Authorization',
                status: findings.some(f => f.test.type === 'idor' || f.test.type === 'horizontal_privilege') ? 'FAIL' : 'PASS',
                findings: findings.filter(f => f.test.type === 'idor' || f.test.type === 'horizontal_privilege')
                    .map(f => f.test.description)
            },
            {
                requirement: 'API2:2023 - Broken Authentication',
                status: findings.some(f => f.test.type === 'no_auth' || f.test.type === 'weak_auth' || f.test.type === 'bypass_auth') ? 'FAIL' : 'PASS',
                findings: findings.filter(f => ['no_auth', 'weak_auth', 'bypass_auth'].includes(f.test.type))
                    .map(f => f.test.description)
            },
            {
                requirement: 'API3:2023 - Broken Object Property Level Authorization',
                status: findings.some(f => f.test.type === 'missing_access_control') ? 'FAIL' : 'PASS',
                findings: findings.filter(f => f.test.type === 'missing_access_control')
                    .map(f => f.test.description)
            },
            {
                requirement: 'API5:2023 - Broken Function Level Authorization',
                status: findings.some(f => f.test.type === 'vertical_privilege' || f.test.type === 'role_bypass') ? 'FAIL' : 'PASS',
                findings: findings.filter(f => f.test.type === 'vertical_privilege' || f.test.type === 'role_bypass')
                    .map(f => f.test.description)
            },
            {
                requirement: 'API7:2023 - Server Side Request Forgery',
                status: 'WARNING',
                findings: ['SSRF testing not implemented in current framework']
            }
        ];
    }
}
exports.SecurityTester = SecurityTester;
//# sourceMappingURL=securityTester.js.map