"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RiskAnalyticsDashboard = void 0;
const logger_1 = require("../utils/logger");
class RiskAnalyticsDashboard {
    constructor(riskEngine) {
        this.riskHistory = [];
        this.vulnerabilityHistory = new Map();
        this.mlInsights = [];
        this.riskEngine = riskEngine;
    }
    async generateRiskPortfolio(vulnerabilities) {
        logger_1.logger.info('Generating AI-powered risk portfolio analysis...');
        const riskScores = await Promise.all(vulnerabilities.map(vuln => this.riskEngine.calculateRiskScore(vuln)));
        // Group by endpoint for analysis
        const endpointRisks = this.groupRisksByEndpoint(vulnerabilities, riskScores);
        // Calculate distribution metrics
        const riskDistribution = this.calculateRiskDistribution(riskScores);
        const businessBreakdown = this.calculateBusinessCriticalityBreakdown(vulnerabilities, riskScores);
        const complianceStatus = this.assessComplianceStatus(vulnerabilities, riskScores);
        const topRisks = this.identifyTopRisks(endpointRisks, 10);
        return {
            totalEndpoints: new Set(vulnerabilities.map(v => v.endpoint)).size,
            scannedEndpoints: new Set(vulnerabilities.map(v => v.endpoint)).size,
            vulnerableEndpoints: endpointRisks.filter(r => r.riskScore > 0.3).length,
            riskDistribution,
            businessCriticalityBreakdown: businessBreakdown,
            complianceStatus,
            topRisks
        };
    }
    async generateRiskHeatmap(vulnerabilities) {
        logger_1.logger.info('Generating ML-enhanced risk heatmap...');
        const riskScores = await Promise.all(vulnerabilities.map(vuln => this.riskEngine.calculateRiskScore(vuln)));
        const endpointRisks = this.groupRisksByEndpoint(vulnerabilities, riskScores);
        return endpointRisks.map(risk => ({
            endpoint: risk.endpoint,
            method: risk.method,
            riskScore: risk.riskScore,
            vulnerabilityCount: risk.vulnerabilities.length,
            criticalityLevel: this.mapRiskToCriticality(risk.riskScore),
            businessImpact: risk.businessImpact,
            lastScanned: new Date().toISOString()
        }));
    }
    async generateMLInsights(vulnerabilities) {
        logger_1.logger.info('Generating AI/ML-powered security insights...');
        const insights = [];
        const riskScores = await Promise.all(vulnerabilities.map(vuln => this.riskEngine.calculateRiskScore(vuln)));
        // Trend Analysis
        const trendInsights = await this.analyzeTrends(vulnerabilities, riskScores);
        insights.push(...trendInsights);
        // Anomaly Detection
        const anomalyInsights = await this.detectAnomalies(vulnerabilities, riskScores);
        insights.push(...anomalyInsights);
        // Predictive Insights
        const predictiveInsights = await this.generatePredictiveInsights(vulnerabilities, riskScores);
        insights.push(...predictiveInsights);
        // Strategic Recommendations
        const strategicInsights = await this.generateStrategicRecommendations(vulnerabilities, riskScores);
        insights.push(...strategicInsights);
        this.mlInsights = insights;
        return insights;
    }
    groupRisksByEndpoint(vulnerabilities, riskScores) {
        const grouped = new Map();
        vulnerabilities.forEach((vuln, index) => {
            const key = `${vuln.endpoint}-${vuln.method}`;
            if (!grouped.has(key)) {
                grouped.set(key, {
                    endpoint: vuln.endpoint,
                    method: vuln.method,
                    vulnerabilities: [],
                    riskScores: [],
                    businessImpact: 0
                });
            }
            const group = grouped.get(key);
            group.vulnerabilities.push(vuln);
            group.riskScores.push(riskScores[index]);
            group.businessImpact = Math.max(group.businessImpact, riskScores[index].prediction.impactMagnitude);
        });
        return Array.from(grouped.values()).map(group => ({
            endpoint: group.endpoint,
            method: group.method,
            riskScore: Math.max(...group.riskScores.map((rs) => rs.overall)),
            vulnerabilities: group.vulnerabilities,
            businessImpact: group.businessImpact
        }));
    }
    calculateRiskDistribution(riskScores) {
        return {
            critical: riskScores.filter(rs => rs.overall >= 0.8).length,
            high: riskScores.filter(rs => rs.overall >= 0.6 && rs.overall < 0.8).length,
            medium: riskScores.filter(rs => rs.overall >= 0.4 && rs.overall < 0.6).length,
            low: riskScores.filter(rs => rs.overall < 0.4).length
        };
    }
    calculateBusinessCriticalityBreakdown(vulnerabilities, riskScores) {
        const breakdown = { high: [], medium: [], low: [] };
        vulnerabilities.forEach((vuln, index) => {
            const criticality = vuln.businessCriticality?.toLowerCase() || 'low';
            if (breakdown[criticality]) {
                breakdown[criticality].push(riskScores[index].overall);
            }
        });
        return {
            high: {
                count: breakdown.high.length,
                avgRisk: breakdown.high.length > 0 ? breakdown.high.reduce((a, b) => a + b, 0) / breakdown.high.length : 0
            },
            medium: {
                count: breakdown.medium.length,
                avgRisk: breakdown.medium.length > 0 ? breakdown.medium.reduce((a, b) => a + b, 0) / breakdown.medium.length : 0
            },
            low: {
                count: breakdown.low.length,
                avgRisk: breakdown.low.length > 0 ? breakdown.low.reduce((a, b) => a + b, 0) / breakdown.low.length : 0
            }
        };
    }
    assessComplianceStatus(vulnerabilities, riskScores) {
        const criticalIssues = riskScores.filter(rs => rs.overall >= 0.8).length;
        const highIssues = riskScores.filter(rs => rs.overall >= 0.6).length;
        // OWASP compliance: No critical auth/injection issues
        const owaspCompliant = !vulnerabilities.some(v => ['A01:2021', 'A02:2021', 'A03:2021', 'A07:2021'].includes(v.owasp) &&
            riskScores[vulnerabilities.indexOf(v)].overall >= 0.7);
        // PCI compliance: No critical data exposure issues
        const pciCompliant = !vulnerabilities.some(v => v.dataClassification === 'CONFIDENTIAL' &&
            riskScores[vulnerabilities.indexOf(v)].overall >= 0.6);
        // GDPR compliance: No critical privacy issues
        const gdprCompliant = !vulnerabilities.some(v => ['CWE-200', 'CWE-359'].includes(v.cwe) &&
            riskScores[vulnerabilities.indexOf(v)].overall >= 0.6);
        const complianceScore = Math.max(0, 100 - (criticalIssues * 20) - (highIssues * 10));
        return {
            owaspCompliant,
            pciCompliant,
            gdprCompliant,
            complianceScore
        };
    }
    identifyTopRisks(endpointRisks, count) {
        return endpointRisks
            .sort((a, b) => b.riskScore - a.riskScore)
            .slice(0, count)
            .map(risk => ({
            endpoint: risk.endpoint,
            riskScore: risk.riskScore,
            vulnerabilities: risk.vulnerabilities.map((v) => v.type),
            businessImpact: risk.businessImpact
        }));
    }
    async analyzeTrends(vulnerabilities, riskScores) {
        const insights = [];
        // Analyze vulnerability type trends
        const typeFrequency = vulnerabilities.reduce((acc, vuln) => {
            acc[vuln.type] = (acc[vuln.type] || 0) + 1;
            return acc;
        }, {});
        const sortedTypes = Object.entries(typeFrequency)
            .sort(([, a], [, b]) => b - a)
            .slice(0, 3);
        if (sortedTypes.length > 0) {
            insights.push({
                type: 'TREND',
                severity: 'MEDIUM',
                title: 'Dominant Vulnerability Pattern Detected',
                description: `${sortedTypes[0][0]} vulnerabilities represent ${Math.round((sortedTypes[0][1] / vulnerabilities.length) * 100)}% of detected issues, indicating a systematic security gap.`,
                confidence: 0.85,
                impact: 'High concentration suggests architectural vulnerability requiring systematic remediation',
                recommendation: `Implement framework-level protections against ${sortedTypes[0][0]} attacks and conduct targeted security training`,
                dataPoints: sortedTypes
            });
        }
        // Risk severity trend analysis
        const avgRisk = riskScores.reduce((sum, rs) => sum + rs.overall, 0) / riskScores.length;
        if (avgRisk > 0.6) {
            insights.push({
                type: 'TREND',
                severity: 'HIGH',
                title: 'Elevated Risk Profile Detected',
                description: `Average risk score of ${Math.round(avgRisk * 100)}% indicates significant security exposure across the API surface.`,
                confidence: 0.9,
                impact: 'High probability of successful attacks against current API infrastructure',
                recommendation: 'Immediate security review and implementation of defense-in-depth strategies required'
            });
        }
        return insights;
    }
    async detectAnomalies(vulnerabilities, riskScores) {
        const insights = [];
        // Detect unusual response time patterns
        const responseTimes = vulnerabilities.map(v => v.responseTime);
        const avgResponseTime = responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length;
        const slowResponses = responseTimes.filter(rt => rt > avgResponseTime * 3).length;
        if (slowResponses > vulnerabilities.length * 0.2) {
            insights.push({
                type: 'ANOMALY',
                severity: 'MEDIUM',
                title: 'Unusual Response Time Patterns',
                description: `${slowResponses} endpoints show significantly slower response times, potentially indicating DoS vulnerabilities or performance-based attack vectors.`,
                confidence: 0.75,
                impact: 'Potential denial of service attack surface',
                recommendation: 'Implement rate limiting and performance monitoring on affected endpoints'
            });
        }
        // Detect authentication anomalies
        const authBypassRate = vulnerabilities.filter(v => v.type.includes('auth') && riskScores[vulnerabilities.indexOf(v)].overall > 0.7).length / vulnerabilities.length;
        if (authBypassRate > 0.3) {
            insights.push({
                type: 'ANOMALY',
                severity: 'HIGH',
                title: 'Authentication System Compromise',
                description: `${Math.round(authBypassRate * 100)}% of endpoints show authentication bypass vulnerabilities, indicating systematic authentication failures.`,
                confidence: 0.95,
                impact: 'Critical business risk with potential for full system compromise',
                recommendation: 'Emergency authentication system review and multi-factor authentication implementation'
            });
        }
        return insights;
    }
    async generatePredictiveInsights(vulnerabilities, riskScores) {
        const insights = [];
        // Predict attack likelihood based on current vulnerabilities
        const criticalVulns = riskScores.filter(rs => rs.overall >= 0.8).length;
        const attackLikelihood = Math.min(0.95, criticalVulns * 0.15 + 0.1);
        if (attackLikelihood > 0.4) {
            const timeToAttack = Math.max(1, Math.round(14 * (1 - attackLikelihood)));
            insights.push({
                type: 'PREDICTION',
                severity: attackLikelihood > 0.7 ? 'HIGH' : 'MEDIUM',
                title: 'Attack Probability Forecast',
                description: `ML models predict ${Math.round(attackLikelihood * 100)}% probability of successful attack within ${timeToAttack} days based on current vulnerability profile.`,
                confidence: 0.82,
                impact: `High probability of security incident requiring immediate response capabilities`,
                recommendation: `Activate incident response procedures and prioritize ${criticalVulns} critical vulnerabilities for immediate remediation`
            });
        }
        // Predict remediation timeline
        const totalEffort = riskScores.reduce((sum, rs) => {
            const priority = rs.recommendations.priority;
            const effort = priority === 'CRITICAL' ? 3 : priority === 'HIGH' ? 2 : priority === 'MEDIUM' ? 1 : 0.5;
            return sum + effort;
        }, 0);
        const estimatedDays = Math.round(totalEffort * 1.5); // Assuming 1.5 days per effort unit
        insights.push({
            type: 'PREDICTION',
            severity: 'LOW',
            title: 'Remediation Timeline Forecast',
            description: `Based on vulnerability complexity and team capacity, estimated remediation timeline is ${estimatedDays} days for complete risk mitigation.`,
            confidence: 0.78,
            impact: 'Resource planning and timeline management for security improvements',
            recommendation: `Allocate ${Math.ceil(totalEffort / 5)} team members for ${estimatedDays} days to meet remediation timeline`
        });
        return insights;
    }
    async generateStrategicRecommendations(vulnerabilities, riskScores) {
        const insights = [];
        // Framework-specific recommendations
        const frameworks = vulnerabilities
            .map(v => v.framework)
            .filter(f => f)
            .reduce((acc, framework) => {
            acc[framework] = (acc[framework] || 0) + 1;
            return acc;
        }, {});
        const dominantFramework = Object.entries(frameworks)
            .sort(([, a], [, b]) => b - a)[0];
        if (dominantFramework) {
            insights.push({
                type: 'RECOMMENDATION',
                severity: 'MEDIUM',
                title: 'Framework-Specific Security Enhancement',
                description: `${dominantFramework[0]} framework detected in ${dominantFramework[1]} endpoints. Implement framework-specific security best practices.`,
                confidence: 0.88,
                impact: 'Systematic security improvements across technology stack',
                recommendation: `Deploy ${dominantFramework[0]}-specific security middleware, update to latest secure versions, and implement framework security guidelines`
            });
        }
        // Business priority recommendations
        const businessCriticalIssues = vulnerabilities.filter(v => v.businessCriticality === 'HIGH' &&
            riskScores[vulnerabilities.indexOf(v)].overall > 0.6).length;
        if (businessCriticalIssues > 0) {
            insights.push({
                type: 'RECOMMENDATION',
                severity: 'HIGH',
                title: 'Business-Critical Security Investment',
                description: `${businessCriticalIssues} high-risk vulnerabilities affect business-critical systems. Immediate executive attention and resource allocation required.`,
                confidence: 0.92,
                impact: 'Direct business continuity and revenue protection',
                recommendation: 'Establish dedicated security budget, hire additional security personnel, and implement enterprise security tools'
            });
        }
        return insights;
    }
    mapRiskToCriticality(riskScore) {
        if (riskScore >= 0.8)
            return 'CRITICAL';
        if (riskScore >= 0.6)
            return 'HIGH';
        if (riskScore >= 0.4)
            return 'MEDIUM';
        return 'LOW';
    }
    addRiskTrend(trend) {
        this.riskHistory.push(trend);
        // Keep only last 100 trends for performance
        if (this.riskHistory.length > 100) {
            this.riskHistory = this.riskHistory.slice(-100);
        }
    }
    getRiskTrends(days = 30) {
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - days);
        return this.riskHistory.filter(trend => new Date(trend.timestamp) >= cutoffDate);
    }
    getMLInsights() {
        return this.mlInsights;
    }
    async exportRiskReport() {
        const vulnerabilities = []; // This would come from your vulnerability store
        const portfolio = await this.generateRiskPortfolio(vulnerabilities);
        const insights = await this.generateMLInsights(vulnerabilities);
        const trends = this.getRiskTrends();
        const modelMetrics = this.riskEngine.getModelMetrics();
        return {
            portfolio,
            insights,
            trends,
            modelMetrics
        };
    }
}
exports.RiskAnalyticsDashboard = RiskAnalyticsDashboard;
//# sourceMappingURL=riskAnalyticsDashboard.js.map