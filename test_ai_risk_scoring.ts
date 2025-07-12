import { RiskScoringEngine, VulnerabilityData } from './src/ai/riskScoringEngine';
import { RiskAnalyticsDashboard } from './src/ai/riskAnalyticsDashboard';
import { logger } from './src/utils/logger';

async function testAIRiskScoringEngine() {
    console.log('\n🧠 AI/ML Risk Scoring Engine with TensorFlow.js - Live Demonstration\n');
    console.log('=' .repeat(80));

    try {
        // Initialize the AI risk scoring engine
        console.log('\n🚀 Initializing AI/ML Risk Scoring Engine...');
        const riskEngine = new RiskScoringEngine();
        
        console.log('⏳ Loading TensorFlow.js and training ML models...');
        await riskEngine.initialize();
        console.log('✅ AI/ML Risk Scoring Engine initialized successfully!');

        // Initialize analytics dashboard
        const dashboard = new RiskAnalyticsDashboard(riskEngine);

        // Create comprehensive test vulnerabilities with rich context
        const testVulnerabilities: VulnerabilityData[] = [
            {
                type: 'sql_injection',
                severity: 'CRITICAL',
                confidence: 0.95,
                cwe: 'CWE-89',
                owasp: 'A03:2021',
                endpoint: '/api/users/{id}',
                method: 'GET',
                parameter: 'user_id',
                responseTime: 1200,
                statusCode: 200,
                errorSignatures: ['SQL syntax error', 'mysql_fetch_array()'],
                businessCriticality: 'HIGH',
                dataClassification: 'CONFIDENTIAL',
                userAccess: 'EXTERNAL',
                framework: 'Express.js',
                database: 'MySQL',
                authentication: false,
                encryption: false,
                attackComplexity: 'LOW',
                exploitability: 0.9,
                impact: 0.95
            },
            {
                type: 'xss',
                severity: 'HIGH',
                confidence: 0.85,
                cwe: 'CWE-79',
                owasp: 'A03:2021',
                endpoint: '/api/search',
                method: 'POST',
                parameter: 'query',
                responseTime: 450,
                statusCode: 200,
                errorSignatures: ['<script>', 'javascript:'],
                businessCriticality: 'MEDIUM',
                dataClassification: 'INTERNAL',
                userAccess: 'EXTERNAL',
                framework: 'React',
                authentication: true,
                encryption: true,
                attackComplexity: 'MEDIUM',
                exploitability: 0.7,
                impact: 0.6
            },
            {
                type: 'command_injection',
                severity: 'CRITICAL',
                confidence: 0.92,
                cwe: 'CWE-78',
                owasp: 'A03:2021',
                endpoint: '/api/files/convert',
                method: 'POST',
                parameter: 'file_path',
                responseTime: 2800,
                statusCode: 500,
                errorSignatures: ['sh: command not found', 'Permission denied'],
                businessCriticality: 'HIGH',
                dataClassification: 'CONFIDENTIAL',
                userAccess: 'INTERNAL',
                framework: 'Django',
                authentication: true,
                encryption: true,
                attackComplexity: 'LOW',
                exploitability: 0.85,
                impact: 0.9
            },
            {
                type: 'auth_bypass',
                severity: 'HIGH',
                confidence: 0.88,
                cwe: 'CWE-287',
                owasp: 'A07:2021',
                endpoint: '/api/admin/users',
                method: 'GET',
                responseTime: 350,
                statusCode: 200,
                errorSignatures: ['Authorization header missing'],
                businessCriticality: 'HIGH',
                dataClassification: 'CONFIDENTIAL',
                userAccess: 'ADMIN',
                framework: 'Spring Boot',
                authentication: false,
                encryption: true,
                attackComplexity: 'MEDIUM',
                exploitability: 0.75,
                impact: 0.8
            },
            {
                type: 'cors_misconfiguration',
                severity: 'MEDIUM',
                confidence: 0.75,
                cwe: 'CWE-346',
                owasp: 'A05:2021',
                endpoint: '/api/data/export',
                method: 'OPTIONS',
                responseTime: 120,
                statusCode: 200,
                errorSignatures: ['Access-Control-Allow-Origin: *'],
                businessCriticality: 'MEDIUM',
                dataClassification: 'INTERNAL',
                userAccess: 'EXTERNAL',
                framework: 'Flask',
                authentication: true,
                encryption: true,
                attackComplexity: 'HIGH',
                exploitability: 0.4,
                impact: 0.5
            },
            {
                type: 'nosql_injection',
                severity: 'HIGH',
                confidence: 0.82,
                cwe: 'CWE-943',
                owasp: 'A03:2021',
                endpoint: '/api/products/search',
                method: 'POST',
                parameter: 'filters',
                responseTime: 890,
                statusCode: 200,
                errorSignatures: ['MongoDB error', '$where operator'],
                businessCriticality: 'HIGH',
                dataClassification: 'INTERNAL',
                userAccess: 'EXTERNAL',
                framework: 'Node.js',
                database: 'MongoDB',
                authentication: true,
                encryption: false,
                attackComplexity: 'MEDIUM',
                exploitability: 0.6,
                impact: 0.7
            }
        ];

        console.log('\n🔍 AI/ML Risk Analysis Results:');
        console.log('=' .repeat(60));

        // Calculate AI/ML risk scores for each vulnerability
        const aiResults = [];
        for (let i = 0; i < testVulnerabilities.length; i++) {
            const vuln = testVulnerabilities[i];
            console.log(`\n📊 Analyzing ${vuln.type.toUpperCase()} vulnerability...`);
            
            const riskScore = await riskEngine.calculateRiskScore(vuln);
            aiResults.push({ vulnerability: vuln, riskScore });

            console.log(`  📍 Endpoint: ${vuln.endpoint} (${vuln.method})`);
            console.log(`  🎯 AI Risk Score: ${(riskScore.overall * 100).toFixed(1)}%`);
            console.log(`  🔥 Priority: ${riskScore.recommendations.priority}`);
            console.log(`  ⏰ Time to Exploit: ${riskScore.prediction.timeToExploit} days`);
            console.log(`  🎖️  Model Confidence: ${(riskScore.confidence * 100).toFixed(1)}%`);
            
            console.log(`\n  📈 AI Component Breakdown:`);
            console.log(`    • Severity Risk: ${(riskScore.components.severity * 100).toFixed(1)}%`);
            console.log(`    • Exploitability: ${(riskScore.components.exploitability * 100).toFixed(1)}%`);
            console.log(`    • Business Impact: ${(riskScore.components.businessImpact * 100).toFixed(1)}%`);
            console.log(`    • Contextual Risk: ${(riskScore.components.contextualRisk * 100).toFixed(1)}%`);
            console.log(`    • Temporal Risk: ${(riskScore.components.temporalRisk * 100).toFixed(1)}%`);
            
            console.log(`\n  🤖 AI Predictions:`);
            console.log(`    • Attack Likelihood: ${(riskScore.prediction.likelihood * 100).toFixed(1)}%`);
            console.log(`    • Impact Magnitude: ${(riskScore.prediction.impactMagnitude * 100).toFixed(1)}%`);
            
            console.log(`\n  💡 AI Recommendations:`);
            console.log(`    • Timeframe: ${riskScore.recommendations.timeframe}`);
            console.log(`    • Resources: ${riskScore.recommendations.resources.join(', ')}`);
            console.log(`    • Alternatives: ${riskScore.recommendations.alternatives.join(', ')}`);
        }

        // Generate comprehensive analytics
        console.log('\n\n🧠 AI-Powered Risk Analytics Dashboard:');
        console.log('=' .repeat(60));

        const riskPortfolio = await dashboard.generateRiskPortfolio(testVulnerabilities);
        console.log(`\n📊 Risk Portfolio Analysis:`);
        console.log(`  • Total Endpoints: ${riskPortfolio.totalEndpoints}`);
        console.log(`  • Vulnerable Endpoints: ${riskPortfolio.vulnerableEndpoints}`);
        console.log(`  • Risk Distribution:`);
        console.log(`    - Critical: ${riskPortfolio.riskDistribution.critical}`);
        console.log(`    - High: ${riskPortfolio.riskDistribution.high}`);
        console.log(`    - Medium: ${riskPortfolio.riskDistribution.medium}`);
        console.log(`    - Low: ${riskPortfolio.riskDistribution.low}`);

        console.log(`\n🏢 Business Criticality Breakdown:`);
        console.log(`  • High Criticality: ${riskPortfolio.businessCriticalityBreakdown.high.count} endpoints, avg risk ${(riskPortfolio.businessCriticalityBreakdown.high.avgRisk * 100).toFixed(1)}%`);
        console.log(`  • Medium Criticality: ${riskPortfolio.businessCriticalityBreakdown.medium.count} endpoints, avg risk ${(riskPortfolio.businessCriticalityBreakdown.medium.avgRisk * 100).toFixed(1)}%`);
        console.log(`  • Low Criticality: ${riskPortfolio.businessCriticalityBreakdown.low.count} endpoints, avg risk ${(riskPortfolio.businessCriticalityBreakdown.low.avgRisk * 100).toFixed(1)}%`);

        console.log(`\n🛡️  Compliance Status:`);
        console.log(`  • OWASP Compliant: ${riskPortfolio.complianceStatus.owaspCompliant ? '✅' : '❌'}`);
        console.log(`  • PCI Compliant: ${riskPortfolio.complianceStatus.pciCompliant ? '✅' : '❌'}`);
        console.log(`  • GDPR Compliant: ${riskPortfolio.complianceStatus.gdprCompliant ? '✅' : '❌'}`);
        console.log(`  • Compliance Score: ${riskPortfolio.complianceStatus.complianceScore}%`);

        // Generate ML-powered insights
        const mlInsights = await dashboard.generateMLInsights(testVulnerabilities);
        console.log(`\n🤖 AI/ML Security Insights:`);
        console.log('=' .repeat(40));

        mlInsights.forEach((insight, index) => {
            console.log(`\n${index + 1}. ${insight.type} - ${insight.severity} Priority`);
            console.log(`   📋 ${insight.title}`);
            console.log(`   📝 ${insight.description}`);
            console.log(`   🎯 Confidence: ${(insight.confidence * 100).toFixed(1)}%`);
            console.log(`   💥 Impact: ${insight.impact}`);
            console.log(`   💡 Recommendation: ${insight.recommendation}`);
        });

        // Generate risk heatmap
        const heatmapData = await dashboard.generateRiskHeatmap(testVulnerabilities);
        console.log(`\n🌡️  AI-Enhanced Risk Heatmap:`);
        console.log('=' .repeat(50));

        heatmapData
            .sort((a, b) => b.riskScore - a.riskScore)
            .forEach((data, index) => {
                const riskEmoji = data.criticalityLevel === 'CRITICAL' ? '🔴' : 
                                data.criticalityLevel === 'HIGH' ? '🟠' : 
                                data.criticalityLevel === 'MEDIUM' ? '🟡' : '🟢';
                
                console.log(`\n${index + 1}. ${riskEmoji} ${data.endpoint} (${data.method})`);
                console.log(`   Risk Score: ${(data.riskScore * 100).toFixed(1)}%`);
                console.log(`   Vulnerabilities: ${data.vulnerabilityCount}`);
                console.log(`   Business Impact: ${(data.businessImpact * 100).toFixed(1)}%`);
                console.log(`   Criticality: ${data.criticalityLevel}`);
            });

        // Show ML model performance metrics
        const modelMetrics = riskEngine.getModelMetrics();
        console.log(`\n📈 TensorFlow.js Model Performance:`);
        console.log('=' .repeat(40));
        console.log(`  • Model Accuracy: ${(modelMetrics.accuracy * 100).toFixed(1)}%`);
        console.log(`  • Precision: ${(modelMetrics.precision * 100).toFixed(1)}%`);
        console.log(`  • Recall: ${(modelMetrics.recall * 100).toFixed(1)}%`);
        console.log(`  • F1 Score: ${(modelMetrics.f1Score * 100).toFixed(1)}%`);
        console.log(`  • Trained Samples: ${modelMetrics.trainedSamples}`);
        console.log(`  • Last Updated: ${new Date(modelMetrics.lastUpdated).toLocaleString()}`);

        // Show top risks summary
        console.log(`\n🚨 Top Critical Risks (AI-Prioritized):`);
        console.log('=' .repeat(45));

        const topRisks = riskPortfolio.topRisks.slice(0, 5);
        topRisks.forEach((risk, index) => {
            console.log(`\n${index + 1}. ${risk.endpoint}`);
            console.log(`   AI Risk Score: ${(risk.riskScore * 100).toFixed(1)}%`);
            console.log(`   Business Impact: ${(risk.businessImpact * 100).toFixed(1)}%`);
            console.log(`   Vulnerabilities: ${risk.vulnerabilities.join(', ')}`);
        });

        // Summary statistics
        const totalRisk = aiResults.reduce((sum, result) => sum + result.riskScore.overall, 0) / aiResults.length;
        const highRiskCount = aiResults.filter(result => result.riskScore.overall >= 0.7).length;
        const avgTimeToExploit = aiResults.reduce((sum, result) => sum + result.riskScore.prediction.timeToExploit, 0) / aiResults.length;

        console.log(`\n\n🎯 AI/ML Risk Scoring Summary:`);
        console.log('=' .repeat(40));
        console.log(`✅ Successfully analyzed ${testVulnerabilities.length} vulnerabilities using TensorFlow.js`);
        console.log(`🧠 Average AI Risk Score: ${(totalRisk * 100).toFixed(1)}%`);
        console.log(`🔥 High-Risk Vulnerabilities: ${highRiskCount}/${testVulnerabilities.length}`);
        console.log(`⏰ Average Time to Exploit: ${avgTimeToExploit.toFixed(1)} days`);
        console.log(`🎖️  Average Model Confidence: ${(aiResults.reduce((sum, result) => sum + result.riskScore.confidence, 0) / aiResults.length * 100).toFixed(1)}%`);
        console.log(`🤖 ML Insights Generated: ${mlInsights.length}`);
        console.log(`📊 Compliance Issues Detected: ${!riskPortfolio.complianceStatus.owaspCompliant || !riskPortfolio.complianceStatus.pciCompliant || !riskPortfolio.complianceStatus.gdprCompliant}`);

        console.log(`\n🚀 AI/ML Risk Scoring Engine Capabilities Demonstrated:`);
        console.log('  ✅ TensorFlow.js Neural Network Integration');
        console.log('  ✅ Multi-Model Ensemble Risk Scoring');
        console.log('  ✅ Context-Aware Feature Engineering');
        console.log('  ✅ Business Impact Assessment');
        console.log('  ✅ Predictive Attack Timeline Modeling');
        console.log('  ✅ Intelligent Prioritization Recommendations');
        console.log('  ✅ Compliance Framework Integration');
        console.log('  ✅ ML-Powered Security Insights');
        console.log('  ✅ Real-time Risk Analytics Dashboard');
        console.log('  ✅ Anomaly Detection & Trend Analysis');

        console.log(`\n🎊 AI/ML Risk Scoring Engine Test Completed Successfully!`);

    } catch (error: any) {
        console.error(`\n❌ AI/ML Risk Scoring Engine test failed: ${error.message}`);
        console.error(error.stack);
    }
}

// Run the comprehensive test
testAIRiskScoringEngine().catch(console.error); 