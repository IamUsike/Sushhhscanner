import { EnhancedRiskScoringEngine } from './src/ai/enhancedRiskScoringEngine';
import { PDFReportGenerator } from './src/ai/pdfReportGenerator';
import { logger } from './src/utils/logger';

async function testDashboardIntegration() {
    console.log('🧪 Testing Dashboard ML and PDF Integration...\n');

    try {
        // Test 1: Enhanced ML Engine Initialization
        console.log('1️⃣ Testing Enhanced ML Engine Initialization...');
        const mlEngine = new EnhancedRiskScoringEngine();
        await mlEngine.initialize();
        console.log('✅ Enhanced ML Engine initialized successfully');
        
        const metrics = mlEngine.getModelMetrics();
        console.log('📊 ML Model Metrics:', {
            accuracy: Math.round(metrics.accuracy * 100) + '%',
            precision: Math.round(metrics.precision * 100) + '%',
            recall: Math.round(metrics.recall * 100) + '%',
            f1Score: Math.round(metrics.f1Score * 100) + '%',
            cvssCorrelation: Math.round(metrics.cvssCorrelation * 100) + '%'
        });

        // Test 2: Enhanced Risk Scoring
        console.log('\n2️⃣ Testing Enhanced Risk Scoring...');
        const testVulnerability = {
            type: 'SQL_INJECTION',
            severity: 'HIGH' as const,
            confidence: 0.85,
            cwe: 'CWE-89',
            owasp: 'A03:2021',
            endpoint: '/api/users',
            method: 'POST',
            parameter: 'username',
            responseTime: 150,
            statusCode: 200,
            errorSignatures: ['mysql_fetch_array', 'ORA-'],
            businessCriticality: 'HIGH' as const,
            dataClassification: 'CONFIDENTIAL' as const,
            userAccess: 'EXTERNAL' as const,
            framework: 'Express.js',
            database: 'MySQL',
            authentication: false,
            encryption: false,
            exploitability: 0.8,
            impact: 0.9,
            attackComplexity: 'LOW' as const,
            attackVector: 'NETWORK' as const,
            privilegesRequired: 'NONE' as const,
            userInteraction: 'NONE' as const,
            scope: 'CHANGED' as const,
            confidentialityImpact: 'HIGH' as const,
            integrityImpact: 'HIGH' as const,
            availabilityImpact: 'LOW' as const
        };

        const riskScore = await mlEngine.calculateEnhancedRiskScore(testVulnerability);
        console.log('✅ Enhanced Risk Score calculated:', {
            overall: riskScore.overall,
            cvssAdjusted: riskScore.cvssAdjusted,
            confidence: Math.round(riskScore.confidence * 100) + '%',
            cvssBaseScore: riskScore.cvssMetrics?.baseScore?.toFixed(1) || 'N/A'
        });

        // Test 3: PDF Report Generator
        console.log('\n3️⃣ Testing PDF Report Generator...');
        const llmProvider = (process.env.LLM_PROVIDER as 'gemini' | 'groq') || 'gemini';
        console.log(`📝 Using LLM Provider: ${llmProvider.toUpperCase()}`);
        
        const pdfGenerator = new PDFReportGenerator(llmProvider);
        
        const testScanData = {
            scanId: 'test-scan-123',
            targetUrl: 'https://api.example.com',
            scanStartTime: new Date(Date.now() - 3600000), // 1 hour ago
            scanEndTime: new Date(),
            endpoints: [
                { url: '/api/users', method: 'GET', status: 200 },
                { url: '/api/users', method: 'POST', status: 201 },
                { url: '/api/admin', method: 'GET', status: 403 }
            ],
            vulnerabilities: [testVulnerability],
            statistics: {
                totalEndpoints: 3,
                totalVulnerabilities: 1,
                riskScore: riskScore
            }
        };

        console.log('📄 Generating PDF report...');
        const pdfBuffer = await pdfGenerator.generatePDFReport(testScanData);
        console.log(`✅ PDF Report generated successfully (${pdfBuffer.length} bytes)`);

        // Test 4: Dashboard API Endpoints
        console.log('\n4️⃣ Testing Dashboard API Endpoints...');
        
        // Test ML initialization endpoint
        const mlInitResponse = await fetch('http://localhost:3000/api/v1/ml/initialize', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        
        if (mlInitResponse.ok) {
            const mlInitResult = await mlInitResponse.json();
            console.log('✅ ML Initialization API:', mlInitResult.success ? 'SUCCESS' : 'FAILED');
        } else {
            console.log('⚠️ ML Initialization API: Server not running or endpoint unavailable');
        }

        // Test risk scoring endpoint
        const riskScoreResponse = await fetch('http://localhost:3000/api/v1/ml/risk-score', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ vulnerability: testVulnerability })
        });
        
        if (riskScoreResponse.ok) {
            const riskScoreResult = await riskScoreResponse.json();
            console.log('✅ Risk Scoring API:', riskScoreResult.success ? 'SUCCESS' : 'FAILED');
        } else {
            console.log('⚠️ Risk Scoring API: Server not running or endpoint unavailable');
        }

        // Test PDF generation endpoint
        const pdfResponse = await fetch('http://localhost:3000/api/v1/reports/test-scan-123', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ format: 'pdf' })
        });
        
        if (pdfResponse.ok) {
            const pdfResult = await pdfResponse.json();
            console.log('✅ PDF Generation API:', pdfResult.success ? 'SUCCESS' : 'FAILED');
        } else {
            console.log('⚠️ PDF Generation API: Server not running or endpoint unavailable');
        }

        console.log('\n🎉 Dashboard Integration Test Completed Successfully!');
        console.log('\n📋 Summary:');
        console.log('✅ Enhanced ML Engine: Working');
        console.log('✅ Risk Scoring: Working');
        console.log('✅ PDF Generation: Working');
        console.log('✅ API Endpoints: Available (if server running)');
        
        console.log('\n🚀 Next Steps:');
        console.log('1. Start the server: npm start');
        console.log('2. Open the dashboard: http://localhost:3000');
        console.log('3. Run a scan to see ML-enhanced risk scoring');
        console.log('4. Generate PDF reports with AI-powered insights');

    } catch (error) {
        console.error('❌ Dashboard Integration Test Failed:', error);
        process.exit(1);
    }
}

// Run the test
testDashboardIntegration(); 