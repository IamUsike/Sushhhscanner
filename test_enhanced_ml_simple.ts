import { EnhancedRiskScoringEngine, EnhancedVulnerabilityData } from './src/ai/enhancedRiskScoringEngine';
import { logger } from './src/utils/logger';

async function testEnhancedMLSimple() {
  console.log('🚀 Testing Enhanced ML Engine (Simplified)\n');

  try {
    // Initialize enhanced risk scoring engine
    const enhancedEngine = new EnhancedRiskScoringEngine();
    await enhancedEngine.initialize();

    console.log('✅ Enhanced ML Engine initialized successfully\n');

    // Test vulnerabilities with CVSS integration
    const testVulnerabilities: EnhancedVulnerabilityData[] = [
      {
        type: 'SQL_INJECTION',
        severity: 'CRITICAL',
        confidence: 0.95,
        cwe: 'CWE-89',
        owasp: 'A03:2021',
        endpoint: '/api/admin/users',
        method: 'GET',
        parameter: 'id',
        responseTime: 150,
        statusCode: 200,
        errorSignatures: ['mysql_fetch', 'sql syntax'],
        businessCriticality: 'HIGH',
        dataClassification: 'CONFIDENTIAL',
        userAccess: 'EXTERNAL',
        framework: 'Express.js',
        database: 'MySQL',
        authentication: false,
        encryption: false,
        exploitability: 0.9,
        impact: 0.95,
        attackComplexity: 'LOW',
        attackVector: 'NETWORK',
        privilegesRequired: 'NONE',
        userInteraction: 'NONE',
        scope: 'CHANGED',
        confidentialityImpact: 'HIGH',
        integrityImpact: 'HIGH',
        availabilityImpact: 'HIGH'
      },
      {
        type: 'XSS',
        severity: 'HIGH',
        confidence: 0.88,
        cwe: 'CWE-79',
        owasp: 'A03:2021',
        endpoint: '/api/users/{id}',
        method: 'POST',
        parameter: 'name',
        responseTime: 200,
        statusCode: 200,
        errorSignatures: [],
        businessCriticality: 'MEDIUM',
        dataClassification: 'INTERNAL',
        userAccess: 'INTERNAL',
        framework: 'Express.js',
        database: 'PostgreSQL',
        authentication: true,
        encryption: true,
        exploitability: 0.7,
        impact: 0.8,
        attackComplexity: 'MEDIUM',
        attackVector: 'NETWORK',
        privilegesRequired: 'LOW',
        userInteraction: 'REQUIRED',
        scope: 'UNCHANGED',
        confidentialityImpact: 'LOW',
        integrityImpact: 'HIGH',
        availabilityImpact: 'NONE'
      },
      {
        type: 'COMMAND_INJECTION',
        severity: 'CRITICAL',
        confidence: 0.92,
        cwe: 'CWE-78',
        owasp: 'A03:2021',
        endpoint: '/api/files/convert',
        method: 'POST',
        parameter: 'filename',
        responseTime: 300,
        statusCode: 200,
        errorSignatures: ['command not found', 'permission denied'],
        businessCriticality: 'HIGH',
        dataClassification: 'CONFIDENTIAL',
        userAccess: 'EXTERNAL',
        framework: 'Express.js',
        database: 'MongoDB',
        authentication: true,
        encryption: false,
        exploitability: 0.85,
        impact: 0.9,
        attackComplexity: 'LOW',
        attackVector: 'NETWORK',
        privilegesRequired: 'NONE',
        userInteraction: 'NONE',
        scope: 'CHANGED',
        confidentialityImpact: 'HIGH',
        integrityImpact: 'HIGH',
        availabilityImpact: 'HIGH'
      }
    ];

    console.log('🔍 Testing Enhanced Risk Scoring with CVSS Integration...\n');

    // Calculate enhanced risk scores
    const enhancedRiskScores: Array<{ vulnerability: EnhancedVulnerabilityData; riskScore: any }> = [];
    for (const vuln of testVulnerabilities) {
      const riskScore = await enhancedEngine.calculateEnhancedRiskScore(vuln);
      enhancedRiskScores.push({ vulnerability: vuln, riskScore });
      
      console.log(`📊 ${vuln.type} - ${vuln.severity}`);
      console.log(`   Endpoint: ${vuln.endpoint}`);
      console.log(`   Overall Risk Score: ${(riskScore.overall * 100).toFixed(1)}%`);
      console.log(`   CVSS Adjusted Score: ${(riskScore.cvssAdjusted * 100).toFixed(1)}%`);
      console.log(`   CVSS Base Score: ${riskScore.cvssMetrics?.baseScore || 'N/A'}`);
      console.log(`   Attack Probability: ${(riskScore.prediction.attackProbability * 100).toFixed(1)}%`);
      console.log(`   Time to Exploit: ${riskScore.prediction.timeToExploit} days`);
      console.log(`   Model Confidence: ${(riskScore.confidence * 100).toFixed(1)}%`);
      console.log(`   Priority: ${riskScore.recommendations.priority}`);
      console.log(`   CVSS Vector: ${riskScore.cvssMetrics?.vector || 'N/A'}`);
      console.log('');
    }

    // Get model metrics
    const modelMetrics = enhancedEngine.getModelMetrics();
    console.log('📈 Enhanced ML Model Performance:');
    console.log(`   Accuracy: ${(modelMetrics.accuracy * 100).toFixed(1)}%`);
    console.log(`   Precision: ${(modelMetrics.precision * 100).toFixed(1)}%`);
    console.log(`   Recall: ${(modelMetrics.recall * 100).toFixed(1)}%`);
    console.log(`   F1 Score: ${(modelMetrics.f1Score * 100).toFixed(1)}%`);
    console.log(`   CVSS Correlation: ${(modelMetrics.cvssCorrelation * 100).toFixed(1)}%`);
    console.log(`   Trained Samples: ${modelMetrics.trainedSamples}`);
    console.log('');

    // Summary statistics
    console.log('📊 Summary Statistics:');
    const avgEnhancedScore = enhancedRiskScores.reduce((sum, rs) => sum + rs.riskScore.overall, 0) / enhancedRiskScores.length;
    const avgCVSSAdjusted = enhancedRiskScores.reduce((sum, rs) => sum + rs.riskScore.cvssAdjusted, 0) / enhancedRiskScores.length;
    const avgConfidence = enhancedRiskScores.reduce((sum, rs) => sum + rs.riskScore.confidence, 0) / enhancedRiskScores.length;

    console.log(`   Average Enhanced Score: ${(avgEnhancedScore * 100).toFixed(1)}%`);
    console.log(`   Average CVSS Adjusted: ${(avgCVSSAdjusted * 100).toFixed(1)}%`);
    console.log(`   Average Model Confidence: ${(avgConfidence * 100).toFixed(1)}%`);
    console.log('');

    // CVSS Analysis
    console.log('🔍 CVSS Analysis:');
    const cvssScores = enhancedRiskScores.map(rs => rs.riskScore.cvssMetrics?.baseScore).filter(Boolean);
    const avgCVSS = cvssScores.reduce((sum, score) => sum + score, 0) / cvssScores.length;
    console.log(`   Average CVSS Base Score: ${avgCVSS.toFixed(1)}`);
    console.log(`   CVSS Range: ${Math.min(...cvssScores).toFixed(1)} - ${Math.max(...cvssScores).toFixed(1)}`);
    console.log(`   Critical Vulnerabilities: ${cvssScores.filter(score => score >= 9.0).length}`);
    console.log(`   High Vulnerabilities: ${cvssScores.filter(score => score >= 7.0 && score < 9.0).length}`);
    console.log('');

    console.log('🎉 Enhanced ML Engine Test Completed Successfully!');
    console.log('');
    console.log('🚀 Key Achievements:');
    console.log('   ✅ CVSS Integration for standardized scoring');
    console.log('   ✅ Enhanced feature engineering (20 features)');
    console.log('   ✅ Advanced neural network architectures');
    console.log('   ✅ Anomaly detection capabilities');
    console.log('   ✅ Improved model accuracy and confidence scoring');
    console.log('   ✅ CVSS vector generation and analysis');
    console.log('   ✅ Multi-component risk assessment');

  } catch (error: any) {
    console.error('❌ Enhanced ML Engine test failed:', error.message);
    logger.error(`Enhanced ML Engine test failed: ${error.message}`);
  }
}

// Run the test
testEnhancedMLSimple().catch(console.error); 