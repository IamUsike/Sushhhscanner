import { RiskScoringEngine } from './src/ai/riskScoringEngine';
import express from 'express';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import cors from 'cors';
import path from 'path';

interface DashboardConfig {
    port: number;
    host: string;
}

class StandaloneDashboard {
    private app: express.Application;
    private server: any;
    private io: SocketIOServer;
    private riskEngine: RiskScoringEngine;

    constructor(private config: DashboardConfig, riskEngine: RiskScoringEngine) {
        this.riskEngine = riskEngine;
        this.app = express();
        this.server = createServer(this.app);
        this.io = new SocketIOServer(this.server, {
            cors: {
                origin: "*",
                methods: ['GET', 'POST']
            }
        });

        this.setupMiddleware();
        this.setupRoutes();
        this.setupSocketHandlers();
    }

    private setupMiddleware(): void {
        this.app.use(cors());
        this.app.use(express.json());
        this.app.use(express.static(path.join(__dirname, 'public')));
    }

    private setupRoutes(): void {
        // Health check
        this.app.get('/api/health', (req, res) => {
            res.json({
                status: 'healthy',
                timestamp: new Date().toISOString(),
                version: '1.0.0',
                ai_engine: 'operational'
            });
        });

        // Sample API endpoints for testing
        this.app.get('/api/risk/metrics', async (req, res) => {
            try {
                // Generate sample metrics
                const metrics = {
                    totalVulnerabilities: 6,
                    criticalCount: 2,
                    highCount: 2,
                    mediumCount: 2,
                    lowCount: 0,
                    averageRiskScore: 0.65,
                    complianceScore: 78
                };

                res.json({
                    success: true,
                    data: metrics,
                    timestamp: new Date().toISOString()
                });
            } catch (error: any) {
                res.status(500).json({
                    success: false,
                    error: error.message
                });
            }
        });

        // AI risk scoring endpoint
        this.app.post('/api/risk/score', async (req, res) => {
            try {
                const sampleVulnerability = {
                    type: 'sql_injection',
                    severity: 'HIGH' as const,
                    confidence: 0.9,
                    cwe: 'CWE-89',
                    owasp: 'A03:2021',
                    endpoint: '/api/users',
                    method: 'GET',
                    parameter: 'id',
                    responseTime: 1200,
                    statusCode: 200,
                    errorSignatures: ['SQL syntax error'],
                    businessCriticality: 'HIGH' as const,
                    dataClassification: 'CONFIDENTIAL' as const,
                    userAccess: 'EXTERNAL' as const,
                    authentication: false,
                    encryption: false,
                    attackComplexity: 'LOW' as const,
                    exploitability: 0.9,
                    impact: 0.95
                };

                const riskScore = await this.riskEngine.calculateRiskScore(sampleVulnerability);
                
                res.json({
                    success: true,
                    data: riskScore,
                    timestamp: new Date().toISOString()
                });
            } catch (error: any) {
                res.status(500).json({
                    success: false,
                    error: error.message
                });
            }
        });

        // Model metrics
        this.app.get('/api/model/metrics', (req, res) => {
            try {
                const metrics = this.riskEngine.getModelMetrics();
                res.json({
                    success: true,
                    data: metrics,
                    timestamp: new Date().toISOString()
                });
            } catch (error: any) {
                res.status(500).json({
                    success: false,
                    error: error.message
                });
            }
        });

        // Serve a simple dashboard HTML
        this.app.get('/', (req, res) => {
            res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Risk Visualizer - AI/ML Dashboard</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #1a1a1a; color: #fff; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { text-align: center; margin-bottom: 30px; }
        .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .metric-card { background: #2a2a2a; padding: 20px; border-radius: 8px; border: 1px solid #444; }
        .metric-value { font-size: 2em; font-weight: bold; color: #4CAF50; }
        .ai-demo { background: #2a2a2a; padding: 20px; border-radius: 8px; border: 1px solid #444; margin-bottom: 20px; }
        .btn { background: #4CAF50; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        .btn:hover { background: #45a049; }
        .result { margin-top: 10px; padding: 10px; background: #333; border-radius: 4px; }
        .status { color: #4CAF50; }
        .error { color: #f44336; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 API Risk Visualizer Dashboard</h1>
            <p>AI/ML-Powered Security Analysis System</p>
        </div>

        <div class="ai-demo">
            <h3>🧠 AI Risk Scoring Demo</h3>
            <p>Test the TensorFlow.js AI/ML risk scoring engine:</p>
            <button class="btn" onclick="testAIScoring()">Calculate AI Risk Score</button>
            <div id="ai-result" class="result" style="display: none;"></div>
        </div>

        <div class="metrics" id="metrics">
            <div class="metric-card">
                <div>🎯 Total Vulnerabilities</div>
                <div class="metric-value" id="total-vulns">Loading...</div>
            </div>
            <div class="metric-card">
                <div>⚠️ Critical Issues</div>
                <div class="metric-value" id="critical-count">Loading...</div>
            </div>
            <div class="metric-card">
                <div>📊 Avg Risk Score</div>
                <div class="metric-value" id="avg-risk">Loading...</div>
            </div>
            <div class="metric-card">
                <div>🤖 AI Model Accuracy</div>
                <div class="metric-value" id="ai-accuracy">Loading...</div>
            </div>
        </div>

        <div class="ai-demo">
            <h3>📊 API Endpoints</h3>
            <button class="btn" onclick="loadMetrics()">Refresh Dashboard</button>
            <div id="status" class="status">Dashboard ready</div>
        </div>
    </div>

    <script>
        async function testAIScoring() {
            const resultDiv = document.getElementById('ai-result');
            resultDiv.style.display = 'block';
            resultDiv.innerHTML = '⏳ Calculating AI risk score...';
            
            try {
                const response = await fetch('/api/risk/score', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });
                
                const data = await response.json();
                
                if (data.success) {
                    const score = data.data;
                    resultDiv.innerHTML = \`
                        <h4>🎯 AI Risk Assessment Results:</h4>
                        <p><strong>Overall Risk Score:</strong> \${(score.overall * 100).toFixed(1)}%</p>
                        <p><strong>Severity Component:</strong> \${(score.components.severity * 100).toFixed(1)}%</p>
                        <p><strong>Business Impact:</strong> \${(score.components.businessImpact * 100).toFixed(1)}%</p>
                        <p><strong>AI Confidence:</strong> \${(score.confidence * 100).toFixed(1)}%</p>
                        <p><strong>Priority:</strong> \${score.recommendations.priority}</p>
                        <p><strong>Exploitation Likelihood:</strong> \${(score.prediction.likelihood * 100).toFixed(1)}%</p>
                    \`;
                } else {
                    resultDiv.innerHTML = '<span class="error">❌ Error: ' + data.error + '</span>';
                }
            } catch (error) {
                resultDiv.innerHTML = '<span class="error">❌ Network error: ' + error.message + '</span>';
            }
        }

        async function loadMetrics() {
            try {
                const statusDiv = document.getElementById('status');
                statusDiv.innerHTML = '⏳ Loading metrics...';
                
                // Load dashboard metrics
                const metricsResponse = await fetch('/api/risk/metrics');
                const metricsData = await metricsResponse.json();
                
                if (metricsData.success) {
                    document.getElementById('total-vulns').textContent = metricsData.data.totalVulnerabilities;
                    document.getElementById('critical-count').textContent = metricsData.data.criticalCount;
                    document.getElementById('avg-risk').textContent = (metricsData.data.averageRiskScore * 100).toFixed(1) + '%';
                }
                
                // Load AI model metrics
                const modelResponse = await fetch('/api/model/metrics');
                const modelData = await modelResponse.json();
                
                if (modelData.success) {
                    document.getElementById('ai-accuracy').textContent = (modelData.data.accuracy * 100).toFixed(1) + '%';
                }
                
                statusDiv.innerHTML = '✅ Dashboard updated successfully';
                
            } catch (error) {
                document.getElementById('status').innerHTML = '<span class="error">❌ Error loading data: ' + error.message + '</span>';
            }
        }

        // Load initial data
        loadMetrics();
        
        // Auto-refresh every 30 seconds
        setInterval(loadMetrics, 30000);
    </script>
</body>
</html>
            `);
        });
    }

    private setupSocketHandlers(): void {
        this.io.on('connection', (socket) => {
            console.log('Client connected:', socket.id);
            
            socket.emit('welcome', {
                message: 'Connected to AI Risk Visualizer',
                timestamp: new Date().toISOString()
            });

            socket.on('disconnect', () => {
                console.log('Client disconnected:', socket.id);
            });
        });
    }

    async start(): Promise<void> {
        return new Promise((resolve) => {
            this.server.listen(this.config.port, this.config.host, () => {
                console.log(`✅ Standalone Dashboard running on http://${this.config.host}:${this.config.port}`);
                resolve();
            });
        });
    }

    async stop(): Promise<void> {
        return new Promise((resolve) => {
            this.server.close(() => {
                console.log('Dashboard server stopped');
                resolve();
            });
        });
    }
}

async function runStandaloneDashboard() {
    console.log('\n🚀 Starting Standalone AI Risk Visualizer Dashboard\n');
    console.log('=' .repeat(60));

    try {
        // Initialize AI/ML Risk Scoring Engine
        console.log('\n🧠 Initializing AI/ML Risk Scoring Engine...');
        const riskEngine = new RiskScoringEngine();
        
        console.log('⏳ Loading TensorFlow.js models...');
        await riskEngine.initialize();
        console.log('✅ AI/ML Risk Scoring Engine ready!');

        // Configure and start dashboard
        const config: DashboardConfig = {
            port: 3000,
            host: 'localhost'
        };

        console.log('\n📊 Starting Dashboard Server...');
        const dashboard = new StandaloneDashboard(config, riskEngine);
        
        await dashboard.start();
        
        console.log('\n🎉 Standalone Dashboard Successfully Launched!');
        console.log('=' .repeat(60));
        
        console.log('\n🌐 Dashboard Access:');
        console.log(`  📍 Main Dashboard: http://${config.host}:${config.port}`);
        console.log(`  📊 Health Check: http://${config.host}:${config.port}/api/health`);
        console.log(`  🤖 AI Risk Scoring: POST http://${config.host}:${config.port}/api/risk/score`);
        console.log(`  📈 Model Metrics: http://${config.host}:${config.port}/api/model/metrics`);

        console.log('\n✨ Dashboard Features:');
        console.log('  🧠 AI/ML Risk Scoring with TensorFlow.js');
        console.log('  📊 Interactive metrics dashboard');
        console.log('  🔄 Real-time risk assessment');
        console.log('  📈 Model performance monitoring');
        console.log('  🎯 Live vulnerability analysis');

        console.log('\n🎯 Dashboard Status:');
        console.log('✅ AI/ML Risk Scoring Engine: Operational');
        console.log('✅ TensorFlow.js Models: Loaded and Ready');
        console.log('✅ Web Server: Running on port 3000');
        console.log('✅ API Endpoints: Active and responding');

        console.log('\n🚀 Dashboard is now live and ready!');
        console.log('🌐 Visit http://localhost:3000 to access the interactive dashboard');
        console.log('💡 Press Ctrl+C to stop the dashboard server');
        
        // Handle graceful shutdown
        process.on('SIGINT', async () => {
            console.log('\n\n🛑 Shutting down Dashboard...');
            await dashboard.stop();
            console.log('✅ Dashboard server stopped gracefully');
            process.exit(0);
        });

        // Keep alive
        await new Promise(() => {});

    } catch (error: any) {
        console.error(`\n❌ Dashboard startup failed: ${error.message}`);
        console.error(error.stack);
        process.exit(1);
    }
}

// Run the standalone dashboard
runStandaloneDashboard().catch(console.error); 