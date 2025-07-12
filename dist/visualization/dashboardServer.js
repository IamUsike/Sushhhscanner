"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.DashboardServer = void 0;
const express_1 = __importDefault(require("express"));
const http_1 = require("http");
const socket_io_1 = require("socket.io");
const cors_1 = __importDefault(require("cors"));
const path_1 = __importDefault(require("path"));
const riskAnalyticsDashboard_1 = require("../ai/riskAnalyticsDashboard");
const realTimeApiScanner_1 = require("../integration/realTimeApiScanner");
const endpointDiscovery_1 = require("../discovery/endpointDiscovery");
const authenticationTester_1 = require("../security/authenticationTester");
const parameterVulnerabilityScanner_1 = require("../security/parameterVulnerabilityScanner");
const logger_1 = require("../utils/logger");
class DashboardServer {
    constructor(config, riskEngine) {
        this.clients = new Map();
        this.updateTimer = null;
        // Sample data for demonstration - will be replaced with real scan data
        this.vulnerabilities = [];
        this.lastUpdate = new Date();
        this.config = config;
        this.riskEngine = riskEngine;
        this.analytics = new riskAnalyticsDashboard_1.RiskAnalyticsDashboard(riskEngine);
        // Initialize real-time scanner with all components
        const discoveryEngine = new endpointDiscovery_1.EndpointDiscovery({ baseUrl: '', authMethod: 'none' });
        const authTester = new authenticationTester_1.AuthenticationTester();
        const parameterScanner = new parameterVulnerabilityScanner_1.ParameterVulnerabilityScanner();
        this.realTimeScanner = new realTimeApiScanner_1.RealTimeApiScanner(riskEngine, discoveryEngine, authTester, parameterScanner);
        this.realTimeScanner.setDashboardServer(this);
        this.app = (0, express_1.default)();
        this.server = (0, http_1.createServer)(this.app);
        this.io = new socket_io_1.Server(this.server, {
            cors: {
                origin: config.corsOrigins,
                methods: ['GET', 'POST']
            }
        });
        this.setupMiddleware();
        this.setupRoutes();
        this.setupSocketHandlers();
        this.loadSampleData();
    }
    setupMiddleware() {
        this.app.use((0, cors_1.default)({
            origin: this.config.corsOrigins
        }));
        this.app.use(express_1.default.json());
        this.app.use(express_1.default.static(path_1.default.join(__dirname, '../../public')));
        // Request logging
        this.app.use((req, res, next) => {
            logger_1.logger.info(`${req.method} ${req.path}`, {
                ip: req.ip,
                userAgent: req.get('user-agent')
            });
            next();
        });
    }
    setupRoutes() {
        // Health check
        this.app.get('/api/health', (req, res) => {
            res.json({
                status: 'healthy',
                timestamp: new Date().toISOString(),
                version: '1.0.0',
                uptime: process.uptime(),
                connectedClients: this.clients.size
            });
        });
        // Risk data endpoints
        this.app.get('/api/risk/portfolio', async (req, res) => {
            try {
                const portfolio = await this.analytics.generateRiskPortfolio(this.vulnerabilities);
                res.json({
                    success: true,
                    data: portfolio,
                    timestamp: new Date().toISOString()
                });
            }
            catch (error) {
                logger_1.logger.error(`Portfolio API error: ${error.message}`);
                res.status(500).json({
                    success: false,
                    error: error.message
                });
            }
        });
        this.app.get('/api/risk/heatmap', async (req, res) => {
            try {
                const heatmapData = await this.analytics.generateRiskHeatmap(this.vulnerabilities);
                res.json({
                    success: true,
                    data: heatmapData,
                    timestamp: new Date().toISOString()
                });
            }
            catch (error) {
                logger_1.logger.error(`Heatmap API error: ${error.message}`);
                res.status(500).json({
                    success: false,
                    error: error.message
                });
            }
        });
        this.app.get('/api/risk/insights', async (req, res) => {
            try {
                const insights = await this.analytics.generateMLInsights(this.vulnerabilities);
                res.json({
                    success: true,
                    data: insights,
                    timestamp: new Date().toISOString()
                });
            }
            catch (error) {
                logger_1.logger.error(`Insights API error: ${error.message}`);
                res.status(500).json({
                    success: false,
                    error: error.message
                });
            }
        });
        this.app.get('/api/risk/timeline', async (req, res) => {
            try {
                const timeline = this.generateTimelineData();
                res.json({
                    success: true,
                    data: timeline,
                    timestamp: new Date().toISOString()
                });
            }
            catch (error) {
                logger_1.logger.error(`Timeline API error: ${error.message}`);
                res.status(500).json({
                    success: false,
                    error: error.message
                });
            }
        });
        this.app.get('/api/risk/metrics', async (req, res) => {
            try {
                const metrics = await this.generateDashboardMetrics();
                res.json({
                    success: true,
                    data: metrics,
                    timestamp: new Date().toISOString()
                });
            }
            catch (error) {
                logger_1.logger.error(`Metrics API error: ${error.message}`);
                res.status(500).json({
                    success: false,
                    error: error.message
                });
            }
        });
        // Individual vulnerability details
        this.app.get('/api/risk/vulnerability/:id', async (req, res) => {
            try {
                const vulnerabilityId = req.params.id;
                const vulnerability = this.vulnerabilities.find(v => `${v.endpoint}-${v.method}` === vulnerabilityId);
                if (!vulnerability) {
                    return res.status(404).json({
                        success: false,
                        error: 'Vulnerability not found'
                    });
                }
                const riskScore = await this.riskEngine.calculateRiskScore(vulnerability);
                res.json({
                    success: true,
                    data: {
                        vulnerability,
                        riskScore,
                        timestamp: new Date().toISOString()
                    }
                });
            }
            catch (error) {
                logger_1.logger.error(`Vulnerability details API error: ${error.message}`);
                res.status(500).json({
                    success: false,
                    error: error.message
                });
            }
        });
        // Risk scoring endpoint
        this.app.post('/api/risk/score', async (req, res) => {
            try {
                const vulnerability = req.body;
                const riskScore = await this.riskEngine.calculateRiskScore(vulnerability);
                res.json({
                    success: true,
                    data: riskScore,
                    timestamp: new Date().toISOString()
                });
            }
            catch (error) {
                logger_1.logger.error(`Risk scoring API error: ${error.message}`);
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
            }
            catch (error) {
                logger_1.logger.error(`Model metrics API error: ${error.message}`);
                res.status(500).json({
                    success: false,
                    error: error.message
                });
            }
        });
        // Real-time API scanning endpoints
        this.app.post('/api/scan/start', async (req, res) => {
            try {
                const scanRequest = req.body;
                // Validate scan request
                if (!scanRequest.targetUrl) {
                    return res.status(400).json({
                        success: false,
                        error: 'Target URL is required'
                    });
                }
                // Set defaults
                scanRequest.scanMethods = scanRequest.scanMethods || ['swagger', 'crawl'];
                scanRequest.scanDepth = scanRequest.scanDepth || 'deep';
                scanRequest.realTimeUpdates = scanRequest.realTimeUpdates !== false;
                const scanId = await this.realTimeScanner.startRealTimeScan(scanRequest);
                res.json({
                    success: true,
                    data: {
                        scanId,
                        message: 'Real-time API scan started',
                        targetUrl: scanRequest.targetUrl
                    },
                    timestamp: new Date().toISOString()
                });
            }
            catch (error) {
                logger_1.logger.error(`Scan start API error: ${error.message}`);
                res.status(500).json({
                    success: false,
                    error: error.message
                });
            }
        });
        this.app.get('/api/scan/status/:scanId', (req, res) => {
            try {
                const scanId = req.params.scanId;
                const scanStatus = this.realTimeScanner.getScanStatus(scanId);
                if (!scanStatus) {
                    return res.status(404).json({
                        success: false,
                        error: 'Scan not found'
                    });
                }
                res.json({
                    success: true,
                    data: scanStatus,
                    timestamp: new Date().toISOString()
                });
            }
            catch (error) {
                logger_1.logger.error(`Scan status API error: ${error.message}`);
                res.status(500).json({
                    success: false,
                    error: error.message
                });
            }
        });
        this.app.post('/api/scan/cancel/:scanId', (req, res) => {
            try {
                const scanId = req.params.scanId;
                const cancelled = this.realTimeScanner.cancelScan(scanId);
                if (!cancelled) {
                    return res.status(404).json({
                        success: false,
                        error: 'Scan not found or already completed'
                    });
                }
                res.json({
                    success: true,
                    data: {
                        scanId,
                        message: 'Scan cancelled successfully'
                    },
                    timestamp: new Date().toISOString()
                });
            }
            catch (error) {
                logger_1.logger.error(`Scan cancel API error: ${error.message}`);
                res.status(500).json({
                    success: false,
                    error: error.message
                });
            }
        });
        this.app.get('/api/scan/active', (req, res) => {
            try {
                const activeScan = this.realTimeScanner.getActiveScan();
                res.json({
                    success: true,
                    data: activeScan,
                    timestamp: new Date().toISOString()
                });
            }
            catch (error) {
                logger_1.logger.error(`Active scan API error: ${error.message}`);
                res.status(500).json({
                    success: false,
                    error: error.message
                });
            }
        });
        // Serve dashboard HTML
        this.app.get('/', (req, res) => {
            res.sendFile(path_1.default.join(__dirname, '../../public/dashboard.html'));
        });
        // Serve real API dashboard
        this.app.get('/real_api_dashboard.html', (req, res) => {
            res.sendFile(path_1.default.join(__dirname, '../../public/real_api_dashboard.html'));
        });
        // Serve regular dashboard as well
        this.app.get('/dashboard.html', (req, res) => {
            res.sendFile(path_1.default.join(__dirname, '../../public/dashboard.html'));
        });
        // 404 handler
        this.app.use('*', (req, res) => {
            res.status(404).json({
                success: false,
                error: 'Endpoint not found'
            });
        });
    }
    setupSocketHandlers() {
        this.io.on('connection', (socket) => {
            const clientId = socket.id;
            const connection = {
                id: clientId,
                connectedAt: new Date(),
                subscriptions: []
            };
            this.clients.set(clientId, connection);
            logger_1.logger.info(`Client connected: ${clientId}`);
            // Send initial data
            socket.emit('initial-data', {
                timestamp: new Date().toISOString(),
                message: 'Connected to Risk Visualization Dashboard'
            });
            // Handle subscription requests
            socket.on('subscribe', (channel) => {
                connection.subscriptions.push(channel);
                socket.join(channel);
                logger_1.logger.info(`Client ${clientId} subscribed to ${channel}`);
            });
            socket.on('unsubscribe', (channel) => {
                connection.subscriptions = connection.subscriptions.filter(c => c !== channel);
                socket.leave(channel);
                logger_1.logger.info(`Client ${clientId} unsubscribed from ${channel}`);
            });
            // Handle real-time data requests
            socket.on('request-heatmap', async () => {
                try {
                    const heatmapData = await this.analytics.generateRiskHeatmap(this.vulnerabilities);
                    socket.emit('heatmap-data', {
                        data: heatmapData,
                        timestamp: new Date().toISOString()
                    });
                }
                catch (error) {
                    socket.emit('error', { message: error.message });
                }
            });
            socket.on('request-insights', async () => {
                try {
                    const insights = await this.analytics.generateMLInsights(this.vulnerabilities);
                    socket.emit('insights-data', {
                        data: insights,
                        timestamp: new Date().toISOString()
                    });
                }
                catch (error) {
                    socket.emit('error', { message: error.message });
                }
            });
            socket.on('request-metrics', async () => {
                try {
                    const metrics = await this.generateDashboardMetrics();
                    socket.emit('metrics-data', {
                        data: metrics,
                        timestamp: new Date().toISOString()
                    });
                }
                catch (error) {
                    socket.emit('error', { message: error.message });
                }
            });
            // Handle disconnection
            socket.on('disconnect', () => {
                this.clients.delete(clientId);
                logger_1.logger.info(`Client disconnected: ${clientId}`);
            });
        });
    }
    loadSampleData() {
        // Load comprehensive sample vulnerabilities for demonstration
        this.vulnerabilities = [
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
        logger_1.logger.info(`Loaded ${this.vulnerabilities.length} sample vulnerabilities`);
    }
    generateTimelineData() {
        const timeline = [];
        const now = new Date();
        // Generate 30 days of timeline data
        for (let i = 29; i >= 0; i--) {
            const date = new Date(now.getTime() - (i * 24 * 60 * 60 * 1000));
            timeline.push({
                timestamp: date,
                value: Math.random() * 100,
                category: 'Risk Score',
                metadata: { day: i }
            });
            timeline.push({
                timestamp: date,
                value: Math.floor(Math.random() * 20),
                category: 'New Vulnerabilities',
                metadata: { day: i }
            });
            timeline.push({
                timestamp: date,
                value: Math.floor(Math.random() * 15),
                category: 'Resolved Issues',
                metadata: { day: i }
            });
        }
        return timeline;
    }
    async generateDashboardMetrics() {
        const riskScores = await Promise.all(this.vulnerabilities.map(vuln => this.riskEngine.calculateRiskScore(vuln)));
        const criticalCount = riskScores.filter(rs => rs.overall >= 0.8).length;
        const highCount = riskScores.filter(rs => rs.overall >= 0.6 && rs.overall < 0.8).length;
        const mediumCount = riskScores.filter(rs => rs.overall >= 0.4 && rs.overall < 0.6).length;
        const lowCount = riskScores.filter(rs => rs.overall < 0.4).length;
        const averageRisk = riskScores.reduce((sum, rs) => sum + rs.overall, 0) / riskScores.length;
        return {
            totalVulnerabilities: this.vulnerabilities.length,
            criticalCount,
            highCount,
            mediumCount,
            lowCount,
            averageRiskScore: averageRisk,
            complianceScore: 85, // Sample compliance score
            trendDirection: 'down' // Sample trend
        };
    }
    startRealTimeUpdates() {
        this.updateTimer = setInterval(async () => {
            try {
                // Generate fresh insights and metrics
                const metrics = await this.generateDashboardMetrics();
                const insights = await this.analytics.generateMLInsights(this.vulnerabilities);
                // Broadcast to all connected clients
                this.io.emit('real-time-update', {
                    type: 'metrics',
                    data: metrics,
                    timestamp: new Date().toISOString()
                });
                this.io.emit('real-time-update', {
                    type: 'insights',
                    data: insights,
                    timestamp: new Date().toISOString()
                });
                this.lastUpdate = new Date();
                logger_1.logger.info(`Real-time update sent to ${this.clients.size} clients`);
            }
            catch (error) {
                logger_1.logger.error(`Real-time update failed: ${error.message}`);
            }
        }, this.config.updateInterval);
    }
    stopRealTimeUpdates() {
        if (this.updateTimer) {
            clearInterval(this.updateTimer);
            this.updateTimer = null;
        }
    }
    async start() {
        try {
            // Initialize the risk engine
            await this.riskEngine.initialize();
            // Start the server
            this.server.listen(this.config.port, this.config.host, () => {
                logger_1.logger.info(`Dashboard server running on http://${this.config.host}:${this.config.port}`);
                logger_1.logger.info(`WebSocket connections: ws://${this.config.host}:${this.config.port}`);
            });
            // Start real-time updates
            this.startRealTimeUpdates();
        }
        catch (error) {
            logger_1.logger.error(`Failed to start dashboard server: ${error.message}`);
            throw error;
        }
    }
    async stop() {
        this.stopRealTimeUpdates();
        return new Promise((resolve) => {
            this.server.close(() => {
                logger_1.logger.info('Dashboard server stopped');
                resolve();
            });
        });
    }
    getConnectedClients() {
        return Array.from(this.clients.values());
    }
    broadcastMessage(channel, message) {
        // For scan updates, emit directly to all connected clients
        if (channel === 'scan_updates') {
            this.io.emit('scan_updates', message);
            logger_1.logger.info(`Broadcasting scan update to ${this.clients.size} clients`);
        }
        else if (channel === 'dashboard_update') {
            this.io.emit('dashboard_update', message);
            logger_1.logger.info(`Broadcasting dashboard update to ${this.clients.size} clients`);
        }
        else {
            // For other channels, use the room-based approach
            this.io.to(channel).emit('broadcast', {
                channel,
                message,
                timestamp: new Date().toISOString()
            });
        }
    }
}
exports.DashboardServer = DashboardServer;
//# sourceMappingURL=dashboardServer.js.map