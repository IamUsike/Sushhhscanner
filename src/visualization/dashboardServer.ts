import express from 'express';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import cors from 'cors';
import path from 'path';
import { RiskScoringEngine, VulnerabilityData } from '../ai/riskScoringEngine';
import { RiskAnalyticsDashboard, RiskHeatmapData, MLInsight } from '../ai/riskAnalyticsDashboard';
import { RealTimeApiScanner, ApiScanRequest } from '../integration/realTimeApiScanner';
import { EndpointDiscovery } from '../discovery/endpointDiscovery';
import { AuthenticationTester } from '../security/authenticationTester';
import { ParameterVulnerabilityScanner } from '../security/parameterVulnerabilityScanner';
import { logger } from '../utils/logger';

export interface DashboardConfig {
  port: number;
  host: string;
  corsOrigins: string[];
  updateInterval: number; // milliseconds
}

export interface ClientConnection {
  id: string;
  connectedAt: Date;
  subscriptions: string[];
}

export class DashboardServer {
  private app: express.Application;
  private server: any;
  private io: SocketIOServer;
  private config: DashboardConfig;
  private riskEngine: RiskScoringEngine;
  private analytics: RiskAnalyticsDashboard;
  private realTimeScanner: RealTimeApiScanner;
  
  private clients: Map<string, ClientConnection> = new Map();
  private updateTimer: NodeJS.Timeout | null = null;
  
  // Sample data for demonstration - will be replaced with real scan data
  private vulnerabilities: VulnerabilityData[] = [];
  private lastUpdate: Date = new Date();
  private hasRealScanData: boolean = false; // Track if we have real scan data vs sample data

  constructor(config: DashboardConfig, riskEngine: RiskScoringEngine) {
    this.config = config;
    this.riskEngine = riskEngine;
    this.analytics = new RiskAnalyticsDashboard(riskEngine);
    
    // Initialize real-time scanner with all components
            const discoveryEngine = new EndpointDiscovery({ baseUrl: '', authMethod: 'none' });
    const authTester = new AuthenticationTester();
    const parameterScanner = new ParameterVulnerabilityScanner();
    
    this.realTimeScanner = new RealTimeApiScanner(
      riskEngine,
      discoveryEngine,
      authTester,
      parameterScanner
    );
    this.realTimeScanner.setDashboardServer(this);
    
    this.app = express();
    this.server = createServer(this.app);
    this.io = new SocketIOServer(this.server, {
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

  private setupMiddleware(): void {
    this.app.use(cors({
      origin: this.config.corsOrigins
    }));
    this.app.use(express.json());
    this.app.use(express.static(path.join(__dirname, '../../public')));
    
    // Request logging
    this.app.use((req, res, next) => {
      logger.info(`${req.method} ${req.path}`, { 
        ip: req.ip, 
        userAgent: req.get('user-agent') 
      });
      next();
    });
  }

  private setupRoutes(): void {
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
      } catch (error: any) {
        logger.error(`Portfolio API error: ${error.message}`);
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
      } catch (error: any) {
        logger.error(`Heatmap API error: ${error.message}`);
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
      } catch (error: any) {
        logger.error(`Insights API error: ${error.message}`);
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
      } catch (error: any) {
        logger.error(`Timeline API error: ${error.message}`);
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
      } catch (error: any) {
        logger.error(`Metrics API error: ${error.message}`);
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
        const vulnerability = this.vulnerabilities.find(v => 
          `${v.endpoint}-${v.method}` === vulnerabilityId
        );
        
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
      } catch (error: any) {
        logger.error(`Vulnerability details API error: ${error.message}`);
        res.status(500).json({
          success: false,
          error: error.message
        });
      }
    });

    // Risk scoring endpoint
    this.app.post('/api/risk/score', async (req, res) => {
      try {
        const vulnerability: VulnerabilityData = req.body;
        const riskScore = await this.riskEngine.calculateRiskScore(vulnerability);
        
        res.json({
          success: true,
          data: riskScore,
          timestamp: new Date().toISOString()
        });
      } catch (error: any) {
        logger.error(`Risk scoring API error: ${error.message}`);
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
        logger.error(`Model metrics API error: ${error.message}`);
        res.status(500).json({
          success: false,
          error: error.message
        });
      }
    });

    // Real-time API scanning endpoints
    this.app.post('/api/scan/start', async (req, res) => {
      try {
        const scanRequest: ApiScanRequest = req.body;
        
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
      } catch (error: any) {
        logger.error(`Scan start API error: ${error.message}`);
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
      } catch (error: any) {
        logger.error(`Scan status API error: ${error.message}`);
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
      } catch (error: any) {
        logger.error(`Scan cancel API error: ${error.message}`);
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
      } catch (error: any) {
        logger.error(`Active scan API error: ${error.message}`);
        res.status(500).json({
          success: false,
          error: error.message
        });
      }
    });

    // Serve dashboard HTML
    this.app.get('/', (req, res) => {
      res.sendFile(path.join(__dirname, '../../public/dashboard.html'));
    });

    // Serve real API dashboard
    this.app.get('/real_api_dashboard.html', (req, res) => {
      res.sendFile(path.join(__dirname, '../../public/real_api_dashboard.html'));
    });

    // Serve regular dashboard as well
    this.app.get('/dashboard.html', (req, res) => {
      res.sendFile(path.join(__dirname, '../../public/dashboard.html'));
    });

    // 404 handler
    this.app.use('*', (req, res) => {
      res.status(404).json({
        success: false,
        error: 'Endpoint not found'
      });
    });
  }

  private setupSocketHandlers(): void {
    this.io.on('connection', (socket) => {
      const clientId = socket.id;
      const connection: ClientConnection = {
        id: clientId,
        connectedAt: new Date(),
        subscriptions: []
      };
      
      this.clients.set(clientId, connection);
      logger.info(`Client connected: ${clientId}`);

      // Send initial data
      socket.emit('initial-data', {
        timestamp: new Date().toISOString(),
        message: 'Connected to Risk Visualization Dashboard'
      });

      // Handle subscription requests
      socket.on('subscribe', (channel: string) => {
        connection.subscriptions.push(channel);
        socket.join(channel);
        logger.info(`Client ${clientId} subscribed to ${channel}`);
      });

      socket.on('unsubscribe', (channel: string) => {
        connection.subscriptions = connection.subscriptions.filter(c => c !== channel);
        socket.leave(channel);
        logger.info(`Client ${clientId} unsubscribed from ${channel}`);
      });

      // Handle real-time data requests
      socket.on('request-heatmap', async () => {
        try {
          const heatmapData = await this.analytics.generateRiskHeatmap(this.vulnerabilities);
          socket.emit('heatmap-data', {
            data: heatmapData,
            timestamp: new Date().toISOString()
          });
        } catch (error: any) {
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
        } catch (error: any) {
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
        } catch (error: any) {
          socket.emit('error', { message: error.message });
        }
      });

      // Handle disconnection
      socket.on('disconnect', () => {
        this.clients.delete(clientId);
        logger.info(`Client disconnected: ${clientId}`);
      });
    });
  }

  private loadSampleData(): void {
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

    logger.info(`Loaded ${this.vulnerabilities.length} sample vulnerabilities`);
  }

  private generateTimelineData(): any[] {
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

  private async generateDashboardMetrics(): Promise<any> {
    const riskScores = await Promise.all(
      this.vulnerabilities.map(vuln => this.riskEngine.calculateRiskScore(vuln))
    );

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
      trendDirection: 'down' as const // Sample trend
    };
  }

  private startRealTimeUpdates(): void {
    this.updateTimer = setInterval(async () => {
      try {
        // Check if we have real scan data from an actual scan
        const activeScan = this.realTimeScanner.getActiveScan();
        
        // If we have real scan data or an active scan, don't send sample data updates
        if (activeScan || this.hasRealScanData) {
          logger.debug('Skipping sample data update - real scan data available');
          return;
        }
        
        // Only send sample data updates if no real scan data exists
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
        logger.info(`Sample data update sent to ${this.clients.size} clients`);
        
      } catch (error: any) {
        logger.error(`Real-time update failed: ${error.message}`);
      }
    }, this.config.updateInterval);
  }

  private stopRealTimeUpdates(): void {
    if (this.updateTimer) {
      clearInterval(this.updateTimer);
      this.updateTimer = null;
    }
  }

  async start(): Promise<void> {
    try {
      // Initialize the risk engine
      await this.riskEngine.initialize();
      
      // Start the server
      this.server.listen(this.config.port, this.config.host, () => {
        logger.info(`Dashboard server running on http://${this.config.host}:${this.config.port}`);
        logger.info(`WebSocket connections: ws://${this.config.host}:${this.config.port}`);
      });

      // Start real-time updates
      this.startRealTimeUpdates();
      
    } catch (error: any) {
      logger.error(`Failed to start dashboard server: ${error.message}`);
      throw error;
    }
  }

  async stop(): Promise<void> {
    this.stopRealTimeUpdates();
    
    return new Promise((resolve) => {
      this.server.close(() => {
        logger.info('Dashboard server stopped');
        resolve();
      });
    });
  }

  getConnectedClients(): ClientConnection[] {
    return Array.from(this.clients.values());
  }

  broadcastMessage(channel: string, message: any): void {
    // For scan updates, emit directly to all connected clients
    if (channel === 'scan_updates') {
      this.io.emit('scan_updates', message);
      logger.info(`Broadcasting scan update to ${this.clients.size} clients`);
    } else if (channel === 'dashboard_update') {
      this.io.emit('dashboard_update', message);
      logger.info(`Broadcasting dashboard update to ${this.clients.size} clients`);
    } else {
      // For other channels, use the room-based approach
      this.io.to(channel).emit('broadcast', {
        channel,
        message,
        timestamp: new Date().toISOString()
      });
    }
  }

  // Method to update dashboard with real scan data
  updateWithRealScanData(vulnerabilities: VulnerabilityData[]): void {
    logger.info(`Updating dashboard with ${vulnerabilities.length} real vulnerabilities`);
    
    // Replace sample data with real scan data
    this.vulnerabilities = vulnerabilities;
    this.hasRealScanData = true;
    this.lastUpdate = new Date();
    
    // Stop sending sample data updates since we now have real data
    logger.info('Real scan data received - stopping sample data updates');
  }

  // Method to reset to sample data (for testing/demo purposes)
  resetToSampleData(): void {
    logger.info('Resetting to sample data');
    this.hasRealScanData = false;
    this.loadSampleData();
  }
} 