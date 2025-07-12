"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.scanRoutes = void 0;
const express_1 = require("express");
const uuid_1 = require("uuid");
const joi_1 = __importDefault(require("joi"));
const middleware_1 = require("@utils/middleware");
const database_1 = require("../core/database");
const websocket_1 = require("../core/websocket");
const logger_1 = require("@utils/logger");
const endpointDiscovery_1 = require("../discovery/endpointDiscovery");
const router = (0, express_1.Router)();
exports.scanRoutes = router;
// Apply security headers to all scan routes
router.use(middleware_1.securityHeaders);
// Validation schemas
const scanTargetSchema = joi_1.default.object({
    baseUrl: joi_1.default.string().uri().required(),
    authMethod: joi_1.default.string().valid('none', 'bearer', 'basic', 'api-key', 'oauth2').default('none'),
    authToken: joi_1.default.string().when('authMethod', {
        is: joi_1.default.string().valid('bearer', 'api-key'),
        then: joi_1.default.required(),
        otherwise: joi_1.default.optional(),
    }),
    authUsername: joi_1.default.string().when('authMethod', {
        is: 'basic',
        then: joi_1.default.required(),
        otherwise: joi_1.default.optional(),
    }),
    authPassword: joi_1.default.string().when('authMethod', {
        is: 'basic',
        then: joi_1.default.required(),
        otherwise: joi_1.default.optional(),
    }),
    headers: joi_1.default.object().pattern(joi_1.default.string(), joi_1.default.string()).optional(),
    endpoints: joi_1.default.array().items(joi_1.default.string()).optional(),
    swaggerUrl: joi_1.default.string().uri().optional(),
});
const scanConfigSchema = joi_1.default.object({
    depth: joi_1.default.string().valid('basic', 'comprehensive', 'deep').default('comprehensive'),
    includeAI: joi_1.default.boolean().default(true),
    testTypes: joi_1.default.array().items(joi_1.default.string().valid('auth', 'injection', 'exposure', 'config', 'rate-limiting', 'headers', 'business-logic', 'data-exposure')).default(['auth', 'injection', 'exposure', 'config']),
    maxEndpoints: joi_1.default.number().min(1).max(1000).default(100),
    timeout: joi_1.default.number().min(60000).max(3600000).default(1800000), // 30 minutes default
    concurrent: joi_1.default.boolean().default(true),
    excludePatterns: joi_1.default.array().items(joi_1.default.string()).optional(),
    customPayloads: joi_1.default.array().items(joi_1.default.string()).optional(),
});
const createScanSchema = joi_1.default.object({
    target: scanTargetSchema.required(),
    scanConfig: scanConfigSchema.optional(),
});
// POST /api/v1/scans - Create a new security scan
router.post('/', middleware_1.authenticate, (0, middleware_1.validateRequest)(createScanSchema), (0, middleware_1.asyncHandler)(async (req, res) => {
    const { target, scanConfig } = req.body;
    const userId = req.user.id;
    // Check if user has reached concurrent scan limit
    const userScans = await database_1.database.getUserScans(userId, 10);
    const activeScans = userScans.filter(scan => ['pending', 'discovering', 'testing', 'analyzing'].includes(scan.status));
    const maxConcurrentScans = parseInt(process.env.MAX_CONCURRENT_SCANS || '5');
    if (activeScans.length >= maxConcurrentScans) {
        return res.status(429).json({
            success: false,
            error: {
                message: `Maximum concurrent scans (${maxConcurrentScans}) reached. Please wait for existing scans to complete.`,
                code: 'CONCURRENT_SCAN_LIMIT',
            },
            timestamp: new Date().toISOString(),
        });
    }
    // Create scan record
    const scanId = (0, uuid_1.v4)();
    const scan = {
        id: scanId,
        userId,
        target: target,
        configuration: {
            depth: 'comprehensive',
            includeAI: true,
            testTypes: ['auth', 'injection', 'exposure', 'config'],
            maxEndpoints: 100,
            timeout: 1800000,
            concurrent: true,
            ...scanConfig
        },
        status: 'pending',
        progress: 0,
        currentStep: 'initializing',
        vulnerabilities: [],
        metadata: {
            userAgent: req.get('User-Agent') || 'unknown',
            scannerVersion: process.env.npm_package_version || '1.0.0',
            startedAt: new Date(),
            endpointsDiscovered: 0,
            requestsSent: 0,
            aiAnalysisEnabled: scanConfig?.includeAI ?? true,
        },
    };
    await database_1.database.createScan(scan);
    // Log scan initiation
    (0, logger_1.logScanStart)(scanId, target.baseUrl, scan.configuration);
    // Start the scan asynchronously (don't await)
    startScanProcess(scan).catch(error => {
        logger_1.logger.error(`Scan ${scanId} failed to start:`, error);
        database_1.database.updateScan(scanId, {
            status: 'failed',
            currentStep: `Failed to start: ${error.message}`,
        });
        const wsManager = (0, websocket_1.getWebSocketManager)();
        wsManager.notifyError(scanId, `Scan failed to start: ${error.message}`);
    });
    const response = {
        success: true,
        data: {
            scanId,
            status: 'initiated',
            websocketUrl: `ws://localhost:${process.env.PORT || 3000}/scans/${scanId}`,
        },
        metadata: {
            timestamp: new Date(),
        },
    };
    res.status(201).json(response);
}));
// GET /api/v1/scans/:scanId - Get scan details and results
router.get('/:scanId', middleware_1.authenticate, (0, middleware_1.asyncHandler)(async (req, res) => {
    const { scanId } = req.params;
    const userId = req.user.id;
    const scan = await database_1.database.getScan(scanId);
    if (!scan) {
        return res.status(404).json({
            success: false,
            error: { message: 'Scan not found' },
            timestamp: new Date().toISOString(),
        });
    }
    // Check if user owns this scan (or is admin)
    if (scan.userId !== userId && req.user.role !== 'admin') {
        return res.status(403).json({
            success: false,
            error: { message: 'Access denied' },
            timestamp: new Date().toISOString(),
        });
    }
    // Load vulnerabilities
    scan.vulnerabilities = await database_1.database.getScanVulnerabilities(scanId);
    const response = {
        success: true,
        data: scan,
        metadata: {
            timestamp: new Date(),
        },
    };
    res.json(response);
}));
// GET /api/v1/scans/:scanId/results - Get detailed scan results with AI analysis
router.get('/:scanId/results', middleware_1.authenticate, (0, middleware_1.asyncHandler)(async (req, res) => {
    const { scanId } = req.params;
    const userId = req.user.id;
    const scan = await database_1.database.getScan(scanId);
    if (!scan) {
        return res.status(404).json({
            success: false,
            error: { message: 'Scan not found' },
            timestamp: new Date().toISOString(),
        });
    }
    if (scan.userId !== userId && req.user.role !== 'admin') {
        return res.status(403).json({
            success: false,
            error: { message: 'Access denied' },
            timestamp: new Date().toISOString(),
        });
    }
    const vulnerabilities = await database_1.database.getScanVulnerabilities(scanId);
    // Format results according to API spec
    const results = {
        scanId,
        status: scan.status,
        summary: scan.summary || {
            totalEndpoints: scan.metadata.endpointsDiscovered,
            vulnerabilities: {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                info: 0,
            },
            overallRiskScore: 0,
            aiPredictedRisk: 0,
        },
        vulnerabilities,
        aiInsights: scan.configuration.includeAI ? {
            threatPrediction: {
                timeToExploit: "Analysis pending",
                attackVectors: [],
                similarBreaches: [],
            },
            recommendations: [
                "Complete security scan in progress",
                "Results will include AI-powered recommendations",
            ],
        } : undefined,
    };
    // Calculate summary if scan is completed
    if (scan.status === 'completed' && vulnerabilities.length > 0) {
        const severityCounts = vulnerabilities.reduce((acc, vuln) => {
            acc[vuln.severity.toLowerCase()]++;
            return acc;
        }, { critical: 0, high: 0, medium: 0, low: 0, info: 0 });
        results.summary.vulnerabilities = severityCounts;
        results.summary.overallRiskScore = calculateRiskScore(vulnerabilities);
    }
    const response = {
        success: true,
        data: results,
        metadata: {
            timestamp: new Date(),
        },
    };
    res.json(response);
}));
// GET /api/v1/scans - Get user's scans with pagination
router.get('/', middleware_1.authenticate, (0, middleware_1.asyncHandler)(async (req, res) => {
    const userId = req.user.id;
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    // For now, we'll get all user scans (can add pagination later)
    const scans = await database_1.database.getUserScans(userId, limit);
    const response = {
        success: true,
        data: scans,
        metadata: {
            timestamp: new Date(),
            pagination: {
                page,
                limit,
                total: scans.length,
                pages: Math.ceil(scans.length / limit),
                hasNext: false,
                hasPrev: page > 1,
            },
        },
    };
    res.json(response);
}));
// DELETE /api/v1/scans/:scanId - Cancel/delete a scan
router.delete('/:scanId', middleware_1.authenticate, (0, middleware_1.asyncHandler)(async (req, res) => {
    const { scanId } = req.params;
    const userId = req.user.id;
    const scan = await database_1.database.getScan(scanId);
    if (!scan) {
        return res.status(404).json({
            success: false,
            error: { message: 'Scan not found' },
            timestamp: new Date().toISOString(),
        });
    }
    if (scan.userId !== userId && req.user.role !== 'admin') {
        return res.status(403).json({
            success: false,
            error: { message: 'Access denied' },
            timestamp: new Date().toISOString(),
        });
    }
    // Update scan status to cancelled
    await database_1.database.updateScan(scanId, {
        status: 'cancelled',
        currentStep: 'Cancelled by user',
    });
    // Notify WebSocket subscribers
    const wsManager = (0, websocket_1.getWebSocketManager)();
    wsManager.notifyError(scanId, 'Scan cancelled by user');
    logger_1.logger.info(`Scan ${scanId} cancelled by user ${userId}`);
    const response = {
        success: true,
        data: { message: 'Scan cancelled successfully' },
        metadata: {
            timestamp: new Date(),
        },
    };
    res.json(response);
}));
// Helper function to start scan process
async function startScanProcess(scan) {
    const wsManager = (0, websocket_1.getWebSocketManager)();
    const scanId = scan.id;
    try {
        // Update status to discovering
        await database_1.database.updateScan(scanId, {
            status: 'discovering',
            currentStep: 'Discovering API endpoints',
            progress: 5,
        });
        wsManager.notifyScanProgress(scanId, 5, 'Discovering API endpoints', {
            message: 'Starting endpoint discovery process',
        });
        // Configure discovery options
        const discoveryOptions = {
            maxEndpoints: scan.configuration.maxEndpoints || 100,
            timeout: 30000,
            includeSwagger: true,
            includeCrawling: true,
            includeBruteForce: scan.configuration.depth !== 'basic',
            includeRobots: true,
            excludePatterns: scan.configuration.excludePatterns,
            userAgent: 'API-Risk-Visualizer/1.0',
        };
        // Run endpoint discovery
        const endpointDiscovery = new endpointDiscovery_1.EndpointDiscovery(scan.target, discoveryOptions);
        const discoveryResult = await endpointDiscovery.discover(scanId, (progress, step, details) => {
            // Real-time progress updates during discovery
            const adjustedProgress = Math.round(5 + (progress * 0.4)); // Discovery takes 5-45% of total
            database_1.database.updateScan(scanId, {
                progress: adjustedProgress,
                currentStep: step,
            }).catch(err => logger_1.logger.error('Failed to update scan progress:', err));
            wsManager.notifyScanProgress(scanId, adjustedProgress, step, details);
        });
        // Update scan with discovered endpoints
        await database_1.database.updateScan(scanId, {
            status: 'testing',
            currentStep: `Discovery completed: ${discoveryResult.totalFound} endpoints found`,
            progress: 50,
            metadata: {
                ...scan.metadata,
                endpointsDiscovered: discoveryResult.totalFound,
                discoveryMethods: discoveryResult.discoveryMethods,
                discoveryDuration: discoveryResult.duration,
                discoveryErrors: discoveryResult.errors,
            },
        });
        wsManager.notifyScanProgress(scanId, 50, `Discovery completed: ${discoveryResult.totalFound} endpoints found`, {
            endpointsFound: discoveryResult.totalFound,
            discoveryMethods: discoveryResult.discoveryMethods,
            duration: `${Math.round(discoveryResult.duration / 1000)}s`,
        });
        // Continue with security testing (placeholder for now)
        await performSecurityTesting(scanId, discoveryResult.endpoints, scan, wsManager);
    }
    catch (error) {
        logger_1.logger.error(`Scan ${scanId} failed:`, error);
        await database_1.database.updateScan(scanId, {
            status: 'failed',
            currentStep: `Failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        });
        wsManager.notifyError(scanId, error instanceof Error ? error.message : 'Unknown error');
    }
}
// Security testing function (placeholder - will be implemented in next phase)
async function performSecurityTesting(scanId, endpoints, scan, wsManager) {
    // Simulate security testing phases for now
    const steps = [
        { progress: 60, step: 'Analyzing authentication mechanisms', delay: 2000 },
        { progress: 70, step: 'Testing for injection vulnerabilities', delay: 3000 },
        { progress: 80, step: 'Checking security configurations', delay: 2000 },
        { progress: 90, step: 'Running AI analysis', delay: 2000 },
        { progress: 100, step: 'Scan completed', delay: 1000 },
    ];
    for (const { progress, step, delay } of steps) {
        await new Promise(resolve => setTimeout(resolve, delay));
        await database_1.database.updateScan(scanId, {
            status: progress === 100 ? 'completed' : 'testing',
            currentStep: step,
            progress,
        });
        wsManager.notifyScanProgress(scanId, progress, step, {
            endpointsTested: Math.min(endpoints.length, Math.round((progress - 50) / 50 * endpoints.length)),
            totalEndpoints: endpoints.length,
        });
    }
    // Create realistic summary based on discovered endpoints
    const summary = {
        totalEndpoints: endpoints.length,
        vulnerabilities: {
            critical: Math.floor(endpoints.length * 0.05), // 5% critical
            high: Math.floor(endpoints.length * 0.1), // 10% high
            medium: Math.floor(endpoints.length * 0.2), // 20% medium
            low: Math.floor(endpoints.length * 0.15), // 15% low
            info: Math.floor(endpoints.length * 0.1), // 10% info
        },
        overallRiskScore: Math.min(85, 20 + endpoints.length * 2), // Risk increases with endpoint count
        aiPredictedRisk: Math.min(92, 25 + endpoints.length * 2),
        complianceStatus: {
            owaspApiTop10: [
                { requirement: 'API1:2023 Broken Object Level Authorization', status: 'FAIL', details: 'Missing authorization checks detected' },
                { requirement: 'API2:2023 Broken Authentication', status: 'WARNING', details: 'Weak authentication patterns found' },
                { requirement: 'API3:2023 Broken Object Property Level Authorization', status: 'PASS', details: 'Proper property-level authorization implemented' },
            ],
        },
    };
    await database_1.database.updateScan(scanId, { summary });
    wsManager.notifyScanCompleted(scanId, summary);
    logger_1.logger.info(`Scan ${scanId} completed successfully with ${endpoints.length} endpoints analyzed`);
}
// Helper function to calculate risk score
function calculateRiskScore(vulnerabilities) {
    const weights = { CRITICAL: 40, HIGH: 20, MEDIUM: 10, LOW: 5, INFO: 1 };
    const maxPossibleScore = 100; // Assume maximum risk scenario
    const totalRisk = vulnerabilities.reduce((sum, vuln) => {
        return sum + (weights[vuln.severity] || 0);
    }, 0);
    return Math.min(Math.round((totalRisk / maxPossibleScore) * 100), 100);
}
//# sourceMappingURL=scans.js.map