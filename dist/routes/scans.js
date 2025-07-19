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
const logger_1 = require("@utils/logger");
const endpointDiscovery_1 = require("../discovery/endpointDiscovery");
// n8n integration for notifications (using native fetch in Node.js 18+)
require("dotenv/config");
const globalAny = global;
if (!globalAny.scanStorage) {
    globalAny.scanStorage = new Map();
}
const scanStorage = globalAny.scanStorage;
const scanRoutes = (io) => {
    const router = (0, express_1.Router)();
    const scanTargetSchema = joi_1.default.object({
        baseUrl: joi_1.default.string().uri().required(),
        // other fields...
    });
    const scanConfigSchema = joi_1.default.object({
        depth: joi_1.default.string().valid('basic', 'comprehensive', 'deep').default('comprehensive'),
        includeAI: joi_1.default.boolean().default(true),
        testTypes: joi_1.default.array().items(joi_1.default.string()).optional(),
        maxEndpoints: joi_1.default.number().min(1).default(100),
        timeout: joi_1.default.number().min(60000).default(300000),
        concurrent: joi_1.default.boolean().default(true)
    });
    const createScanSchema = joi_1.default.object({
        target: scanTargetSchema.required(),
        scanConfig: scanConfigSchema.optional()
    });
    router.post('/', (0, middleware_1.validateRequest)(createScanSchema), (0, middleware_1.asyncHandler)(async (req, res) => {
        const { target, scanConfig } = req.body; // Ensure scanConfig is destructured
        const userId = 'mock-user-id'; // Mock user for now
        const scanId = (0, uuid_1.v4)();
        const scan = {
            id: scanId,
            userId,
            target: target,
            status: 'pending',
            progress: 0,
            currentStep: 'Initializing...',
            vulnerabilities: [],
            configuration: scanConfig || { depth: 'comprehensive', includeAI: true }, // Correctly use scanConfig
            metadata: {
                userAgent: req.get('User-Agent') || 'unknown',
                scannerVersion: process.env.npm_package_version || '1.0.0',
                startedAt: new Date(),
                endpointsDiscovered: 0,
                requestsSent: 0,
                aiAnalysisEnabled: scanConfig?.includeAI ?? true,
            }
        };
        scanStorage.set(scanId, scan);
        console.log('scanStorage keys after storing:', [...scanStorage.keys()]);
        // Acknowledge the request immediately
        res.status(202).json({ scanId, message: 'Scan initiated successfully.' });
        // Start the actual scan process asynchronously
        startFullScanProcess(scan, io);
    }));
    return router;
};
exports.scanRoutes = scanRoutes;
async function startFullScanProcess(scan, io) {
    const { id: scanId, target, configuration } = scan;
    const emitProgress = (progress, message, details = {}) => {
        io.to(scanId).emit('scan-update', { eventType: 'progress', data: { progress, message, ...details } });
        const scan = scanStorage.get(scanId);
        if (scan) {
            scan.progress = progress;
            scan.currentStep = message;
            scanStorage.set(scanId, scan);
        }
    };
    const emitEndpoint = (endpoint) => {
        io.to(scanId).emit('scan-update', { eventType: 'endpoint_discovered', data: { endpoint } });
    };
    const emitVulnerability = (vulnerability) => {
        io.to(scanId).emit('scan-update', { eventType: 'vulnerability_found', data: { vulnerability } });
        const scan = scanStorage.get(scanId);
        if (scan) {
            scan.vulnerabilities = scan.vulnerabilities || [];
            scan.vulnerabilities.push(vulnerability);
            scanStorage.set(scanId, scan);
        }
    };
    // This is where your real, complex scanning logic will go.
    // For now, we use a more realistic mock process.
    try {
        emitProgress(5, 'Starting endpoint discovery...');
        const discoveryOptions = {
            maxEndpoints: configuration?.maxEndpoints || 100,
            timeout: 20000,
            includeSwagger: true,
            includeCrawling: true,
            includeBruteForce: true,
        };
        const endpointDiscovery = new endpointDiscovery_1.EndpointDiscovery(target, discoveryOptions);
        const discovered = await endpointDiscovery.discover(scanId, (progress, step, details) => {
            const overallProgress = 5 + Math.round(progress * 0.4);
            emitProgress(overallProgress, step, details);
        }, emitEndpoint, // Pass the emitter function here
        emitVulnerability // Pass the new vulnerability emitter
        );
        emitProgress(45, `Discovery complete. Found ${discovered.totalFound} endpoints.`);
        // **FIX:** Emit each discovered endpoint so the frontend can update
        if (discovered.endpoints && discovered.endpoints.length > 0) {
            logger_1.logger.info(`Emitting ${discovered.endpoints.length} discovered endpoints to the client.`);
            discovered.endpoints.forEach(endpoint => {
                emitEndpoint(endpoint);
            });
        }
        // --- Placeholder for your other scanning modules ---
        // (Authentication, Parameter Fuzzing, etc.)
        await new Promise(res => setTimeout(res, 2000));
        emitProgress(60, "Testing Authentication...");
        await new Promise(res => setTimeout(res, 3000));
        emitProgress(80, "Analyzing for vulnerabilities...");
        // Mock finding a vulnerability
        if (discovered.endpoints.length > 0) {
            const vuln = { endpoint: discovered.endpoints[0].url, type: 'SQL_INJECTION', severity: 'HIGH', description: 'SQL Injection vulnerability found in login parameter.' };
            io.to(scanId).emit('scan-update', { eventType: 'vulnerability_found', data: { vulnerability: vuln } });
            // n8n integration for critical/high vulnerabilities
            if (vuln.severity === 'CRITICAL' || vuln.severity === 'HIGH') {
                fetch(process.env.WEBHOOK_URL, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        endpoint: vuln.endpoint,
                        type: vuln.type,
                        description: vuln.description
                    })
                }).catch(err => console.error('Failed to notify n8n:', err));
            }
            // The method doesn't exist, so we comment it out for now to prevent crash
            // await database.addVulnerability(scanId, vuln); 
        }
        await new Promise(res => setTimeout(res, 2000));
        emitProgress(100, "Scan complete!");
        io.to(scanId).emit('scan-update', { eventType: 'scan_complete', data: { message: 'Analysis finished.' } });
        const scan = scanStorage.get(scanId);
        if (scan) {
            scan.status = 'completed';
            scanStorage.set(scanId, scan);
        }
    }
    catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'An unknown error occurred';
        logger_1.logger.error(`Scan ${scanId} failed:`, error);
        io.to(scanId).emit('scan-update', { eventType: 'error', data: { message: errorMessage } });
        const scanErr = scanStorage.get(scanId);
        if (scanErr) {
            scanErr.status = 'failed';
            scanErr.currentStep = errorMessage;
            scanStorage.set(scanId, scanErr);
        }
    }
}
//# sourceMappingURL=scans.js.map