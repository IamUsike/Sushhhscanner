import { Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import Joi from 'joi';
import { validateRequest, asyncHandler } from '@utils/middleware';
import { database } from '../core/database';
import { logger } from '@utils/logger';
import { Scan, ScanTarget, APIResponse } from '@/types';
import { EndpointDiscovery, DiscoveryOptions } from '../discovery/endpointDiscovery';
import { Server as SocketIOServer } from 'socket.io';

export const scanRoutes = (io: SocketIOServer) => {
const router = Router();

const scanTargetSchema = Joi.object({
  baseUrl: Joi.string().uri().required(),
        // other fields...
});

const scanConfigSchema = Joi.object({
  depth: Joi.string().valid('basic', 'comprehensive', 'deep').default('comprehensive'),
  includeAI: Joi.boolean().default(true),
        testTypes: Joi.array().items(Joi.string()).optional(),
        maxEndpoints: Joi.number().min(1).default(100),
        timeout: Joi.number().min(60000).default(300000),
        concurrent: Joi.boolean().default(true)
});

const createScanSchema = Joi.object({
  target: scanTargetSchema.required(),
        scanConfig: scanConfigSchema.optional()
});

router.post('/', 
  validateRequest(createScanSchema),
  asyncHandler(async (req, res) => {
        const { target, scanConfig } = req.body; // Ensure scanConfig is destructured
        const userId = 'mock-user-id'; // Mock user for now
        const scanId = uuidv4();
        
    const scan: Omit<Scan, 'createdAt' | 'updatedAt'> = {
      id: scanId,
      userId,
      target: target as ScanTarget,
      status: 'pending',
      progress: 0,
          currentStep: 'Initializing...',
      vulnerabilities: [],
          configuration: scanConfig || { depth: 'comprehensive', includeAI: true }, // Correctly use scanConfig
          metadata: { // Add all required metadata properties
        userAgent: req.get('User-Agent') || 'unknown',
        scannerVersion: process.env.npm_package_version || '1.0.0',
        startedAt: new Date(),
        endpointsDiscovered: 0,
        requestsSent: 0,
        aiAnalysisEnabled: scanConfig?.includeAI ?? true,
          }
    };

    await database.createScan(scan);

        // Acknowledge the request immediately
        res.status(202).json({ scanId, message: 'Scan initiated successfully.' });

        // Start the actual scan process asynchronously
        startFullScanProcess(scan, io);
      })
    );
    return router;
};

async function startFullScanProcess(scan: Omit<Scan, 'createdAt' | 'updatedAt'>, io: SocketIOServer): Promise<void> {
    const { id: scanId, target, configuration } = scan;

    const emitProgress = (progress, message, details = {}) => {
        io.to(scanId).emit('scan-update', { eventType: 'progress', data: { progress, message, ...details } });
        database.updateScan(scanId, { progress, currentStep: message });
    };

    const emitEndpoint = (endpoint) => {
        io.to(scanId).emit('scan-update', { eventType: 'endpoint_discovered', data: { endpoint }});
    };
    
    // This is where your real, complex scanning logic will go.
    // For now, we use a more realistic mock process.
    try {
        emitProgress(5, 'Starting endpoint discovery...');
        
    const discoveryOptions: DiscoveryOptions = {
            maxEndpoints: configuration?.maxEndpoints || 100,
            timeout: 20000,
      includeSwagger: true,
      includeCrawling: true,
            includeBruteForce: true,
        };

        const endpointDiscovery = new EndpointDiscovery(target, discoveryOptions);
        const discovered = await endpointDiscovery.discover(
            scanId,
            (progress, step, details) => {
                const overallProgress = 5 + Math.round(progress * 0.4);
                emitProgress(overallProgress, step, details);
            },
            emitEndpoint // Pass the emitter function here
        );

        emitProgress(45, `Discovery complete. Found ${discovered.totalFound} endpoints.`);
        
        // **FIX:** Emit each discovered endpoint so the frontend can update
        if (discovered.endpoints && discovered.endpoints.length > 0) {
            logger.info(`Emitting ${discovered.endpoints.length} discovered endpoints to the client.`);
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
            // The method doesn't exist, so we comment it out for now to prevent crash
            // await database.addVulnerability(scanId, vuln); 
        }

        await new Promise(res => setTimeout(res, 2000));
        emitProgress(100, "Scan complete!");
        
        io.to(scanId).emit('scan-update', { eventType: 'scan_complete', data: { message: 'Analysis finished.' } });
        database.updateScan(scanId, { status: 'completed' });

    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'An unknown error occurred';
        logger.error(`Scan ${scanId} failed:`, error);
        io.to(scanId).emit('scan-update', { eventType: 'error', data: { message: errorMessage } });
        database.updateScan(scanId, { status: 'failed', currentStep: errorMessage });
    }
} 