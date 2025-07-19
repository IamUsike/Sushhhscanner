"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.reportRoutes = void 0;
const express_1 = require("express");
const uuid_1 = require("uuid");
const joi_1 = __importDefault(require("joi"));
const logger_1 = require("@utils/logger");
// Use the global scanStorage
const globalAny = global;
if (!globalAny.scanStorage) {
    globalAny.scanStorage = new Map();
}
const scanStorage = globalAny.scanStorage;
// Simplified in-memory storage for generated reports (temporary)
const reportFileStorage = new Map(); // Added createdAt
const router = (0, express_1.Router)();
exports.reportRoutes = router;
// Middleware to mock authentication for development
router.use((req, res, next) => {
    // Only mock if req.user is not already set by actual auth middleware (if present)
    if (!req.user) {
        req.user = { id: 'mock-user-id', email: 'mock@example.com', role: 'admin' }; // Added email
    }
    next();
});
// Validation schema for report generation
const generateReportSchema = joi_1.default.object({
    format: joi_1.default.string().valid('json', 'csv', 'pdf').required(), // Added PDF support
});
// POST /api/v1/reports/:scanId - Generate a report for a scan
router.post('/:scanId', async (req, res) => {
    // Manual validation
    const { error, value } = generateReportSchema.validate(req.body);
    if (error) {
        logger_1.logger.warn(`Report generation validation error: ${error.details.map(x => x.message).join(', ')}`);
        return res.status(400).json({
            success: false,
            error: {
                message: 'Invalid request payload',
                details: error.details.map(x => x.message),
            },
            timestamp: new Date().toISOString(),
        });
    }
    const { format } = value; // Use validated value
    const { scanId } = req.params;
    const userId = req.user?.id || 'anonymous'; // Use mock user id
    logger_1.logger.info(`Attempting to generate ${format} report for scan: ${scanId} by user: ${userId}`);
    // Verify scan exists and is completed
    const scan = scanStorage.get(scanId);
    if (!scan) {
        logger_1.logger.warn(`Scan ${scanId} not found in storage.`);
        return res.status(404).json({
            success: false,
            error: { message: 'Scan not found or has not completed yet' },
            timestamp: new Date().toISOString(),
        });
    }
    if (scan.status !== 'completed') {
        logger_1.logger.warn(`Scan ${scanId} status is ${scan.status}, not completed.`);
        return res.status(400).json({
            success: false,
            error: {
                message: 'Cannot generate report for incomplete scan. Please wait for scan to finish.',
                code: 'SCAN_NOT_COMPLETED',
            },
            timestamp: new Date().toISOString(),
        });
    }
    try {
        let reportData;
        let contentType;
        const reportId = (0, uuid_1.v4)(); // Unique ID for this report instance
        switch (format) {
            case 'json':
                reportData = generateJSONReport(scan);
                contentType = 'application/json';
                break;
            case 'csv':
                reportData = generateCSVReport(scan);
                contentType = 'text/csv';
                break;
            case 'pdf':
                const { PDFReportGenerator } = await Promise.resolve().then(() => __importStar(require('../ai/pdfReportGenerator')));
                // Use Gemini by default, can be configured via environment variable
                const llmProvider = process.env.LLM_PROVIDER || 'gemini';
                const pdfGenerator = new PDFReportGenerator(llmProvider);
                const pdfBuffer = await pdfGenerator.generatePDFReport(scan);
                reportData = pdfBuffer.toString('base64');
                contentType = 'application/pdf';
                break;
            default:
                return res.status(400).json({
                    success: false,
                    error: { message: 'Unsupported report format' },
                    timestamp: new Date().toISOString(),
                });
        }
        // Store the generated report data in memory for download
        reportFileStorage.set(reportId, { data: reportData, format, contentType, createdAt: new Date() }); // Storing createdAt
        const downloadUrl = `/api/v1/reports/${reportId}/download`;
        logger_1.logger.info(`Report generated for scan ${scanId} in format ${format}`, { reportId, downloadUrl });
        const response = {
            success: true,
            data: {
                reportId,
                downloadUrl,
                format,
                size: Buffer.byteLength(reportData, 'utf8'),
            },
            metadata: {
                timestamp: new Date(),
            },
        };
        res.status(201).json(response);
    }
    catch (error) {
        logger_1.logger.error(`Failed to generate ${format} report for scan ${scanId}:`, error);
        res.status(500).json({
            success: false,
            error: {
                message: 'Report generation failed',
                details: error instanceof Error ? error.message : 'Unknown error',
            },
            timestamp: new Date().toISOString(),
        });
    }
});
// GET /api/v1/reports/:reportId/download - Download a generated report
router.get('/:reportId/download', async (req, res) => {
    const { reportId } = req.params;
    const userId = req.user?.id || 'anonymous'; // Use mock user id
    logger_1.logger.info(`Attempting to download report ${reportId} by user: ${userId}`);
    try {
        const report = reportFileStorage.get(reportId);
        if (!report) {
            logger_1.logger.warn(`Report ${reportId} not found in file storage.`);
            return res.status(404).json({
                success: false,
                error: { message: 'Report not found or expired' },
                timestamp: new Date().toISOString(),
            });
        }
        res.setHeader('Content-Type', report.contentType);
        res.setHeader('Content-Disposition', `attachment; filename="security-report-${reportId}.${report.format}"`);
        res.send(report.data);
        logger_1.logger.info(`Report ${reportId} downloaded successfully.`);
    }
    catch (error) {
        logger_1.logger.error(`Failed to download report ${reportId}:`, error);
        res.status(500).json({
            success: false,
            error: { message: 'Failed to download report' },
            timestamp: new Date().toISOString(),
        });
    }
});
// GET /api/v1/reports/scan/:scanId - Get reports for a specific scan
router.get('/scan/:scanId', async (req, res) => {
    const { scanId } = req.params;
    const userId = req.user?.id || 'anonymous'; // Use mock user id
    logger_1.logger.info(`Attempting to get reports for scan ${scanId} by user: ${userId}`);
    try {
        const scan = scanStorage.get(scanId);
        if (!scan) {
            logger_1.logger.warn(`Scan ${scanId} not found in storage.`);
            return res.status(404).json({
                success: false,
                error: { message: 'Scan not found' },
                timestamp: new Date().toISOString(),
            });
        }
        if (scan.userId !== userId && req.user?.role !== 'admin') {
            logger_1.logger.warn(`User ${userId} does not have access to scan ${scanId}.`);
            return res.status(403).json({
                success: false,
                error: { message: 'Access denied' },
                timestamp: new Date().toISOString(),
            });
        }
        // Get reports for this scan (simulated - in real app, query database)
        const reports = []; // Placeholder for actual report data
        reportFileStorage.forEach((report, reportId) => {
            // Check if report belongs to this scan
            // For now, assuming all reports in reportFileStorage are relevant if no scanId is stored with them
            // In a real app, reportFileStorage would be keyed by scanId or have scanId in its value
            // To fix this simply: if (report.scanId === scanId) {
            reports.push({
                id: reportId,
                scanId, // Use the scanId from the request
                type: 'technical', // Placeholder type
                format: report.format,
                template: 'executive_summary', // Placeholder template
                sections: ['summary', 'vulnerabilities'], // Placeholder sections
                generatedAt: report.createdAt, // Use createdAt from reportFileStorage
                downloadUrl: `/api/v1/reports/${reportId}/download`,
                expiresAt: new Date(report.createdAt.getTime() + 30 * 24 * 60 * 60 * 1000), // 30 days from now
                size: report.data.length,
            });
        });
        const response = {
            success: true,
            data: reports,
            metadata: {
                timestamp: new Date(),
            },
        };
        res.json(response);
        logger_1.logger.info(`Reports for scan ${scanId} retrieved successfully.`);
    }
    catch (error) {
        logger_1.logger.error(`Failed to get reports for scan ${scanId}:`, error);
        res.status(500).json({
            success: false,
            error: { message: 'Failed to get reports' },
            timestamp: new Date().toISOString(),
        });
    }
});
// DELETE /api/v1/reports/:reportId - Delete a report
router.delete('/:reportId', async (req, res) => {
    const { reportId } = req.params;
    const userId = req.user?.id || 'anonymous'; // Use mock user id
    logger_1.logger.info(`Attempting to delete report ${reportId} by user: ${userId}`);
    try {
        const report = reportFileStorage.get(reportId);
        if (!report) {
            logger_1.logger.warn(`Report ${reportId} not found in file storage.`);
            return res.status(404).json({
                success: false,
                error: { message: 'Report not found or expired' },
                timestamp: new Date().toISOString(),
            });
        }
        reportFileStorage.delete(reportId);
        logger_1.logger.info(`Report ${reportId} deleted successfully.`);
        const response = {
            success: true,
            data: { message: 'Report deleted successfully' },
            metadata: {
                timestamp: new Date(),
            },
        };
        res.json(response);
    }
    catch (error) {
        logger_1.logger.error(`Failed to delete report ${reportId}:`, error);
        res.status(500).json({
            success: false,
            error: { message: 'Failed to delete report' },
            timestamp: new Date().toISOString(),
        });
    }
});
// Helper function to generate JSON report
function generateJSONReport(scan) {
    const reportData = {
        reportMetadata: {
            generated: new Date().toISOString(),
            scanId: scan.id,
            format: 'json',
            // Include other relevant scan metadata if available
        },
        scanSummary: {
            target: scan.target?.baseUrl || 'N/A',
            status: scan.status,
            startedAt: scan.metadata?.startedAt,
            completedAt: scan.metadata?.completedAt,
            duration: scan.metadata?.duration,
            endpointsDiscovered: scan.metadata?.endpointsDiscovered,
            vulnerabilitiesCount: scan.vulnerabilities?.length || 0,
            overallRiskScore: scan.summary?.overallRiskScore || 0,
        },
        vulnerabilities: scan.vulnerabilities?.map((vuln) => ({
            id: vuln.id,
            type: vuln.type,
            severity: vuln.severity,
            endpoint: vuln.endpoint,
            method: vuln.method,
            description: vuln.description,
            impact: vuln.impact,
            confidence: vuln.confidence,
            cwe: vuln.cwe || '',
            remediation: vuln.remediation || {}, // Ensure remediation exists
            aiAnalysis: vuln.aiAnalysis || {},
        })) || [],
    };
    return JSON.stringify(reportData, null, 2);
}
// Helper function to generate CSV report
function generateCSVReport(scan) {
    const headers = [
        'ID', 'Type', 'Severity', 'Endpoint', 'Method', 'Description', 'Impact',
        'Confidence', 'CWE', 'Remediation Priority', 'Remediation Steps', 'Remediation Resources',
    ];
    const rows = (scan.vulnerabilities || []).map((vuln) => {
        const remediation = vuln.remediation || {};
        const steps = (remediation.steps || []).join(' | '); // Join steps with a pipe
        const resources = (remediation.resources || []).join(' | '); // Join resources with a pipe
        return [
            vuln.id,
            vuln.type,
            vuln.severity,
            vuln.endpoint,
            vuln.method,
            `"${vuln.description.replace(/"/g, '""')}"`, // Escape quotes for CSV
            `"${vuln.impact.replace(/"/g, '""')}"`,
            vuln.confidence,
            vuln.cwe || '',
            remediation.priority || '',
            `"${steps.replace(/"/g, '""')}"`,
            `"${resources.replace(/"/g, '""')}"`,
        ].map(item => (typeof item === 'string' && item.includes(',') ? `"${item}"` : item)).join(','); // Ensure commas in fields are quoted
    });
    return [headers.join(','), ...rows].join('\n');
}
//# sourceMappingURL=reports.js.map