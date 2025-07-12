"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.reportRoutes = void 0;
const express_1 = require("express");
const uuid_1 = require("uuid");
const joi_1 = __importDefault(require("joi"));
const middleware_1 = require("@utils/middleware");
const database_1 = require("../core/database");
const logger_1 = require("@utils/logger");
const router = (0, express_1.Router)();
exports.reportRoutes = router;
// Validation schemas
const generateReportSchema = joi_1.default.object({
    format: joi_1.default.string().valid('pdf', 'html', 'json', 'csv').default('pdf'),
    template: joi_1.default.string().valid('executive_summary', 'technical_detailed', 'compliance_report', 'developer_guide').default('executive_summary'),
    includeAI: joi_1.default.boolean().default(true),
    sections: joi_1.default.array().items(joi_1.default.string().valid('summary', 'vulnerabilities', 'remediation', 'ai_insights', 'compliance', 'appendix')).default(['summary', 'vulnerabilities', 'remediation']),
});
// POST /api/v1/reports/:scanId - Generate a report for a scan
router.post('/:scanId', middleware_1.authenticate, (0, middleware_1.validateRequest)(generateReportSchema), (0, middleware_1.asyncHandler)(async (req, res) => {
    const { scanId } = req.params;
    const { format, template, includeAI, sections } = req.body;
    const userId = req.user.id;
    // Verify scan exists and user has access
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
    // Check if scan is completed
    if (scan.status !== 'completed') {
        return res.status(400).json({
            success: false,
            error: {
                message: 'Cannot generate report for incomplete scan',
                code: 'SCAN_NOT_COMPLETED',
            },
            timestamp: new Date().toISOString(),
        });
    }
    try {
        // Generate the report
        const reportId = (0, uuid_1.v4)();
        const reportData = await generateReport(scan, { format, template, includeAI, sections });
        // Calculate expiry date (30 days from now)
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + parseInt(process.env.REPORT_RETENTION_DAYS || '30'));
        // Save report metadata to database
        const report = {
            id: reportId,
            scanId,
            type: getReportTypeFromTemplate(template),
            format: format,
            template,
            sections,
            downloadUrl: `/api/v1/reports/${reportId}/download`,
            expiresAt,
            size: Buffer.byteLength(reportData, 'utf8'),
        };
        // In a real implementation, save the report file to storage
        // For now, we'll just store metadata and simulate file storage
        await saveReportToStorage(reportId, reportData, format);
        logger_1.logger.info(`Report generated for scan ${scanId}`, {
            reportId,
            format,
            template,
            userId,
            size: report.size,
        });
        const response = {
            success: true,
            data: {
                reportId,
                downloadUrl: report.downloadUrl,
                expiresAt: report.expiresAt,
                format: report.format,
                size: report.size,
            },
            metadata: {
                timestamp: new Date(),
            },
        };
        res.status(201).json(response);
    }
    catch (error) {
        logger_1.logger.error(`Failed to generate report for scan ${scanId}:`, error);
        res.status(500).json({
            success: false,
            error: {
                message: 'Report generation failed',
                details: error instanceof Error ? error.message : 'Unknown error',
            },
            timestamp: new Date().toISOString(),
        });
    }
}));
// GET /api/v1/reports/:reportId/download - Download a generated report
router.get('/:reportId/download', middleware_1.authenticate, (0, middleware_1.asyncHandler)(async (req, res) => {
    const { reportId } = req.params;
    const userId = req.user.id;
    try {
        // Get report metadata (in real implementation, this would be from database)
        const reportData = await getReportFromStorage(reportId);
        if (!reportData) {
            return res.status(404).json({
                success: false,
                error: { message: 'Report not found or expired' },
                timestamp: new Date().toISOString(),
            });
        }
        // Set appropriate headers for download
        const contentType = getContentTypeForFormat(reportData.format);
        const filename = `security-report-${reportId}.${reportData.format}`;
        res.setHeader('Content-Type', contentType);
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.setHeader('Content-Length', reportData.data.length);
        // Send the file
        res.send(reportData.data);
        logger_1.logger.info(`Report downloaded`, {
            reportId,
            userId,
            format: reportData.format,
            size: reportData.data.length,
        });
    }
    catch (error) {
        logger_1.logger.error(`Failed to download report ${reportId}:`, error);
        res.status(500).json({
            success: false,
            error: { message: 'Failed to download report' },
            timestamp: new Date().toISOString(),
        });
    }
}));
// GET /api/v1/reports/scan/:scanId - Get reports for a specific scan
router.get('/scan/:scanId', middleware_1.authenticate, (0, middleware_1.asyncHandler)(async (req, res) => {
    const { scanId } = req.params;
    const userId = req.user.id;
    // Verify scan access
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
    // Get reports for this scan (simulated - in real app, query database)
    const reports = await getScanReports(scanId);
    const response = {
        success: true,
        data: reports,
        metadata: {
            timestamp: new Date(),
        },
    };
    res.json(response);
}));
// DELETE /api/v1/reports/:reportId - Delete a report
router.delete('/:reportId', middleware_1.authenticate, (0, middleware_1.asyncHandler)(async (req, res) => {
    const { reportId } = req.params;
    const userId = req.user.id;
    try {
        // Verify report exists and user has access (simplified)
        const reportData = await getReportFromStorage(reportId);
        if (!reportData) {
            return res.status(404).json({
                success: false,
                error: { message: 'Report not found' },
                timestamp: new Date().toISOString(),
            });
        }
        // Delete report from storage
        await deleteReportFromStorage(reportId);
        logger_1.logger.info(`Report deleted`, {
            reportId,
            userId,
        });
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
}));
// Helper functions for report generation
async function generateReport(scan, options) {
    const { format, template, includeAI, sections } = options;
    // Load vulnerabilities
    const vulnerabilities = await database_1.database.getScanVulnerabilities(scan.id);
    // Generate report content based on format
    switch (format) {
        case 'json':
            return generateJSONReport(scan, vulnerabilities, options);
        case 'csv':
            return generateCSVReport(scan, vulnerabilities, options);
        case 'html':
            return generateHTMLReport(scan, vulnerabilities, options);
        case 'pdf':
            return generatePDFReport(scan, vulnerabilities, options);
        default:
            throw new Error(`Unsupported format: ${format}`);
    }
}
function generateJSONReport(scan, vulnerabilities, options) {
    const reportData = {
        reportMetadata: {
            generated: new Date().toISOString(),
            scanId: scan.id,
            template: options.template,
            sections: options.sections,
        },
        scanSummary: {
            target: scan.target.baseUrl,
            status: scan.status,
            startedAt: scan.metadata.startedAt,
            completedAt: scan.metadata.completedAt,
            duration: scan.metadata.duration,
            endpointsDiscovered: scan.metadata.endpointsDiscovered,
        },
        vulnerabilities: vulnerabilities.map(vuln => ({
            type: vuln.type,
            severity: vuln.severity,
            endpoint: vuln.endpoint,
            method: vuln.method,
            description: vuln.description,
            impact: vuln.impact,
            confidence: vuln.confidence,
            cwe: vuln.cwe,
            remediation: vuln.remediation,
            ...(options.includeAI && vuln.aiAnalysis && { aiAnalysis: vuln.aiAnalysis }),
        })),
        summary: scan.summary,
    };
    return JSON.stringify(reportData, null, 2);
}
function generateCSVReport(scan, vulnerabilities, options) {
    const headers = [
        'Type',
        'Severity',
        'Endpoint',
        'Method',
        'Description',
        'Impact',
        'Confidence',
        'CWE',
        'Remediation Priority',
    ];
    if (options.includeAI) {
        headers.push('AI Confidence', 'AI Predicted Exploitability');
    }
    const rows = vulnerabilities.map(vuln => {
        const row = [
            vuln.type,
            vuln.severity,
            vuln.endpoint,
            vuln.method,
            `"${vuln.description.replace(/"/g, '""')}"`,
            `"${vuln.impact.replace(/"/g, '""')}"`,
            vuln.confidence,
            vuln.cwe || '',
            vuln.remediation.priority || '',
        ];
        if (options.includeAI && vuln.aiAnalysis) {
            row.push(vuln.aiAnalysis.confidence || '', vuln.aiAnalysis.predictedExploitability || '');
        }
        return row.join(',');
    });
    return [headers.join(','), ...rows].join('\n');
}
function generateHTMLReport(scan, vulnerabilities, options) {
    const criticalCount = vulnerabilities.filter(v => v.severity === 'CRITICAL').length;
    const highCount = vulnerabilities.filter(v => v.severity === 'HIGH').length;
    const mediumCount = vulnerabilities.filter(v => v.severity === 'MEDIUM').length;
    const lowCount = vulnerabilities.filter(v => v.severity === 'LOW').length;
    return `
<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report - ${scan.target.baseUrl}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { border-bottom: 2px solid #333; padding-bottom: 10px; }
        .summary { background: #f5f5f5; padding: 15px; margin: 20px 0; }
        .vulnerability { border: 1px solid #ddd; margin: 10px 0; padding: 15px; }
        .critical { border-left: 5px solid #d32f2f; }
        .high { border-left: 5px solid #f57c00; }
        .medium { border-left: 5px solid #fbc02d; }
        .low { border-left: 5px solid #388e3c; }
        .severity { font-weight: bold; text-transform: uppercase; }
        .remediation { background: #e3f2fd; padding: 10px; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>API Security Scan Report</h1>
        <p><strong>Target:</strong> ${scan.target.baseUrl}</p>
        <p><strong>Scan Date:</strong> ${new Date(scan.metadata.startedAt).toLocaleString()}</p>
        <p><strong>Report Generated:</strong> ${new Date().toLocaleString()}</p>
    </div>

    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Total Vulnerabilities:</strong> ${vulnerabilities.length}</p>
        <ul>
            <li>Critical: ${criticalCount}</li>
            <li>High: ${highCount}</li>
            <li>Medium: ${mediumCount}</li>
            <li>Low: ${lowCount}</li>
        </ul>
        <p><strong>Overall Risk Score:</strong> ${scan.summary?.overallRiskScore || 'N/A'}</p>
        ${options.includeAI ? `<p><strong>AI Predicted Risk:</strong> ${scan.summary?.aiPredictedRisk || 'N/A'}</p>` : ''}
    </div>

    <h2>Vulnerabilities</h2>
    ${vulnerabilities.map(vuln => `
        <div class="vulnerability ${vuln.severity.toLowerCase()}">
            <h3>${vuln.type} <span class="severity">(${vuln.severity})</span></h3>
            <p><strong>Endpoint:</strong> ${vuln.method} ${vuln.endpoint}</p>
            <p><strong>Description:</strong> ${vuln.description}</p>
            <p><strong>Impact:</strong> ${vuln.impact}</p>
            <p><strong>Confidence:</strong> ${Math.round(vuln.confidence * 100)}%</p>
            ${vuln.cwe ? `<p><strong>CWE:</strong> ${vuln.cwe}</p>` : ''}
            ${options.includeAI && vuln.aiAnalysis ? `
                <div style="background: #fff3e0; padding: 10px; margin: 10px 0;">
                    <strong>AI Analysis:</strong><br>
                    <em>${vuln.aiAnalysis.patternMatch}</em><br>
                    <strong>Business Impact:</strong> ${vuln.aiAnalysis.businessImpact}
                </div>
            ` : ''}
            <div class="remediation">
                <strong>Remediation:</strong>
                <ol>
                    ${vuln.remediation.steps.map((step) => `<li>${step}</li>`).join('')}
                </ol>
            </div>
        </div>
    `).join('')}
</body>
</html>
  `.trim();
}
function generatePDFReport(scan, vulnerabilities, options) {
    // For demo purposes, return HTML that would be converted to PDF
    // In a real implementation, use puppeteer or similar to generate actual PDF
    return `PDF Report Generation - Would use Puppeteer to convert HTML to PDF
  
Scan Report for: ${scan.target.baseUrl}
Generated: ${new Date().toISOString()}
Vulnerabilities Found: ${vulnerabilities.length}

This would be a properly formatted PDF document with:
- Executive summary
- Detailed vulnerability listings
- Remediation guidance
- Charts and graphs
- AI insights (if enabled)
  `;
}
// Storage helper functions (simplified - in real app, use proper file storage)
const reportStorage = new Map();
async function saveReportToStorage(reportId, data, format) {
    reportStorage.set(reportId, {
        data,
        format,
        createdAt: new Date(),
    });
}
async function getReportFromStorage(reportId) {
    const report = reportStorage.get(reportId);
    if (!report)
        return null;
    // Check if expired (30 days)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    if (report.createdAt < thirtyDaysAgo) {
        reportStorage.delete(reportId);
        return null;
    }
    return { data: report.data, format: report.format };
}
async function deleteReportFromStorage(reportId) {
    reportStorage.delete(reportId);
}
async function getScanReports(scanId) {
    // Simplified - in real app, query database
    const reports = [];
    reportStorage.forEach((report, reportId) => {
        reports.push({
            id: reportId,
            scanId,
            type: 'technical',
            format: report.format,
            template: 'executive_summary',
            sections: ['summary', 'vulnerabilities'],
            generatedAt: report.createdAt,
            downloadUrl: `/api/v1/reports/${reportId}/download`,
            expiresAt: new Date(report.createdAt.getTime() + 30 * 24 * 60 * 60 * 1000),
            size: report.data.length,
        });
    });
    return reports;
}
function getReportTypeFromTemplate(template) {
    switch (template) {
        case 'executive_summary': return 'executive';
        case 'technical_detailed': return 'technical';
        case 'compliance_report': return 'compliance';
        case 'developer_guide': return 'developer';
        default: return 'technical';
    }
}
function getContentTypeForFormat(format) {
    switch (format) {
        case 'pdf': return 'application/pdf';
        case 'html': return 'text/html';
        case 'json': return 'application/json';
        case 'csv': return 'text/csv';
        default: return 'application/octet-stream';
    }
}
//# sourceMappingURL=reports.js.map