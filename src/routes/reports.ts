import express from 'express';
import { generateDetailedPDFReport } from '../ai/pdfReportGenerator';
import { logger } from '../utils/logger';

const router = express.Router();

// In-memory storage for generated reports (for demo purposes)
const reportStore: Record<string, { data: Buffer, filename: string, mime: string }> = {};

// Generate PDF report
router.post('/generate-pdf', async (req, res) => {
    try {
        const scanData = req.body;
        
        if (!scanData) {
            return res.status(400).json({
                success: false,
                message: 'Scan data is required'
            });
        }

        logger.info('Generating detailed PDF report', {
            scanId: scanData.scanId,
            vulnerabilityCount: scanData.vulnerabilities?.length || 0
        });

        // Prepare scan data for PDF generation
        const pdfScanData = {
            scanId: scanData.scanId || `scan-${Date.now()}`,
            target: scanData.target || scanData.targetUrl || 'Unknown Target',
            startTime: scanData.startTime || new Date().toISOString(),
            endTime: scanData.endTime || new Date().toISOString(),
            duration: scanData.duration || 0,
            vulnerabilities: Array.isArray(scanData.vulnerabilities) ? scanData.vulnerabilities : [],
            endpointsDiscovered: scanData.endpointsDiscovered || scanData.endpoints?.length || 0,
            totalRiskScore: scanData.totalRiskScore || 0,
            cvssScore: scanData.cvssScore || 0,
            scanProgress: scanData.scanProgress,
            mlMetrics: scanData.mlMetrics
        };

        // Generate PDF
        const pdfBytes = await generateDetailedPDFReport(pdfScanData);
        
        // Convert to base64 for transmission
        const base64PDF = Buffer.from(pdfBytes).toString('base64');
        
        logger.info('PDF report generated successfully', {
            scanId: pdfScanData.scanId,
            pdfSize: pdfBytes.length,
            base64Size: base64PDF.length
        });

        res.json({
            success: true,
            message: 'PDF report generated successfully',
            report: {
                data: base64PDF,
                filename: `security-report-${pdfScanData.scanId}.pdf`,
                size: pdfBytes.length
            }
        });

    } catch (error) {
        logger.error('PDF generation failed:', {
            message: error.message,
            stack: error.stack
        });
        
        res.status(500).json({
            success: false,
            message: 'Failed to generate PDF report',
            error: error.message
        });
    }
});

// Generate JSON report
router.post('/generate-json', async (req, res) => {
    try {
        const scanData = req.body;
        if (!scanData) {
            return res.status(400).json({
                success: false,
                message: 'Scan data is required'
            });
        }
        logger.info('Generating JSON report', {
            scanId: scanData.scanId,
            vulnerabilityCount: scanData.vulnerabilities?.length || 0
        });
        const jsonString = JSON.stringify(scanData, null, 2);
        const base64JSON = Buffer.from(jsonString).toString('base64');
        res.json({
            success: true,
            message: 'JSON report generated successfully',
            report: {
                data: base64JSON,
                filename: `security-report-${scanData.scanId || Date.now()}.json`,
                size: jsonString.length
            }
        });
    } catch (error) {
        logger.error('JSON report generation failed:', {
            message: error.message,
            stack: error.stack
        });
        res.status(500).json({
            success: false,
            message: 'Failed to generate JSON report',
            error: error.message
        });
    }
});

// Generate CSV report
router.post('/generate-csv', async (req, res) => {
    try {
        const scanData = req.body;
        if (!scanData || !Array.isArray(scanData.vulnerabilities)) {
            return res.status(400).json({
                success: false,
                message: 'Scan data with vulnerabilities array is required'
            });
        }
        logger.info('Generating CSV report', {
            scanId: scanData.scanId,
            vulnerabilityCount: scanData.vulnerabilities.length
        });
        // CSV header
        let csv = 'Type,Severity,Endpoint,Method,Description,CWE,CVSS,Timestamp\n';
        scanData.vulnerabilities.forEach(vuln => {
            csv += `"${vuln.type}","${vuln.severity}","${vuln.endpoint}","${vuln.method || ''}","${(vuln.description || '').replace(/"/g, '""')}","${vuln.cwe || ''}","${vuln.cvss || ''}","${vuln.timestamp || ''}"\n`;
        });
        const base64CSV = Buffer.from(csv).toString('base64');
        res.json({
            success: true,
            message: 'CSV report generated successfully',
            report: {
                data: base64CSV,
                filename: `security-report-${scanData.scanId || Date.now()}.csv`,
                size: csv.length
            }
        });
    } catch (error) {
        logger.error('CSV report generation failed:', {
            message: error.message,
            stack: error.stack
        });
        res.status(500).json({
            success: false,
            message: 'Failed to generate CSV report',
            error: error.message
        });
    }
});

// Dynamic report generation endpoint
router.post('/:scanId', async (req, res) => {
    try {
        const { scanId } = req.params;
        const { format } = req.body;
        if (!format || !['json', 'csv', 'pdf'].includes(format)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid or missing report format'
            });
        }
        // For demo, expect scan data in body (in real app, fetch from DB)
        const scanData = req.body.scanData || req.body.data || req.body;
        let fileBuffer, filename, mime;
        if (format === 'json') {
            const jsonString = JSON.stringify(scanData, null, 2);
            fileBuffer = Buffer.from(jsonString);
            filename = `security-report-${scanId}.json`;
            mime = 'application/json';
        } else if (format === 'csv') {
            if (!Array.isArray(scanData.vulnerabilities)) {
                return res.status(400).json({
                    success: false,
                    message: 'Scan data with vulnerabilities array is required for CSV'
                });
            }
            let csv = 'Type,Severity,Endpoint,Method,Description,CWE,CVSS,Timestamp\n';
            scanData.vulnerabilities.forEach(vuln => {
                csv += `"${vuln.type}","${vuln.severity}","${vuln.endpoint}","${vuln.method || ''}","${(vuln.description || '').replace(/"/g, '""')}","${vuln.cwe || ''}","${vuln.cvss || ''}","${vuln.timestamp || ''}"\n`;
            });
            fileBuffer = Buffer.from(csv);
            filename = `security-report-${scanId}.csv`;
            mime = 'text/csv';
        } else if (format === 'pdf') {
            // Use the existing PDF generator
            const { generateDetailedPDFReport } = require('../ai/pdfReportGenerator');
            fileBuffer = await generateDetailedPDFReport(scanData);
            filename = `security-report-${scanId}.pdf`;
            mime = 'application/pdf';
        }
        // Store in memory for download
        const key = `${scanId}.${format}`;
        reportStore[key] = { data: fileBuffer, filename, mime };
        // Return download URL
        res.json({
            success: true,
            data: {
                downloadUrl: `/api/v1/reports/download/${scanId}.${format}`,
                filename,
                size: fileBuffer.length
            }
        });
    } catch (error) {
        logger.error('Dynamic report generation failed:', {
            message: error.message,
            stack: error.stack
        });
        res.status(500).json({
            success: false,
            message: 'Failed to generate report',
            error: error.message
        });
    }
});

// Download endpoint for generated reports
router.get('/download/:file', (req, res) => {
    const { file } = req.params;
    const report = reportStore[file];
    if (!report) {
        return res.status(404).json({
            success: false,
            message: 'Report not found. Please generate a new report.'
        });
    }
    res.setHeader('Content-Disposition', `attachment; filename="${report.filename}"`);
    res.setHeader('Content-Type', report.mime);
    res.send(report.data);
});

export default router; 