import express from 'express';
import { generateDetailedPDFReport } from '../ai/pdfReportGenerator';
import { logger } from '../utils/logger';

const router = express.Router();

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

// Download PDF report
router.get('/download/:scanId', async (req, res) => {
    try {
        const { scanId } = req.params;
        
        // For now, we'll return a placeholder since we need the full scan data
        // In a real implementation, you'd fetch the scan data from your database
        res.status(404).json({
            success: false,
            message: 'Report not found. Please generate a new report with scan data.'
        });
        
    } catch (error) {
        logger.error('PDF download failed:', {
            message: error.message,
            stack: error.stack
        });
        
        res.status(500).json({
            success: false,
            message: 'Failed to download PDF report',
            error: error.message
        });
    }
});

export default router; 