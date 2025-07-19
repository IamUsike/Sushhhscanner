import { Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import Joi from 'joi';
import { logger } from '@utils/logger';
import { APIResponse } from '@/types';

// Use the global scanStorage
const globalAny = global as any;
if (!globalAny.scanStorage) {
  globalAny.scanStorage = new Map();
}
const scanStorage = globalAny.scanStorage;

// Simplified in-memory storage for generated reports (temporary)
const reportFileStorage = new Map<string, { data: string; format: string; contentType: string; createdAt: Date }>(); // Added createdAt

const router = Router();

// Middleware to mock authentication for development
router.use((req, res, next) => {
  // Only mock if req.user is not already set by actual auth middleware (if present)
  if (!req.user) {
    req.user = { id: 'mock-user-id', email: 'mock@example.com', role: 'admin' }; // Added email
  }
  next();
});

// Validation schema for report generation
const generateReportSchema = Joi.object({
  format: Joi.string().valid('json', 'csv', 'pdf').required(), // Added PDF support
});

// POST /api/v1/reports/:scanId - Generate a report for a scan
router.post('/:scanId',
  async (req, res) => {
    // Manual validation
    const { error, value } = generateReportSchema.validate(req.body);
    if (error) {
      logger.warn(`Report generation validation error: ${error.details.map(x => x.message).join(', ')}`);
      return res.status(400).json({
        success: false,
        error: {
          message: 'Invalid request payload',
          details: error.details.map(x => x.message),
        },
        timestamp: new Date().toISOString(),
      } as APIResponse);
    }
    const { format } = value; // Use validated value

    const { scanId } = req.params;
    const userId = req.user?.id || 'anonymous'; // Use mock user id

    logger.info(`Attempting to generate ${format} report for scan: ${scanId} by user: ${userId}`);

    // Verify scan exists and is completed
    const scan = scanStorage.get(scanId);
    if (!scan) {
      logger.warn(`Scan ${scanId} not found in storage.`);
      return res.status(404).json({
        success: false,
        error: { message: 'Scan not found or has not completed yet' },
        timestamp: new Date().toISOString(),
      } as APIResponse);
    }

    if (scan.status !== 'completed') {
      logger.warn(`Scan ${scanId} status is ${scan.status}, not completed.`);
      return res.status(400).json({
        success: false,
        error: { 
          message: 'Cannot generate report for incomplete scan. Please wait for scan to finish.',
          code: 'SCAN_NOT_COMPLETED',
        },
        timestamp: new Date().toISOString(),
      } as APIResponse);
    }

    try {
      let reportData: string;
      let contentType: string;
      const reportId = uuidv4(); // Unique ID for this report instance

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
          try {
            const { PDFReportGenerator } = await import('../ai/pdfReportGenerator');
            // Use Gemini by default, can be configured via environment variable
            const llmProvider = (process.env.LLM_PROVIDER as 'gemini' | 'groq') || 'gemini';
            const pdfGenerator = new PDFReportGenerator(llmProvider);
            
            // Check if scan data was passed in the request body
            const passedScanData = req.body.scanData || scan;

            // Log the scan data for debugging
            logger.info('PDF Generation - Scan Data:', JSON.stringify({
              id: passedScanData.id,
              target: passedScanData.target,
              vulnerabilitiesCount: passedScanData.vulnerabilities?.length || 0,
              endpointsCount: passedScanData.endpoints?.length || 0
            }, null, 2));

            // Validate scan data
            if (!passedScanData) {
              throw new Error('No scan data provided for PDF generation');
            }

            // Ensure vulnerabilities exist
            if (!passedScanData.vulnerabilities || passedScanData.vulnerabilities.length === 0) {
              // Create a minimal report with a message if no vulnerabilities
              passedScanData.vulnerabilities = [{
                type: 'NO_VULNERABILITIES',
                severity: 'INFO',
                description: 'No vulnerabilities were detected during the scan.',
                endpoint: passedScanData.target?.baseUrl || 'Unknown Target'
              }];
            }

            const pdfBuffer = await pdfGenerator.generatePDFReport(passedScanData);
            
            // Additional PDF validation
            if (!pdfBuffer || pdfBuffer.length === 0) {
              throw new Error('Generated PDF buffer is empty');
            }

            // Log PDF buffer details for verification
            logger.info(`PDF Generation - Buffer Details`, {
              bufferSize: pdfBuffer.length,
              base64Length: pdfBuffer.toString('base64').length
            });

            reportData = pdfBuffer.toString('base64');
            contentType = 'application/pdf';
          } catch (pdfError) {
            logger.error('PDF Generation Error:', {
              message: pdfError.message,
              stack: pdfError.stack,
              name: pdfError.name,
              scanId: req.params.scanId
            });
            throw pdfError; // Re-throw to be caught by the outer catch block
          }
          break;
        default:
          return res.status(400).json({
            success: false,
            error: { message: 'Unsupported report format' },
            timestamp: new Date().toISOString(),
          } as APIResponse);
      }

      // Store the generated report data in memory for download
      reportFileStorage.set(reportId, { data: reportData, format, contentType, createdAt: new Date() }); // Storing createdAt

      const downloadUrl = `/api/v1/reports/${reportId}/download`;

      logger.info(`Report generated for scan ${scanId} in format ${format}`, { reportId, downloadUrl });

      const response: APIResponse<{
        reportId: string;
        downloadUrl: string;
        format: string;
        size: number;
      }> = {
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
    } catch (error) {
      logger.error(`Failed to generate ${format} report for scan ${scanId}:`, error);
      
      res.status(500).json({
        success: false,
        error: {
          message: 'Report generation failed',
          details: error instanceof Error ? error.message : 'Unknown error',
        },
        timestamp: new Date().toISOString(),
      } as APIResponse);
    }
  }
);

// GET /api/v1/reports/:reportId/download - Download a generated report
router.get('/:reportId/download', async (req, res) => {
    const { reportId } = req.params;
    const userId = req.user?.id || 'anonymous'; // Use mock user id

    logger.info(`Attempting to download report ${reportId} by user: ${userId}`);

    try {
        const report = reportFileStorage.get(reportId);
        
        if (!report) {
            logger.warn(`Report ${reportId} not found in file storage.`);
            return res.status(404).json({
                success: false,
                error: { message: 'Report not found or expired' },
                timestamp: new Date().toISOString(),
            } as APIResponse);
        }

        // Log detailed report information
        logger.info('Report Download Details', {
            reportId,
            format: report.format,
            contentType: report.contentType,
            dataLength: report.data.length,
            createdAt: report.createdAt
        });

        // Validate report data
        if (!report.data || report.data.length === 0) {
            logger.error(`Report ${reportId} has empty data`);
            return res.status(500).json({
                success: false,
                error: { message: 'Report data is empty' },
                timestamp: new Date().toISOString(),
            } as APIResponse);
        }

        // Attempt to decode base64 data
        let decodedData;
        try {
            decodedData = Buffer.from(report.data, 'base64');
        } catch (decodeError) {
            logger.error(`Failed to decode report ${reportId}:`, {
                message: decodeError.message,
                dataType: typeof report.data,
                dataLength: report.data.length
            });
            return res.status(500).json({
                success: false,
                error: { message: 'Failed to decode report data' },
                timestamp: new Date().toISOString(),
            } as APIResponse);
        }

        res.setHeader('Content-Type', report.contentType);
        res.setHeader('Content-Disposition', `attachment; filename="security-report-${reportId}.${report.format}"`);
        res.send(decodedData);

        logger.info(`Report ${reportId} downloaded successfully.`);
    } catch (error) {
        logger.error(`Failed to download report ${reportId}:`, {
            message: error.message,
            stack: error.stack
        });
        
        res.status(500).json({
            success: false,
            error: { 
                message: 'Failed to download report',
                details: error instanceof Error ? error.message : 'Unknown error'
            },
            timestamp: new Date().toISOString(),
        } as APIResponse);
    }
});

// GET /api/v1/reports/scan/:scanId - Get reports for a specific scan
router.get('/scan/:scanId', async (req, res) => {
    const { scanId } = req.params;
  const userId = req.user?.id || 'anonymous'; // Use mock user id

  logger.info(`Attempting to get reports for scan ${scanId} by user: ${userId}`);

  try {
    const scan = scanStorage.get(scanId);

    if (!scan) {
      logger.warn(`Scan ${scanId} not found in storage.`);
      return res.status(404).json({
        success: false,
        error: { message: 'Scan not found' },
        timestamp: new Date().toISOString(),
      } as APIResponse);
    }

    if (scan.userId !== userId && req.user?.role !== 'admin') {
      logger.warn(`User ${userId} does not have access to scan ${scanId}.`);
      return res.status(403).json({
        success: false,
        error: { message: 'Access denied' },
        timestamp: new Date().toISOString(),
      } as APIResponse);
    }

    // Get reports for this scan (simulated - in real app, query database)
    const reports: any[] = []; // Placeholder for actual report data
    reportFileStorage.forEach((report, reportId) => {
      // Check if report belongs to this scan
      // For now, assuming all reports in reportFileStorage are relevant if no scanId is stored with them
      // In a real app, reportFileStorage would be keyed by scanId or have scanId in its value
      // To fix this simply: if (report.scanId === scanId) {
      reports.push({
        id: reportId,
        scanId, // Use the scanId from the request
        type: 'technical', // Placeholder type
        format: report.format as 'json' | 'csv',
        template: 'executive_summary', // Placeholder template
        sections: ['summary', 'vulnerabilities'], // Placeholder sections
        generatedAt: report.createdAt, // Use createdAt from reportFileStorage
        downloadUrl: `/api/v1/reports/${reportId}/download`,
        expiresAt: new Date(report.createdAt.getTime() + 30 * 24 * 60 * 60 * 1000), // 30 days from now
        size: report.data.length,
      });
    });

    const response: APIResponse<any[]> = {
      success: true,
      data: reports,
      metadata: {
        timestamp: new Date(),
      },
    };

    res.json(response);
    logger.info(`Reports for scan ${scanId} retrieved successfully.`);
  } catch (error) {
    logger.error(`Failed to get reports for scan ${scanId}:`, error);
    res.status(500).json({
      success: false,
      error: { message: 'Failed to get reports' },
      timestamp: new Date().toISOString(),
    } as APIResponse);
  }
});

// DELETE /api/v1/reports/:reportId - Delete a report
router.delete('/:reportId', async (req, res) => {
    const { reportId } = req.params;
  const userId = req.user?.id || 'anonymous'; // Use mock user id

  logger.info(`Attempting to delete report ${reportId} by user: ${userId}`);

    try {
    const report = reportFileStorage.get(reportId);
      
    if (!report) {
      logger.warn(`Report ${reportId} not found in file storage.`);
        return res.status(404).json({
          success: false,
        error: { message: 'Report not found or expired' },
          timestamp: new Date().toISOString(),
        } as APIResponse);
      }

    reportFileStorage.delete(reportId);
    logger.info(`Report ${reportId} deleted successfully.`);

      const response: APIResponse<{ message: string }> = {
        success: true,
        data: { message: 'Report deleted successfully' },
        metadata: {
          timestamp: new Date(),
        },
      };

      res.json(response);
    } catch (error) {
      logger.error(`Failed to delete report ${reportId}:`, error);
      
      res.status(500).json({
        success: false,
        error: { message: 'Failed to delete report' },
        timestamp: new Date().toISOString(),
      } as APIResponse);
    }
});

// Helper function to generate JSON report
function generateJSONReport(scan: any): string {
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
    vulnerabilities: scan.vulnerabilities?.map((vuln: any) => ({
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
function generateCSVReport(scan: any): string {
  const headers = [
    'ID', 'Type', 'Severity', 'Endpoint', 'Method', 'Description', 'Impact',
    'Confidence', 'CWE', 'Remediation Priority', 'Remediation Steps', 'Remediation Resources',
  ];

  const rows = (scan.vulnerabilities || []).map((vuln: any) => {
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

export { router as reportRoutes }; 