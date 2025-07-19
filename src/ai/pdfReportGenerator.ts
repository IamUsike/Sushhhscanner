import { PDFDocument, PDFPage, PDFFont, rgb, StandardFonts } from 'pdf-lib';
import { GoogleGenerativeAI } from '@google/generative-ai';
import { Groq } from 'groq-sdk';
import { logger } from '../utils/logger';
import { RiskScoringEngine } from './riskScoringEngine';

export interface PDFReportConfig {
  includeExecutiveSummary: boolean;
  includeTechnicalDetails: boolean;
  includeRemediationPlan: boolean;
  includeRiskAnalysis: boolean;
  includeComplianceAssessment: boolean;
  customBranding?: {
    logo?: Buffer;
    companyName?: string;
    primaryColor?: string;
  };
}

export interface VulnerabilityWithRemediation {
  id: string;
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  endpoint: string;
  method: string;
  description: string;
  impact: string;
  confidence: number;
  cwe: string;
  cvss?: number;
  aiRemediation: {
    priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    timeframe: string;
    effort: string;
    steps: string[];
    codeExamples: string[];
    resources: string[];
    alternatives: string[];
    aiConfidence: number;
  };
  riskScore: number;
}

export type LLMProvider = 'gemini' | 'groq';

export interface AIRemediationEngine {
  generateRemediation(vulnerability: any): Promise<any>;
  generateExecutiveSummary(vulnerabilities: any[]): Promise<string>;
  generateRiskAnalysis(vulnerabilities: any[]): Promise<any>;
  generateComplianceAssessment(vulnerabilities: any[]): Promise<any>;
}

export class PDFReportGenerator {
  private gemini: GoogleGenerativeAI | null = null;
  private groq: Groq | null = null;
  private riskEngine: RiskScoringEngine;
  private remediationEngine: AIRemediationEngine;
  private provider: LLMProvider;

  constructor(provider: LLMProvider = 'gemini', apiKey?: string) {
    this.provider = provider;
    
    if (provider === 'gemini') {
      // Use the latest Gemini model name
      this.gemini = new GoogleGenerativeAI(apiKey || process.env.GEMINI_API_KEY || '');
    } else if (provider === 'groq') {
      this.groq = new Groq({
        apiKey: apiKey || process.env.GROQ_API_KEY || '',
      });
    }
    
    this.riskEngine = new RiskScoringEngine();
    this.remediationEngine = new AIRemediationEngineImpl(this.gemini, this.groq, provider);
  }

  async generatePDFReport(
    scanData: any,
    config: PDFReportConfig = {
      includeExecutiveSummary: true,
      includeTechnicalDetails: true,
      includeRemediationPlan: true,
      includeRiskAnalysis: true,
      includeComplianceAssessment: true,
    }
  ): Promise<Buffer> {
    logger.info('Generating AI-powered PDF security report...');

    // Validate input data
    if (!scanData) {
      throw new Error('No scan data provided for PDF report generation');
    }

    // Ensure minimum required fields exist
    const sanitizedScanData = {
      id: scanData.id || `scan-${Date.now()}`,
      target: scanData.target?.baseUrl || scanData.targetUrl || 'Unknown Target',
      vulnerabilities: Array.isArray(scanData.vulnerabilities) ? scanData.vulnerabilities : [],
      endpoints: Array.isArray(scanData.endpoints) ? scanData.endpoints : [],
      metadata: scanData.metadata || {},
      configuration: scanData.configuration || {}
    };

    try {
      // Create PDF document with explicit error handling
      let pdfDoc;
      try {
        pdfDoc = await PDFDocument.create();
      } catch (docCreateError) {
        logger.error('Failed to create PDF document:', {
          message: docCreateError.message,
          stack: docCreateError.stack
        });
        throw new Error(`PDF document creation failed: ${docCreateError.message}`);
      }

      // Ensure pages exist
      let pages = pdfDoc.getPages();
      if (pages.length === 0) {
        pages = [pdfDoc.addPage()];
      }
      const page = pages[0];

      // Verify page size can be retrieved
      let width, height;
      try {
        const pageSize = page.getSize();
        width = pageSize.width;
        height = pageSize.height;
      } catch (sizeError) {
        logger.error('Failed to get page size:', {
          message: sizeError.message,
          stack: sizeError.stack,
          pageObject: page ? Object.keys(page) : 'No page object'
        });
        throw new Error(`Unable to determine page size: ${sizeError.message}`);
      }

      // Add fonts with error handling
      let font, boldFont, titleFont;
      try {
        font = await pdfDoc.embedFont(StandardFonts.Helvetica);
        boldFont = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
        titleFont = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
      } catch (fontError) {
        logger.error('Failed to embed fonts:', {
          message: fontError.message,
          stack: fontError.stack
        });
        throw new Error(`Font embedding failed: ${fontError.message}`);
      }

      let currentY = height - 50;

      // Add header with error handling
      try {
        currentY = await this.addHeader(
          pdfDoc, 
          page, 
          font, 
          boldFont, 
          titleFont, 
          currentY, 
          config, 
          sanitizedScanData
        );
      } catch (headerError) {
        logger.error('Failed to add header:', {
          message: headerError.message,
          stack: headerError.stack
        });
        throw new Error(`Header generation failed: ${headerError.message}`);
      }

      // Add sections with error handling
      const sections = [
        { 
          condition: config.includeExecutiveSummary, 
          method: this.addExecutiveSummary,
          name: 'Executive Summary'
        },
        { 
          condition: config.includeRiskAnalysis, 
          method: this.addRiskAnalysis,
          name: 'Risk Analysis'
        },
        { 
          condition: config.includeTechnicalDetails, 
          method: this.addVulnerabilityDetails,
          name: 'Vulnerability Details'
        },
        { 
          condition: config.includeRemediationPlan, 
          method: this.addRemediationPlan,
          name: 'Remediation Plan'
        },
        { 
          condition: config.includeComplianceAssessment, 
          method: this.addComplianceAssessment,
          name: 'Compliance Assessment'
        }
      ];

      // Ensure at least some content is added
      let contentAdded = false;

      for (const section of sections) {
        if (section.condition) {
          try {
            currentY = await section.method.call(this,
              pdfDoc, 
              page, 
              font, 
              boldFont, 
              sanitizedScanData, 
              currentY, 
              config
            );
            contentAdded = true;
          } catch (sectionError) {
            logger.error(`Failed to add ${section.name} section:`, {
              message: sectionError.message,
              stack: sectionError.stack
            });
            // Continue with other sections instead of failing completely
          }
        }
      }

      // If no content was added, add a placeholder page
      if (!contentAdded) {
        page.drawText('No vulnerability data available', {
          x: 50,
          y: height - 100,
          size: 16,
          font: font,
          color: rgb(0, 0, 0)
        });
      }

      // Add footer
      try {
        await this.addFooter(pdfDoc, page, font, currentY);
      } catch (footerError) {
        logger.error('Failed to add footer:', {
          message: footerError.message,
          stack: footerError.stack
        });
        // Non-critical, so we'll continue
      }

      // Generate PDF bytes
      let pdfBytes;
      try {
        pdfBytes = await pdfDoc.save({
          // Add additional PDF/A compatibility options
          addDefaultPage: true,
          updateMetadata: true
        });
      } catch (saveError) {
        logger.error('Failed to save PDF document:', {
          message: saveError.message,
          stack: saveError.stack
        });
        throw new Error(`PDF document save failed: ${saveError.message}`);
      }

      // Validate PDF bytes
      if (!pdfBytes || pdfBytes.length === 0) {
        throw new Error('Generated PDF is empty');
      }

      // Additional validation: try to load the PDF bytes
      try {
        const loadedPdfDoc = await PDFDocument.load(pdfBytes);
        const loadedPages = loadedPdfDoc.getPages();
        
        logger.info('PDF validation successful', {
          bufferSize: pdfBytes.length,
          pageCount: loadedPages.length
        });
      } catch (loadError) {
        logger.error('PDF validation failed:', {
          message: loadError.message,
          stack: loadError.stack,
          bufferSize: pdfBytes.length
        });
        throw new Error(`PDF validation failed: ${loadError.message}`);
      }

      logger.info('PDF report generated successfully', {
        bufferSize: pdfBytes.length
      });

      return Buffer.from(pdfBytes);
    } catch (error: any) {
      logger.error(`PDF generation failed: ${error.message}`, {
        stack: error.stack,
        scanDataId: sanitizedScanData.id
      });
      throw error;
    }
  }

  private async addHeader(
    pdfDoc: PDFDocument, 
    page: PDFPage, 
    font: PDFFont, 
    boldFont: PDFFont, 
    titleFont: PDFFont, 
    y: number,
    config: PDFReportConfig,
    scanData: any
  ): Promise<number> {
    const { width } = page.getSize();

    // Title
    page.drawText('Security Vulnerability Assessment Report', {
      x: 50,
      y: y,
      size: 24,
      font: titleFont,
      color: rgb(0.2, 0.2, 0.2),
    });

    y -= 40;

    // Subtitle
    page.drawText('Comprehensive API Security Analysis', {
      x: 50,
      y: y,
      size: 14,
      font: font,
      color: rgb(0.4, 0.4, 0.4),
    });

    y -= 30;

    // Metadata
    const metadata = [
      `Generated: ${new Date().toLocaleDateString()}`,
      `Scan ID: ${scanData.id || 'N/A'}`,
      `Target: ${scanData.target?.baseUrl || 'Unknown'}`,
      `Vulnerabilities: ${scanData.vulnerabilities?.length || 0}`,
      `Endpoints Discovered: ${scanData.endpoints?.length || 0}`
    ];

    metadata.forEach((text, index) => {
      page.drawText(text, {
        x: 50,
        y: y - (index * 20),
        size: 10,
        font: font,
        color: rgb(0.5, 0.5, 0.5),
      });
    });

    // Draw a line separator
    page.drawLine({
      start: { x: 50, y: y - (metadata.length * 20) - 10 },
      end: { x: width - 50, y: y - (metadata.length * 20) - 10 },
      thickness: 1,
      color: rgb(0.8, 0.8, 0.8)
    });

    // Return the new Y position
    return y - (metadata.length * 20) - 20;
  }

  private async addExecutiveSummary(
    pdfDoc: PDFDocument, 
    page: PDFPage, 
    font: PDFFont, 
    boldFont: PDFFont, 
    scanData: any, 
    y: number, 
    config: PDFReportConfig
  ): Promise<number> {
    try {
      // Attempt to generate executive summary
      let executiveSummary = '';
      try {
        executiveSummary = await this.remediationEngine.generateExecutiveSummary(scanData.vulnerabilities);
      } catch (summaryError) {
        logger.warn('AI executive summary generation failed:', summaryError);
        // Fallback to a generic summary
        executiveSummary = `Executive Summary for Scan of ${scanData.target?.baseUrl || 'Unknown Target'}

Total Endpoints Scanned: ${scanData.endpoints?.length || 0}
Total Vulnerabilities Found: ${scanData.vulnerabilities?.length || 0}

A comprehensive security assessment was conducted to identify potential risks and vulnerabilities in the target system. The scan revealed critical insights into the security posture of the infrastructure.`;
      }

      // Sanitize and prepare text
      const sanitizedSummary = this.sanitizeText(executiveSummary);

      // Draw section title
      page.drawText('Executive Summary', {
        x: 50,
        y: y,
        size: 16,
        font: boldFont,
        color: rgb(0, 0, 0)
      });

      y -= 30;

      // Split text into paragraphs with width consideration
      const { width } = page.getSize();
      const paragraphs = this.splitTextIntoParagraphs(
        sanitizedSummary, 
        width - 100,  // Leave margins
        font, 
        12
      );

      // Draw paragraphs
      paragraphs.forEach((paragraph, index) => {
        try {
          page.drawText(paragraph, {
            x: 50,
            y: y - (index * 20),
            size: 12,
            font: font,
            color: rgb(0.2, 0.2, 0.2)
          });
        } catch (drawError) {
          logger.warn(`Failed to draw paragraph: ${paragraph}`, drawError);
        }
      });

      // Return new Y position
      return y - (paragraphs.length * 20) - 20;
    } catch (error) {
      logger.error('Failed to add Executive Summary section:', {
        message: error.message,
        stack: error.stack
      });
      
      // Return original Y position to prevent breaking PDF generation
      return y;
    }
  }

  private async addRiskAnalysis(
    pdfDoc: PDFDocument,
    page: any,
    font: any,
    boldFont: any,
    scanData: any,
    y: number,
    config: PDFReportConfig
  ): Promise<number> {
    const { width } = page.getSize();

    // Section title
    page.drawText('AI Risk Analysis', {
      x: 50,
      y: y,
      size: 18,
      font: boldFont,
      color: rgb(0.2, 0.2, 0.2),
    });

    y -= 30;

    const vulnerabilities = scanData.vulnerabilities || [];
    const riskAnalysis = await this.remediationEngine.generateRiskAnalysis(vulnerabilities);

    // Risk metrics
    const metrics = [
      `Total Vulnerabilities: ${vulnerabilities.length}`,
      `Critical Risk: ${vulnerabilities.filter((v: any) => v.severity === 'CRITICAL').length}`,
      `High Risk: ${vulnerabilities.filter((v: any) => v.severity === 'HIGH').length}`,
      `Average CVSS Score: ${riskAnalysis.averageCVSS?.toFixed(1) || 'N/A'}`,
      `Overall Risk Score: ${riskAnalysis.overallRiskScore?.toFixed(1) || 'N/A'}`,
    ];

    metrics.forEach((metric, index) => {
      page.drawText(metric, {
        x: 50,
        y: y - (index * 20),
        size: 12,
        font: font,
        color: rgb(0.1, 0.1, 0.1),
      });
    });

    y -= (metrics.length * 20) + 20;

    // Risk insights
    if (riskAnalysis.insights) {
      page.drawText('Key Risk Insights:', {
        x: 50,
        y: y,
        size: 14,
        font: boldFont,
        color: rgb(0.2, 0.2, 0.2),
      });

      y -= 25;

      const insights = this.splitTextIntoParagraphs(riskAnalysis.insights, width - 100, font, 11);
      insights.forEach((insight, index) => {
        page.drawText(`• ${insight}`, {
          x: 60,
          y: y - (index * 18),
          size: 11,
          font: font,
          color: rgb(0.1, 0.1, 0.1),
        });
      });

      y -= (insights.length * 18) + 20;
    }

    return y;
  }

  private async addVulnerabilityDetails(
    pdfDoc: PDFDocument,
    page: any,
    font: any,
    boldFont: any,
    scanData: any,
    y: number,
    config: PDFReportConfig
  ): Promise<number> {
    const { width } = page.getSize();
    const vulnerabilities = scanData.vulnerabilities || [];

    // Section title
    page.drawText('Vulnerability Details with AI Remediation', {
      x: 50,
      y: y,
      size: 18,
      font: boldFont,
      color: rgb(0.2, 0.2, 0.2),
    });

    y -= 30;

    // Process each vulnerability
    for (const vuln of vulnerabilities.slice(0, 5)) { // Limit to first 5 for space
      if (y < 150) {
        const newPage = pdfDoc.addPage();
        page = newPage;
        y = newPage.getSize().height - 50;
      }

      // Vulnerability header
      page.drawText(`${vuln.type} - ${vuln.severity}`, {
        x: 50,
        y: y,
        size: 14,
        font: boldFont,
        color: this.getSeverityColor(vuln.severity),
      });

      y -= 25;

      // Vulnerability details
      const details = [
        `Endpoint: ${vuln.endpoint}`,
        `Method: ${vuln.method}`,
        `CWE: ${vuln.cwe || 'N/A'}`,
        `CVSS: ${vuln.cvss || 'N/A'}`,
        `Description: ${vuln.description}`,
      ];

      details.forEach((detail, index) => {
        page.drawText(detail, {
          x: 60,
          y: y - (index * 16),
          size: 10,
          font: font,
          color: rgb(0.1, 0.1, 0.1),
        });
      });

      y -= (details.length * 16) + 15;

      // AI Remediation
      try {
        const aiRemediation = await this.remediationEngine.generateRemediation(vuln);
        
        page.drawText('AI Remediation Plan:', {
          x: 60,
          y: y,
          size: 12,
          font: boldFont,
          color: rgb(0.2, 0.2, 0.2),
        });

        y -= 20;

        const remediationText = [
          `Priority: ${aiRemediation.priority}`,
          `Timeframe: ${aiRemediation.timeframe}`,
          `Effort: ${aiRemediation.effort}`,
          `Steps: ${aiRemediation.steps.join(', ')}`,
        ];

        remediationText.forEach((text, index) => {
          page.drawText(text, {
            x: 70,
            y: y - (index * 14),
            size: 10,
            font: font,
            color: rgb(0.1, 0.1, 0.1),
          });
        });

        y -= (remediationText.length * 14) + 20;
      } catch (error) {
        logger.warn(`Failed to generate AI remediation for vulnerability: ${error}`);
        y -= 20;
      }
    }

    return y;
  }

  private async addRemediationPlan(
    pdfDoc: PDFDocument,
    page: any,
    font: any,
    boldFont: any,
    scanData: any,
    y: number,
    config: PDFReportConfig
  ): Promise<number> {
    const { width } = page.getSize();

    // Section title
    page.drawText('Comprehensive Remediation Plan', {
      x: 50,
      y: y,
      size: 18,
      font: boldFont,
      color: rgb(0.2, 0.2, 0.2),
    });

    y -= 30;

    const vulnerabilities = scanData.vulnerabilities || [];
    const criticalVulns = vulnerabilities.filter((v: any) => v.severity === 'CRITICAL');
    const highVulns = vulnerabilities.filter((v: any) => v.severity === 'HIGH');

    // Immediate actions
    page.drawText('Immediate Actions (0-24 hours):', {
      x: 50,
      y: y,
      size: 14,
      font: boldFont,
      color: rgb(0.8, 0.2, 0.2),
    });

    y -= 25;

    if (criticalVulns.length > 0) {
      page.drawText(`• Address ${criticalVulns.length} critical vulnerabilities`, {
        x: 60,
        y: y,
        size: 12,
        font: font,
        color: rgb(0.1, 0.1, 0.1),
      });
      y -= 20;
    }

    // Short-term actions
    page.drawText('Short-term Actions (1-7 days):', {
      x: 50,
      y: y,
      size: 14,
      font: boldFont,
      color: rgb(0.9, 0.6, 0.1),
    });

    y -= 25;

    if (highVulns.length > 0) {
      page.drawText(`• Remediate ${highVulns.length} high-risk vulnerabilities`, {
        x: 60,
        y: y,
        size: 12,
        font: font,
        color: rgb(0.1, 0.1, 0.1),
      });
      y -= 20;
    }

    // Long-term actions
    page.drawText('Long-term Actions (1-4 weeks):', {
      x: 50,
      y: y,
      size: 14,
      font: boldFont,
      color: rgb(0.2, 0.6, 0.2),
    });

    y -= 25;

    page.drawText('• Implement security training program', {
      x: 60,
      y: y,
      size: 12,
      font: font,
      color: rgb(0.1, 0.1, 0.1),
    });

    y -= 20;

    page.drawText('• Establish continuous security monitoring', {
      x: 60,
      y: y,
      size: 12,
      font: font,
      color: rgb(0.1, 0.1, 0.1),
    });

    return y - 30;
  }

  private async addComplianceAssessment(
    pdfDoc: PDFDocument,
    page: any,
    font: any,
    boldFont: any,
    scanData: any,
    y: number,
    config: PDFReportConfig
  ): Promise<number> {
    const { width } = page.getSize();

    // Section title
    page.drawText('Compliance Assessment', {
      x: 50,
      y: y,
      size: 18,
      font: boldFont,
      color: rgb(0.2, 0.2, 0.2),
    });

    y -= 30;

    const vulnerabilities = scanData.vulnerabilities || [];
    const complianceAssessment = await this.remediationEngine.generateComplianceAssessment(vulnerabilities);

    const frameworks = [
      { name: 'OWASP Top 10', status: complianceAssessment.owasp?.status || 'UNKNOWN' },
      { name: 'PCI DSS', status: complianceAssessment.pci?.status || 'UNKNOWN' },
      { name: 'GDPR', status: complianceAssessment.gdpr?.status || 'UNKNOWN' },
      { name: 'ISO 27001', status: complianceAssessment.iso?.status || 'UNKNOWN' },
    ];

    frameworks.forEach((framework, index) => {
      const color = this.getComplianceColor(framework.status);
      
      page.drawText(`${framework.name}:`, {
        x: 50,
        y: y - (index * 25),
        size: 12,
        font: boldFont,
        color: rgb(0.1, 0.1, 0.1),
      });

      page.drawText(framework.status, {
        x: 200,
        y: y - (index * 25),
        size: 12,
        font: font,
        color: color,
      });
    });

    return y - (frameworks.length * 25) - 20;
  }

  private addFooter(pdfDoc: PDFDocument, page: any, font: any, y: number): void {
    const { width } = page.getSize();

    page.drawText('Generated by AI-Powered Security Assessment Tool', {
      x: 50,
      y: 30,
      size: 10,
      font: font,
      color: rgb(0.5, 0.5, 0.5),
    });

    page.drawText(`Page ${pdfDoc.getPageCount()}`, {
      x: width - 100,
      y: 30,
      size: 10,
      font: font,
      color: rgb(0.5, 0.5, 0.5),
    });
  }

  private splitTextIntoParagraphs(text: string, maxWidth: number, font: any, fontSize: number): string[] {
    // Remove any problematic characters and normalize newlines
    const cleanText = text
      .replace(/\r\n/g, '\n')  // Normalize line breaks
      .replace(/\r/g, '\n')    // Replace carriage returns
      .replace(/\n{2,}/g, '\n') // Reduce multiple newlines
      .trim();

    // If text is empty after cleaning, return an empty array
    if (!cleanText) return [];

    const paragraphs: string[] = [];
    const lines = cleanText.split('\n');

    for (const line of lines) {
      // Skip empty lines
      if (!line.trim()) continue;

      // Break long lines
      const words = line.split(/\s+/);
      let currentLine = '';

      for (const word of words) {
        const testLine = currentLine ? `${currentLine} ${word}` : word;
        
        try {
          const testWidth = font.widthOfTextAtSize(testLine, fontSize);
          
          if (testWidth <= maxWidth) {
            currentLine = testLine;
          } else {
            // If current line is not empty, add it to paragraphs
            if (currentLine) {
              paragraphs.push(currentLine);
            }
            currentLine = word;
          }
        } catch (error) {
          // Fallback if width calculation fails
          paragraphs.push(word);
          currentLine = '';
        }
      }

      // Add the last line of the paragraph
      if (currentLine) {
        paragraphs.push(currentLine);
      }
    }

    return paragraphs;
  }

  private sanitizeText(text: string): string {
    // Remove or replace characters that might cause encoding issues
    return text
      .normalize('NFC')  // Normalize Unicode characters
      .replace(/[^\x20-\x7E]/g, '')  // Remove non-printable characters
      .replace(/\s+/g, ' ')  // Normalize whitespace
      .trim();
  }

  private getSeverityColor(severity: string): any {
    switch (severity) {
      case 'CRITICAL':
        return rgb(0.8, 0.1, 0.1);
      case 'HIGH':
        return rgb(0.9, 0.4, 0.1);
      case 'MEDIUM':
        return rgb(0.9, 0.7, 0.1);
      case 'LOW':
        return rgb(0.2, 0.6, 0.2);
      default:
        return rgb(0.5, 0.5, 0.5);
    }
  }

  private getComplianceColor(status: string): any {
    switch (status) {
      case 'COMPLIANT':
        return rgb(0.2, 0.6, 0.2);
      case 'NON_COMPLIANT':
        return rgb(0.8, 0.1, 0.1);
      case 'PARTIAL':
        return rgb(0.9, 0.6, 0.1);
      default:
        return rgb(0.5, 0.5, 0.5);
    }
  }
}

class AIRemediationEngineImpl implements AIRemediationEngine {
  constructor(
    private gemini: GoogleGenerativeAI | null,
    private groq: Groq | null,
    private provider: LLMProvider
  ) {}

  private async getGenerativeModel() {
    if (this.provider === 'gemini' && this.gemini) {
      // Use the latest Gemini model
      return this.gemini.getGenerativeModel({ 
        model: 'gemini-1.5-flash-latest' 
      });
    }
    // Fallback for other providers
    return null;
  }

  async generateRemediation(vulnerability: any): Promise<any> {
    try {
      if (this.provider === 'gemini') {
        const model = await this.getGenerativeModel();
        if (!model) {
          return this.generateFallbackRemediation(vulnerability);
        }

        const prompt = `Generate a detailed remediation plan for a ${vulnerability.severity} severity vulnerability of type ${vulnerability.type} found at endpoint ${vulnerability.endpoint}. 
        
        Provide:
        1. Detailed description of the vulnerability
        2. Potential impact
        3. Step-by-step remediation guidance
        4. Code examples for fixing the vulnerability
        5. Best practices to prevent similar vulnerabilities`;

        const result = await model.generateContent(prompt);
        const response = result.response;
        
        return {
          priority: this.getPriorityFromSeverity(vulnerability.severity),
          steps: response.text().split('\n').filter(step => step.trim() !== ''),
          description: prompt,
          aiConfidence: 0.9
        };
      } else if (this.provider === 'groq' && this.groq) {
        // Existing Groq implementation
        const chatCompletion = await this.groq.chat.completions.create({
          messages: [
            {
              role: 'system',
              content: 'You are a cybersecurity expert specializing in vulnerability remediation.'
            },
            {
              role: 'user',
              content: `Generate a detailed remediation plan for a ${vulnerability.severity} severity vulnerability of type ${vulnerability.type} found at endpoint ${vulnerability.endpoint}`
            }
          ],
          model: 'mixtral-8x7b-32768'
        });

        return {
          priority: this.getPriorityFromSeverity(vulnerability.severity),
          steps: chatCompletion.choices[0].message.content?.split('\n').filter(step => step.trim() !== '') || [],
          description: chatCompletion.choices[0].message.content || '',
          aiConfidence: 0.8
        };
      }

      // Fallback
      return this.generateFallbackRemediation(vulnerability);
    } catch (error) {
      logger.error('Remediation generation failed:', error);
      return this.generateFallbackRemediation(vulnerability);
    }
  }

  async generateExecutiveSummary(vulnerabilities: any[]): Promise<string> {
    try {
      // Validate input
      if (!vulnerabilities || vulnerabilities.length === 0) {
        return `Executive Summary

No vulnerabilities were detected during the security assessment.

Scan completed with no significant findings. The system appears to be in a secure state.`;
      }

      // Prepare vulnerability summary
      const severityCounts = vulnerabilities.reduce((acc, vuln) => {
        acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
        return acc;
      }, {});

      const uniqueEndpoints = new Set(vulnerabilities.map(v => v.endpoint)).size;
      const uniqueVulnerabilityTypes = new Set(vulnerabilities.map(v => v.type)).size;

      // Construct a detailed summary
      let summary = `Executive Summary

Comprehensive Security Assessment Results:

Total Vulnerabilities Detected: ${vulnerabilities.length}
Unique Endpoints Affected: ${uniqueEndpoints}
Unique Vulnerability Types: ${uniqueVulnerabilityTypes}

Vulnerability Severity Breakdown:
${Object.entries(severityCounts)
  .map(([severity, count]) => `- ${severity}: ${count} vulnerabilities`)
  .join('\n')}

Key Findings:
${vulnerabilities
  .slice(0, 5)  // Limit to top 5 most critical vulnerabilities
  .map((vuln, index) => 
    `${index + 1}. ${vuln.severity} Severity: ${vuln.type} at ${vuln.endpoint}
   Description: ${vuln.description || 'No detailed description available'}`
  )
  .join('\n\n')}

Recommendations:
1. Immediate remediation of high and critical severity vulnerabilities
2. Conduct a comprehensive security review
3. Implement robust security controls
4. Perform regular vulnerability assessments

Note: This summary provides an overview of detected vulnerabilities. 
Detailed remediation steps are available in the full report.`;

      // Sanitize the summary to remove any problematic characters
      return summary
        .normalize('NFC')  // Normalize Unicode characters
        .replace(/[^\x20-\x7E\n]/g, '')  // Remove non-printable characters
        .replace(/\s+/g, ' ')  // Normalize whitespace
        .trim();

    } catch (error) {
      logger.error('Failed to generate executive summary:', {
        message: error.message,
        stack: error.stack
      });

      // Fallback summary
      return this.generateFallbackExecutiveSummary(vulnerabilities);
    }
  }

  async generateRiskAnalysis(vulnerabilities: any[]): Promise<any> {
    const criticalCount = vulnerabilities.filter(v => v.severity === 'CRITICAL').length;
    const highCount = vulnerabilities.filter(v => v.severity === 'HIGH').length;
    const totalCVSS = vulnerabilities.reduce((sum, v) => sum + (v.cvss || 0), 0);
    const averageCVSS = vulnerabilities.length > 0 ? totalCVSS / vulnerabilities.length : 0;

    return {
      overallRiskScore: Math.min(100, (criticalCount * 25) + (highCount * 15) + (averageCVSS * 10)),
      averageCVSS,
      criticalCount,
      highCount,
      insights: `Found ${criticalCount} critical and ${highCount} high-risk vulnerabilities requiring immediate attention.`,
    };
  }

  async generateComplianceAssessment(vulnerabilities: any[]): Promise<any> {
    const hasCriticalVulns = vulnerabilities.some(v => v.severity === 'CRITICAL');
    const hasDataExposure = vulnerabilities.some(v => v.type.includes('DATA_EXPOSURE') || v.type.includes('INFORMATION_DISCLOSURE'));

    return {
      owasp: { status: hasCriticalVulns ? 'NON_COMPLIANT' : 'COMPLIANT' },
      pci: { status: hasDataExposure ? 'NON_COMPLIANT' : 'COMPLIANT' },
      gdpr: { status: hasDataExposure ? 'NON_COMPLIANT' : 'COMPLIANT' },
      iso: { status: hasCriticalVulns ? 'NON_COMPLIANT' : 'PARTIAL' },
    };
  }

  private generateFallbackRemediation(vulnerability: any): any {
    return {
      priority: vulnerability.severity,
      timeframe: vulnerability.severity === 'CRITICAL' ? 'Immediate' : '1-7 days',
      effort: vulnerability.severity === 'CRITICAL' ? 'High' : 'Medium',
      steps: ['Review vulnerability details', 'Implement security fix', 'Test thoroughly', 'Deploy to production'],
      codeExamples: [],
      resources: ['OWASP Guidelines', 'Security Best Practices'],
      alternatives: ['Alternative security controls'],
      aiConfidence: 0.7,
    };
  }

  private generateFallbackExecutiveSummary(vulnerabilities: any[]): string {
    return `Executive Summary

Security Assessment Overview:

Total Vulnerabilities: ${vulnerabilities.length}

Severity Breakdown:
${Object.entries(
  vulnerabilities.reduce((acc, vuln) => {
    acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
    return acc;
  }, {})
)
  .map(([severity, count]) => `- ${severity}: ${count}`)
  .join('\n')}

A comprehensive security assessment was conducted. 
Please refer to the detailed report for specific vulnerability information.

Recommendations:
1. Review all identified vulnerabilities
2. Prioritize and remediate high-risk issues
3. Implement security best practices`;
  }

  private getPriorityFromSeverity(severity: string): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
    switch (severity) {
      case 'CRITICAL': return 'CRITICAL';
      case 'HIGH': return 'HIGH';
      case 'MEDIUM': return 'MEDIUM';
      default: return 'LOW';
    }
  }
} 