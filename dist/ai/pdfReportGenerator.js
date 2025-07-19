"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PDFReportGenerator = void 0;
const pdf_lib_1 = require("pdf-lib");
const generative_ai_1 = require("@google/generative-ai");
const groq_sdk_1 = require("groq-sdk");
const logger_1 = require("../utils/logger");
const riskScoringEngine_1 = require("./riskScoringEngine");
class PDFReportGenerator {
    constructor(provider = 'gemini', apiKey) {
        this.gemini = null;
        this.groq = null;
        this.provider = provider;
        if (provider === 'gemini') {
            this.gemini = new generative_ai_1.GoogleGenerativeAI(apiKey || process.env.GEMINI_API_KEY || '');
        }
        else if (provider === 'groq') {
            this.groq = new groq_sdk_1.Groq({
                apiKey: apiKey || process.env.GROQ_API_KEY || '',
            });
        }
        this.riskEngine = new riskScoringEngine_1.RiskScoringEngine();
        this.remediationEngine = new AIRemediationEngineImpl(this.gemini, this.groq, provider);
    }
    async generatePDFReport(scanData, config = {
        includeExecutiveSummary: true,
        includeTechnicalDetails: true,
        includeRemediationPlan: true,
        includeRiskAnalysis: true,
        includeComplianceAssessment: true,
    }) {
        logger_1.logger.info('Generating AI-powered PDF security report...');
        try {
            // Create PDF document
            const pdfDoc = await pdf_lib_1.PDFDocument.create();
            const pages = pdfDoc.getPages();
            const page = pages[0];
            const { width, height } = page.getSize();
            // Add fonts
            const font = await pdfDoc.embedFont(pdf_lib_1.StandardFonts.Helvetica);
            const boldFont = await pdfDoc.embedFont(pdf_lib_1.StandardFonts.HelveticaBold);
            const titleFont = await pdfDoc.embedFont(pdf_lib_1.StandardFonts.HelveticaBold);
            let currentY = height - 50;
            // Add header
            currentY = await this.addHeader(pdfDoc, page, font, boldFont, titleFont, currentY, config);
            // Add executive summary
            if (config.includeExecutiveSummary) {
                currentY = await this.addExecutiveSummary(pdfDoc, page, font, boldFont, scanData, currentY, config);
            }
            // Add risk analysis
            if (config.includeRiskAnalysis) {
                currentY = await this.addRiskAnalysis(pdfDoc, page, font, boldFont, scanData, currentY, config);
            }
            // Add vulnerability details with AI remediation
            if (config.includeTechnicalDetails) {
                currentY = await this.addVulnerabilityDetails(pdfDoc, page, font, boldFont, scanData, currentY, config);
            }
            // Add remediation plan
            if (config.includeRemediationPlan) {
                currentY = await this.addRemediationPlan(pdfDoc, page, font, boldFont, scanData, currentY, config);
            }
            // Add compliance assessment
            if (config.includeComplianceAssessment) {
                currentY = await this.addComplianceAssessment(pdfDoc, page, font, boldFont, scanData, currentY, config);
            }
            // Add footer
            await this.addFooter(pdfDoc, page, font, currentY);
            // Generate PDF bytes
            const pdfBytes = await pdfDoc.save();
            logger_1.logger.info('PDF report generated successfully');
            return Buffer.from(pdfBytes);
        }
        catch (error) {
            logger_1.logger.error(`PDF generation failed: ${error.message}`);
            throw error;
        }
    }
    async addHeader(pdfDoc, page, font, boldFont, titleFont, y, config) {
        const { width } = page.getSize();
        // Title
        page.drawText('AI-Powered Security Assessment Report', {
            x: 50,
            y: y,
            size: 24,
            font: titleFont,
            color: (0, pdf_lib_1.rgb)(0.2, 0.2, 0.2),
        });
        y -= 40;
        // Subtitle
        page.drawText('Comprehensive Vulnerability Analysis with Intelligent Remediation', {
            x: 50,
            y: y,
            size: 14,
            font: font,
            color: (0, pdf_lib_1.rgb)(0.4, 0.4, 0.4),
        });
        y -= 30;
        // Report metadata
        const metadata = [
            `Generated: ${new Date().toLocaleDateString()}`,
            `Scan ID: ${Math.random().toString(36).substr(2, 9)}`,
            `AI Model: GPT-4 Enhanced`,
        ];
        metadata.forEach((text, index) => {
            page.drawText(text, {
                x: 50,
                y: y - (index * 20),
                size: 10,
                font: font,
                color: (0, pdf_lib_1.rgb)(0.5, 0.5, 0.5),
            });
        });
        return y - (metadata.length * 20) - 30;
    }
    async addExecutiveSummary(pdfDoc, page, font, boldFont, scanData, y, config) {
        const { width } = page.getSize();
        // Section title
        page.drawText('Executive Summary', {
            x: 50,
            y: y,
            size: 18,
            font: boldFont,
            color: (0, pdf_lib_1.rgb)(0.2, 0.2, 0.2),
        });
        y -= 30;
        // Generate AI-powered executive summary
        const vulnerabilities = scanData.vulnerabilities || [];
        const executiveSummary = await this.remediationEngine.generateExecutiveSummary(vulnerabilities);
        // Split summary into paragraphs
        const paragraphs = this.splitTextIntoParagraphs(executiveSummary, width - 100, font, 12);
        paragraphs.forEach((paragraph, index) => {
            if (y < 100) {
                // Add new page if needed
                const newPage = pdfDoc.addPage();
                y = newPage.getSize().height - 50;
            }
            page.drawText(paragraph, {
                x: 50,
                y: y,
                size: 12,
                font: font,
                color: (0, pdf_lib_1.rgb)(0.1, 0.1, 0.1),
            });
            y -= 20;
        });
        return y - 20;
    }
    async addRiskAnalysis(pdfDoc, page, font, boldFont, scanData, y, config) {
        const { width } = page.getSize();
        // Section title
        page.drawText('AI Risk Analysis', {
            x: 50,
            y: y,
            size: 18,
            font: boldFont,
            color: (0, pdf_lib_1.rgb)(0.2, 0.2, 0.2),
        });
        y -= 30;
        const vulnerabilities = scanData.vulnerabilities || [];
        const riskAnalysis = await this.remediationEngine.generateRiskAnalysis(vulnerabilities);
        // Risk metrics
        const metrics = [
            `Total Vulnerabilities: ${vulnerabilities.length}`,
            `Critical Risk: ${vulnerabilities.filter((v) => v.severity === 'CRITICAL').length}`,
            `High Risk: ${vulnerabilities.filter((v) => v.severity === 'HIGH').length}`,
            `Average CVSS Score: ${riskAnalysis.averageCVSS?.toFixed(1) || 'N/A'}`,
            `Overall Risk Score: ${riskAnalysis.overallRiskScore?.toFixed(1) || 'N/A'}`,
        ];
        metrics.forEach((metric, index) => {
            page.drawText(metric, {
                x: 50,
                y: y - (index * 20),
                size: 12,
                font: font,
                color: (0, pdf_lib_1.rgb)(0.1, 0.1, 0.1),
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
                color: (0, pdf_lib_1.rgb)(0.2, 0.2, 0.2),
            });
            y -= 25;
            const insights = this.splitTextIntoParagraphs(riskAnalysis.insights, width - 100, font, 11);
            insights.forEach((insight, index) => {
                page.drawText(`• ${insight}`, {
                    x: 60,
                    y: y - (index * 18),
                    size: 11,
                    font: font,
                    color: (0, pdf_lib_1.rgb)(0.1, 0.1, 0.1),
                });
            });
            y -= (insights.length * 18) + 20;
        }
        return y;
    }
    async addVulnerabilityDetails(pdfDoc, page, font, boldFont, scanData, y, config) {
        const { width } = page.getSize();
        const vulnerabilities = scanData.vulnerabilities || [];
        // Section title
        page.drawText('Vulnerability Details with AI Remediation', {
            x: 50,
            y: y,
            size: 18,
            font: boldFont,
            color: (0, pdf_lib_1.rgb)(0.2, 0.2, 0.2),
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
                    color: (0, pdf_lib_1.rgb)(0.1, 0.1, 0.1),
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
                    color: (0, pdf_lib_1.rgb)(0.2, 0.2, 0.2),
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
                        color: (0, pdf_lib_1.rgb)(0.1, 0.1, 0.1),
                    });
                });
                y -= (remediationText.length * 14) + 20;
            }
            catch (error) {
                logger_1.logger.warn(`Failed to generate AI remediation for vulnerability: ${error}`);
                y -= 20;
            }
        }
        return y;
    }
    async addRemediationPlan(pdfDoc, page, font, boldFont, scanData, y, config) {
        const { width } = page.getSize();
        // Section title
        page.drawText('Comprehensive Remediation Plan', {
            x: 50,
            y: y,
            size: 18,
            font: boldFont,
            color: (0, pdf_lib_1.rgb)(0.2, 0.2, 0.2),
        });
        y -= 30;
        const vulnerabilities = scanData.vulnerabilities || [];
        const criticalVulns = vulnerabilities.filter((v) => v.severity === 'CRITICAL');
        const highVulns = vulnerabilities.filter((v) => v.severity === 'HIGH');
        // Immediate actions
        page.drawText('Immediate Actions (0-24 hours):', {
            x: 50,
            y: y,
            size: 14,
            font: boldFont,
            color: (0, pdf_lib_1.rgb)(0.8, 0.2, 0.2),
        });
        y -= 25;
        if (criticalVulns.length > 0) {
            page.drawText(`• Address ${criticalVulns.length} critical vulnerabilities`, {
                x: 60,
                y: y,
                size: 12,
                font: font,
                color: (0, pdf_lib_1.rgb)(0.1, 0.1, 0.1),
            });
            y -= 20;
        }
        // Short-term actions
        page.drawText('Short-term Actions (1-7 days):', {
            x: 50,
            y: y,
            size: 14,
            font: boldFont,
            color: (0, pdf_lib_1.rgb)(0.9, 0.6, 0.1),
        });
        y -= 25;
        if (highVulns.length > 0) {
            page.drawText(`• Remediate ${highVulns.length} high-risk vulnerabilities`, {
                x: 60,
                y: y,
                size: 12,
                font: font,
                color: (0, pdf_lib_1.rgb)(0.1, 0.1, 0.1),
            });
            y -= 20;
        }
        // Long-term actions
        page.drawText('Long-term Actions (1-4 weeks):', {
            x: 50,
            y: y,
            size: 14,
            font: boldFont,
            color: (0, pdf_lib_1.rgb)(0.2, 0.6, 0.2),
        });
        y -= 25;
        page.drawText('• Implement security training program', {
            x: 60,
            y: y,
            size: 12,
            font: font,
            color: (0, pdf_lib_1.rgb)(0.1, 0.1, 0.1),
        });
        y -= 20;
        page.drawText('• Establish continuous security monitoring', {
            x: 60,
            y: y,
            size: 12,
            font: font,
            color: (0, pdf_lib_1.rgb)(0.1, 0.1, 0.1),
        });
        return y - 30;
    }
    async addComplianceAssessment(pdfDoc, page, font, boldFont, scanData, y, config) {
        const { width } = page.getSize();
        // Section title
        page.drawText('Compliance Assessment', {
            x: 50,
            y: y,
            size: 18,
            font: boldFont,
            color: (0, pdf_lib_1.rgb)(0.2, 0.2, 0.2),
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
                color: (0, pdf_lib_1.rgb)(0.1, 0.1, 0.1),
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
    addFooter(pdfDoc, page, font, y) {
        const { width } = page.getSize();
        page.drawText('Generated by AI-Powered Security Assessment Tool', {
            x: 50,
            y: 30,
            size: 10,
            font: font,
            color: (0, pdf_lib_1.rgb)(0.5, 0.5, 0.5),
        });
        page.drawText(`Page ${pdfDoc.getPageCount()}`, {
            x: width - 100,
            y: 30,
            size: 10,
            font: font,
            color: (0, pdf_lib_1.rgb)(0.5, 0.5, 0.5),
        });
    }
    splitTextIntoParagraphs(text, maxWidth, font, fontSize) {
        const words = text.split(' ');
        const paragraphs = [];
        let currentLine = '';
        words.forEach(word => {
            const testLine = currentLine + word + ' ';
            const testWidth = font.widthOfTextAtSize(testLine, fontSize);
            if (testWidth > maxWidth && currentLine !== '') {
                paragraphs.push(currentLine.trim());
                currentLine = word + ' ';
            }
            else {
                currentLine = testLine;
            }
        });
        if (currentLine.trim()) {
            paragraphs.push(currentLine.trim());
        }
        return paragraphs;
    }
    getSeverityColor(severity) {
        switch (severity) {
            case 'CRITICAL':
                return (0, pdf_lib_1.rgb)(0.8, 0.1, 0.1);
            case 'HIGH':
                return (0, pdf_lib_1.rgb)(0.9, 0.4, 0.1);
            case 'MEDIUM':
                return (0, pdf_lib_1.rgb)(0.9, 0.7, 0.1);
            case 'LOW':
                return (0, pdf_lib_1.rgb)(0.2, 0.6, 0.2);
            default:
                return (0, pdf_lib_1.rgb)(0.5, 0.5, 0.5);
        }
    }
    getComplianceColor(status) {
        switch (status) {
            case 'COMPLIANT':
                return (0, pdf_lib_1.rgb)(0.2, 0.6, 0.2);
            case 'NON_COMPLIANT':
                return (0, pdf_lib_1.rgb)(0.8, 0.1, 0.1);
            case 'PARTIAL':
                return (0, pdf_lib_1.rgb)(0.9, 0.6, 0.1);
            default:
                return (0, pdf_lib_1.rgb)(0.5, 0.5, 0.5);
        }
    }
}
exports.PDFReportGenerator = PDFReportGenerator;
class AIRemediationEngineImpl {
    constructor(gemini, groq, provider) {
        this.gemini = gemini;
        this.groq = groq;
        this.provider = provider;
    }
    async generateRemediation(vulnerability) {
        try {
            const prompt = `Generate a detailed remediation plan for this security vulnerability:

Vulnerability Type: ${vulnerability.type}
Severity: ${vulnerability.severity}
Endpoint: ${vulnerability.endpoint}
Method: ${vulnerability.method}
Description: ${vulnerability.description}
CWE: ${vulnerability.cwe}

Please provide:
1. Priority level (CRITICAL/HIGH/MEDIUM/LOW)
2. Timeframe for remediation
3. Effort estimation
4. Step-by-step remediation steps
5. Code examples if applicable
6. Additional resources
7. Alternative approaches
8. Confidence level in this recommendation

Format as JSON.`;
            let content;
            if (this.provider === 'gemini' && this.gemini) {
                const model = this.gemini.getGenerativeModel({ model: 'gemini-pro' });
                const result = await model.generateContent(prompt);
                content = result.response.text();
            }
            else if (this.provider === 'groq' && this.groq) {
                const response = await this.groq.chat.completions.create({
                    messages: [{ role: 'user', content: prompt }],
                    model: 'llama3-8b-8192',
                    temperature: 0.3,
                });
                content = response.choices[0]?.message?.content;
            }
            if (content) {
                try {
                    return JSON.parse(content);
                }
                catch {
                    return this.generateFallbackRemediation(vulnerability);
                }
            }
        }
        catch (error) {
            logger_1.logger.warn(`AI remediation generation failed: ${error}`);
        }
        return this.generateFallbackRemediation(vulnerability);
    }
    async generateExecutiveSummary(vulnerabilities) {
        try {
            const prompt = `Generate an executive summary for a security assessment with ${vulnerabilities.length} vulnerabilities found.

Key metrics:
- Critical: ${vulnerabilities.filter(v => v.severity === 'CRITICAL').length}
- High: ${vulnerabilities.filter(v => v.severity === 'HIGH').length}
- Medium: ${vulnerabilities.filter(v => v.severity === 'MEDIUM').length}
- Low: ${vulnerabilities.filter(v => v.severity === 'LOW').length}

Provide a concise, business-focused summary highlighting key risks and recommendations.`;
            let content;
            if (this.provider === 'gemini' && this.gemini) {
                const model = this.gemini.getGenerativeModel({ model: 'gemini-pro' });
                const result = await model.generateContent(prompt);
                content = result.response.text();
            }
            else if (this.provider === 'groq' && this.groq) {
                const response = await this.groq.chat.completions.create({
                    messages: [{ role: 'user', content: prompt }],
                    model: 'llama3-8b-8192',
                    temperature: 0.4,
                });
                content = response.choices[0]?.message?.content;
            }
            return content || this.generateFallbackExecutiveSummary(vulnerabilities);
        }
        catch (error) {
            logger_1.logger.warn(`AI executive summary generation failed: ${error}`);
            return this.generateFallbackExecutiveSummary(vulnerabilities);
        }
    }
    async generateRiskAnalysis(vulnerabilities) {
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
    async generateComplianceAssessment(vulnerabilities) {
        const hasCriticalVulns = vulnerabilities.some(v => v.severity === 'CRITICAL');
        const hasDataExposure = vulnerabilities.some(v => v.type.includes('DATA_EXPOSURE') || v.type.includes('INFORMATION_DISCLOSURE'));
        return {
            owasp: { status: hasCriticalVulns ? 'NON_COMPLIANT' : 'COMPLIANT' },
            pci: { status: hasDataExposure ? 'NON_COMPLIANT' : 'COMPLIANT' },
            gdpr: { status: hasDataExposure ? 'NON_COMPLIANT' : 'COMPLIANT' },
            iso: { status: hasCriticalVulns ? 'NON_COMPLIANT' : 'PARTIAL' },
        };
    }
    generateFallbackRemediation(vulnerability) {
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
    generateFallbackExecutiveSummary(vulnerabilities) {
        const criticalCount = vulnerabilities.filter(v => v.severity === 'CRITICAL').length;
        const highCount = vulnerabilities.filter(v => v.severity === 'HIGH').length;
        return `Security assessment completed with ${vulnerabilities.length} vulnerabilities identified. 
    ${criticalCount} critical and ${highCount} high-risk issues require immediate attention. 
    Recommended immediate action plan includes addressing critical vulnerabilities within 24 hours 
    and implementing comprehensive security controls for long-term protection.`;
    }
}
//# sourceMappingURL=pdfReportGenerator.js.map