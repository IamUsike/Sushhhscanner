import { PDFDocument, rgb, StandardFonts } from 'pdf-lib';
import { generateAIRemediation } from './aiRemediationEngine';

interface Vulnerability {
    id: string;
    type: string;
    severity: string;
    endpoint: string;
    method: string;
    description: string;
    cwe?: string;
    cvss?: string;
    timestamp: string;
    details?: any;
}

interface ScanData {
    scanId: string;
    target: string;
    startTime: string;
    endTime: string;
    duration: number;
    vulnerabilities: Vulnerability[];
    endpointsDiscovered: number;
    totalRiskScore: number;
    cvssScore: number;
    scanProgress?: any;
    mlMetrics?: any;
}

export async function generateDetailedPDFReport(scanData: ScanData): Promise<Uint8Array> {
    const pdfDoc = await PDFDocument.create();

    try {
        const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
        const boldFont = await pdfDoc.embedFont(StandardFonts.HelveticaBold);

        const pageWidth = 595.28;
        const pageHeight = 841.89;

        // Page 1: Executive Summary
        const page1 = pdfDoc.addPage([pageWidth, pageHeight]);

        // Title
        page1.drawText('Security Vulnerability Assessment Report', {
            x: 50,
            y: pageHeight - 80,
            size: 24,
            font: boldFont,
            color: rgb(0.2, 0.2, 0.2)
        });

        page1.drawText('Comprehensive API Security Analysis', {
            x: 50,
            y: pageHeight - 110,
            size: 16,
            font: font,
            color: rgb(0.4, 0.4, 0.4)
        });

        // Report metadata
        const metadata = [
            `Generated: ${new Date().toLocaleDateString()}`,
            `Scan ID: ${scanData.scanId}`,
            `Target: ${scanData.target || 'Unknown'}`,
            `Vulnerabilities: ${scanData.vulnerabilities.length}`,
            `Endpoints Discovered: ${scanData.endpointsDiscovered || scanData.vulnerabilities.length || 0}`,
            `Total Risk Score: ${scanData.totalRiskScore || calculateFallbackRiskScore(scanData.vulnerabilities)}`,
            `CVSS Score: ${scanData.cvssScore || scanData.totalRiskScore || 'N/A'}`,
            `Scan Duration: ${scanData.duration || 'Unknown'}s`
        ];

        let yPos = pageHeight - 160;
        metadata.forEach(item => {
            page1.drawText(item, {
                x: 50,
                y: yPos,
                size: 12,
                font: font,
                color: rgb(0.3, 0.3, 0.3)
            });
            yPos -= 20;
        });

        // Executive Summary
        yPos -= 30;
        page1.drawText('Executive Summary', {
            x: 50,
            y: yPos,
            size: 18,
            font: boldFont,
            color: rgb(0.2, 0.2, 0.2)
        });

        yPos -= 30;
        const riskLevel = scanData.totalRiskScore > 75 ? 'critical' : scanData.totalRiskScore > 50 ? 'high' : 'moderate';
        const summary = `This security assessment identified ${scanData.vulnerabilities.length} vulnerabilities across ${scanData.endpointsDiscovered || scanData.vulnerabilities.length} API endpoints. The overall risk score of ${scanData.totalRiskScore || calculateFallbackRiskScore(scanData.vulnerabilities)} indicates ${riskLevel} security concerns requiring immediate attention.`;

        const summaryLines = splitTextToFit(summary, pageWidth - 100, font, 12);
        summaryLines.forEach(line => {
            page1.drawText(line, {
                x: 50,
                y: yPos,
                size: 12,
                font: font,
                color: rgb(0.3, 0.3, 0.3)
            });
            yPos -= 18;
        });

        // Vulnerability breakdown
        yPos -= 20;
        page1.drawText('Vulnerability Breakdown:', {
            x: 50,
            y: yPos,
            size: 14,
            font: boldFont,
            color: rgb(0.2, 0.2, 0.2)
        });

        const severityCounts = scanData.vulnerabilities.reduce((acc, vuln) => {
            acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
            return acc;
        }, {} as Record<string, number>);

        yPos -= 25;
        Object.entries(severityCounts).forEach(([severity, count]) => {
            const color = severity === 'CRITICAL' ? rgb(0.8, 0.2, 0.2) :
                         severity === 'HIGH' ? rgb(0.9, 0.5, 0.1) :
                         severity === 'MEDIUM' ? rgb(0.9, 0.7, 0.1) :
                         rgb(0.2, 0.6, 0.2);

            page1.drawText(`${severity}: ${count}`, {
                x: 50,
                y: yPos,
                size: 12,
                font: font,
                color: color
            });
            yPos -= 18;
        });

        // Detailed Vulnerabilities - Proper page tracking
        let currentPage = pdfDoc.addPage([pageWidth, pageHeight]);
        let currentPageYPos = pageHeight - 80;

        currentPage.drawText('Detailed Vulnerability Analysis', {
            x: 50,
            y: currentPageYPos,
            size: 20,
            font: boldFont,
            color: rgb(0.2, 0.2, 0.2)
        });

        currentPageYPos -= 40;

        for (let i = 0; i < scanData.vulnerabilities.length; i++) {
            const vuln = scanData.vulnerabilities[i];

            // Estimate space needed for this vulnerability, including remediation
            let estimatedVulnHeight = 150; // Base height for header and details
            estimatedVulnHeight += splitTextToFit(vuln.description || '', pageWidth - 120, font, 11).length * 16;
            // A more precise calculation for remediation would involve calling processRemediationSections
            // and getting its total height, but for a general estimate, we can use an average.
            estimatedVulnHeight += 200; // Average height for remediation plan

            if (currentPageYPos < estimatedVulnHeight + 50 && currentPageYPos < pageHeight - 150) {
                currentPage = pdfDoc.addPage([pageWidth, pageHeight]);
                currentPageYPos = pageHeight - 80;

                currentPage.drawText('Detailed Vulnerability Analysis (Continued)', {
                    x: 50,
                    y: currentPageYPos,
                    size: 18,
                    font: boldFont,
                    color: rgb(0.2, 0.2, 0.2)
                });
                currentPageYPos -= 40;
            }

            // Vulnerability header
            const severityColor = vuln.severity === 'CRITICAL' ? rgb(0.8, 0.2, 0.2) :
                                 vuln.severity === 'HIGH' ? rgb(0.9, 0.5, 0.1) :
                                 vuln.severity === 'MEDIUM' ? rgb(0.9, 0.7, 0.1) :
                                 rgb(0.2, 0.6, 0.2);

            currentPage.drawText(`${vuln.type} - ${vuln.severity}`, {
                x: 50,
                y: currentPageYPos,
                size: 16,
                font: boldFont,
                color: severityColor
            });

            currentPageYPos -= 25;

            // Vulnerability details
            const endpointText = sanitizeTextForPDF(vuln.endpoint || 'N/A');
            const descriptionText = sanitizeTextForPDF(vuln.description || 'No description available');

            const details = [
                `Endpoint: ${endpointText}`,
                `Method: ${sanitizeTextForPDF(vuln.method || 'N/A')}`,
                `CWE: ${sanitizeTextForPDF(vuln.cwe || 'N/A')}`,
                `CVSS: ${sanitizeTextForPDF(vuln.cvss || 'N/A')}`
            ];

            for (const detail of details) {
                if (currentPageYPos < 100) {
                    currentPage = pdfDoc.addPage([pageWidth, pageHeight]);
                    currentPageYPos = pageHeight - 80;

                    currentPage.drawText('Detailed Vulnerability Analysis (Continued)', {
                        x: 50,
                        y: currentPageYPos,
                        size: 18,
                        font: boldFont,
                        color: rgb(0.2, 0.2, 0.2)
                    });
                    currentPageYPos -= 40;
                }

                currentPage.drawText(detail, {
                    x: 60,
                    y: currentPageYPos,
                    size: 11,
                    font: font,
                    color: rgb(0.3, 0.3, 0.3)
                });
                currentPageYPos -= 16;
            }

            // Description with proper line handling
            currentPageYPos -= 5;
            currentPage.drawText('Description:', {
                x: 60,
                y: currentPageYPos,
                size: 11,
                font: boldFont,
                color: rgb(0.3, 0.3, 0.3)
            });
            currentPageYPos -= 16;

            const descriptionLines = splitTextToFit(descriptionText, pageWidth - 120, font, 11);
            for (const line of descriptionLines) {
                if (currentPageYPos < 100) {
                    currentPage = pdfDoc.addPage([pageWidth, pageHeight]);
                    currentPageYPos = pageHeight - 80;

                    currentPage.drawText('Detailed Vulnerability Analysis (Continued)', {
                        x: 50,
                        y: currentPageYPos,
                        size: 18,
                        font: boldFont,
                        color: rgb(0.2, 0.2, 0.2)
                    });
                    currentPageYPos -= 40;
                }

                currentPage.drawText(line, {
                    x: 80,
                    y: currentPageYPos,
                    size: 11,
                    font: font,
                    color: rgb(0.3, 0.3, 0.3)
                });
                currentPageYPos -= 16;
            }

            // AI Remediation with proper page tracking
            currentPageYPos -= 10;
            if (currentPageYPos < 100) {
                currentPage = pdfDoc.addPage([pageWidth, pageHeight]);
                currentPageYPos = pageHeight - 80;

                currentPage.drawText('Detailed Vulnerability Analysis (Continued)', {
                    x: 50,
                    y: currentPageYPos,
                    size: 18,
                    font: boldFont,
                    color: rgb(0.2, 0.2, 0.2)
                });
                currentPageYPos -= 40;
            }

            currentPage.drawText('AI Remediation Plan:', {
                x: 50,
                y: currentPageYPos,
                size: 14,
                font: boldFont,
                color: rgb(0.2, 0.2, 0.2)
            });

            currentPageYPos -= 20;

            try {
                const aiRemediation = await generateAIRemediation(vuln);
                const remediationText = aiRemediation && aiRemediation.trim() ?
                    sanitizeTextForPDF(aiRemediation) :
                    generateFallbackRemediation(vuln);

                const { currentPage: updatedPage, currentPageYPos: updatedYPos } = await processRemediationSections(
                    remediationText,
                    currentPage,
                    currentPageYPos,
                    pdfDoc,
                    pageWidth,
                    pageHeight,
                    font,
                    boldFont
                );
                currentPage = updatedPage;
                currentPageYPos = updatedYPos;

            } catch (error) {
                const fallbackRemediation = generateFallbackRemediation(vuln);
                const { currentPage: updatedPage, currentPageYPos: updatedYPos } = await processRemediationSections(
                    fallbackRemediation,
                    currentPage,
                    currentPageYPos,
                    pdfDoc,
                    pageWidth,
                    pageHeight,
                    font,
                    boldFont
                );
                currentPage = updatedPage;
                currentPageYPos = updatedYPos;
            }

            currentPageYPos -= 30; // Space between vulnerabilities
        }

        // Page 3: Compliance and Recommendations
        const page3 = pdfDoc.addPage([pageWidth, pageHeight]);

        page3.drawText('Compliance Assessment & Recommendations', {
            x: 50,
            y: pageHeight - 80,
            size: 20,
            font: boldFont,
            color: rgb(0.2, 0.2, 0.2)
        });

        yPos = pageHeight - 120;

        // Compliance status
        const complianceStandards = [
            'OWASP Top 10',
            'PCI DSS',
            'GDPR',
            'ISO 27001',
            'SOC 2'
        ];

        page3.drawText('Compliance Status:', {
            x: 50,
            y: yPos,
            size: 16,
            font: boldFont,
            color: rgb(0.2, 0.2, 0.2)
        });

        yPos -= 25;

        complianceStandards.forEach(standard => {
            const status = scanData.vulnerabilities.length > 0 ? 'NON-COMPLIANT' : 'COMPLIANT';
            const statusColor = status === 'NON-COMPLIANT' ? rgb(0.8, 0.2, 0.2) : rgb(0.2, 0.6, 0.2);

            page3.drawText(`${standard}: ${status}`, {
                x: 60,
                y: yPos,
                size: 12,
                font: font,
                color: statusColor
            });
            yPos -= 18;
        });

        // Recommendations
        yPos -= 20;
        page3.drawText('Key Recommendations:', {
            x: 50,
            y: yPos,
            size: 16,
            font: boldFont,
            color: rgb(0.2, 0.2, 0.2)
        });

        yPos -= 25;

        const recommendations = [
            'Immediate remediation of critical and high severity vulnerabilities',
            'Implement comprehensive input validation and sanitization',
            'Deploy Web Application Firewall (WAF) protection',
            'Establish regular security testing and vulnerability assessments',
            'Enhance API authentication and authorization mechanisms',
            'Implement proper error handling and logging',
            'Conduct security awareness training for development teams'
        ];

        for (const rec of recommendations) {
            const recLines = splitTextToFit(`• ${rec}`, pageWidth - 120, font, 11);
            for (const line of recLines) {
                if (yPos < 100) { // Check for space before drawing each line of recommendation
                    const newPage = pdfDoc.addPage([pageWidth, pageHeight]);
                    yPos = pageHeight - 80;
                    newPage.drawText('Key Recommendations (Continued):', {
                        x: 50,
                        y: yPos,
                        size: 16,
                        font: boldFont,
                        color: rgb(0.2, 0.2, 0.2)
                    });
                    yPos -= 25;
                    page3.drawText(line, {
                        x: 60,
                        y: yPos,
                        size: 11,
                        font: font,
                        color: rgb(0.3, 0.3, 0.3)
                    });
                    yPos -= 16;
                } else {
                    page3.drawText(line, {
                        x: 60,
                        y: yPos,
                        size: 11,
                        font: font,
                        color: rgb(0.3, 0.3, 0.3)
                    });
                    yPos -= 16;
                }
            }
        }


        // Footer on last page
        const pages = pdfDoc.getPages();
        const lastPage = pages[pages.length - 1];
        lastPage.drawText(`Report generated by AI-Powered Security Assessment Tool - Page ${pages.length}`, {
            x: 50,
            y: 50,
            size: 10,
            font: font,
            color: rgb(0.5, 0.5, 0.5)
        });

        const pdfBytes = await pdfDoc.save();
        return pdfBytes;

    } catch (error) {
        console.error('PDF generation error:', error);
        throw new Error(`PDF generation failed: ${error.message}`);
    }
}

// **NEW**: Helper function to process remediation sections properly
async function processRemediationSections(
    remediationText: string,
    initialCurrentPage: any,
    initialCurrentPageYPos: number,
    pdfDoc: any,
    pageWidth: number,
    pageHeight: number,
    font: any,
    boldFont: any
): Promise<{ currentPage: any, currentPageYPos: number }> {
    let currentPage = initialCurrentPage;
    let currentPageYPos = initialCurrentPageYPos;

    const sections = remediationText.split(/(?=\d+\.)/g).filter(section => section.trim());

    for (const section of sections) {
        const trimmedSection = section.trim();
        if (!trimmedSection) continue;

        // Estimate space needed for this section
        let estimatedSectionHeight = 20; // For section number/header
        const contentMatch = trimmedSection.match(/^\d+\.\s*(.*)/s);
        if (contentMatch) {
            const content = contentMatch[1];
            estimatedSectionHeight += splitTextToFit(content, pageWidth - 140, font, 11).length * 16;
        }
        estimatedSectionHeight += 10; // Extra space between sections

        // Check if we need a new page before drawing this section
        if (currentPageYPos < estimatedSectionHeight + 50) {
            currentPage = pdfDoc.addPage([pageWidth, pageHeight]);
            currentPageYPos = pageHeight - 80;

            currentPage.drawText('Detailed Vulnerability Analysis (Continued)', {
                x: 50,
                y: pageHeight - 80,
                size: 18,
                font: boldFont,
                color: rgb(0.2, 0.2, 0.2)
            });
            currentPageYPos = pageHeight - 120;
        }

        // Extract section number and content
        const sectionMatch = trimmedSection.match(/^(\d+)\.\s*(.*)/s);
        if (sectionMatch) {
            const [, sectionNum, content] = sectionMatch;

            // Draw section number
            currentPage.drawText(`${sectionNum}.`, {
                x: 60,
                y: currentPageYPos,
                size: 11,
                font: boldFont,
                color: rgb(0.2, 0.2, 0.2)
            });

            currentPageYPos -= 20;

            // Draw section content
            const contentLines = splitTextToFit(content, pageWidth - 140, font, 11);
            for (const line of contentLines) {
                if (currentPageYPos < 100) {
                    currentPage = pdfDoc.addPage([pageWidth, pageHeight]);
                    currentPageYPos = pageHeight - 80;

                    currentPage.drawText('Detailed Vulnerability Analysis (Continued)', {
                        x: 50,
                        y: pageHeight - 80,
                        size: 18,
                        font: boldFont,
                        color: rgb(0.2, 0.2, 0.2)
                    });
                    currentPageYPos = pageHeight - 120;
                }

                currentPage.drawText(line, {
                    x: 80,
                    y: currentPageYPos,
                    size: 11,
                    font: font,
                    color: rgb(0.3, 0.3, 0.3)
                });
                currentPageYPos -= 16;
            }
            currentPageYPos -= 10; // Extra space between sections
        }
    }

    return { currentPage, currentPageYPos };
}

function splitTextToFit(text: string, maxWidth: number, font: any, fontSize: number): string[] {
    const sanitizedText = text
        .replace(/\r\n/g, ' ')
        .replace(/\r/g, ' ')
        .replace(/\n/g, ' ')
        .replace(/\t/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();

    const words = sanitizedText.split(' ');
    const lines: string[] = [];
    let currentLine = '';

    for (const word of words) {
        const testLine = currentLine ? `${currentLine} ${word}` : word;
        const testWidth = font.widthOfTextAtSize(testLine, fontSize);

        if (testWidth <= maxWidth) {
            currentLine = testLine;
        } else {
            if (currentLine) {
                lines.push(currentLine);
            }
            // If the current word itself is too long, split it
            if (font.widthOfTextAtSize(word, fontSize) > maxWidth) {
                let tempWord = word;
                while (font.widthOfTextAtSize(tempWord, fontSize) > maxWidth) {
                    let chars = tempWord.length;
                    let splitPoint = Math.floor(chars * (maxWidth / font.widthOfTextAtSize(tempWord, fontSize)));
                    if (splitPoint === 0) splitPoint = 1; // Ensure at least one character is taken
                    lines.push(tempWord.substring(0, splitPoint));
                    tempWord = tempWord.substring(splitPoint);
                }
                currentLine = tempWord;
            } else {
                currentLine = word;
            }
        }
    }

    if (currentLine) {
        lines.push(currentLine);
    }

    return lines;
}

function sanitizeTextForPDF(text: string): string {
    return text
        .replace(/\r\n/g, ' ')
        .replace(/\r/g, ' ')
        .replace(/\n/g, ' ')
        .replace(/\t/g, ' ')
        .replace(/\s+/g, ' ')
        .replace(/[^\x20-\x7E]/g, '')
        .trim();
}

function calculateFallbackRiskScore(vulnerabilities: Vulnerability[]): number {
    if (!vulnerabilities || vulnerabilities.length === 0) return 0;

    const severityScores = {
        'CRITICAL': 100,
        'HIGH': 75,
        'MEDIUM': 50,
        'LOW': 25,
        'INFO': 10
    };

    return vulnerabilities.reduce((total, vuln) => {
        return total + (severityScores[vuln.severity] || 0);
    }, 0);
}

function generateFallbackRemediation(vulnerability: Vulnerability): string {
    const severity = vulnerability.severity;
    const type = vulnerability.type;

    return `1. Immediate Action (Within 1 hour): Disable or restrict access to the affected endpoint immediately. Implement temporary blocking at the web server or load balancer level to prevent further data exposure.

2. Technical Fix (Within 24 hours): Review the application code handling the ${vulnerability.endpoint} endpoint. Remove any hardcoded sensitive data, tokens, or credentials from the response. Implement proper input validation and output sanitization.

3. Security Enhancement (Within 1 week): Implement proper secrets management using environment variables or a secure vault. Add comprehensive logging and monitoring for sensitive data access. Configure security headers and implement rate limiting.

4. Verification Step: Test the endpoint to ensure no sensitive data is exposed. Perform a security scan to verify the vulnerability is resolved. Monitor logs for any suspicious activity.`;
}