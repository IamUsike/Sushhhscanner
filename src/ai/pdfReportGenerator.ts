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
        // Use built-in fonts instead of custom fonts
        const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
        const boldFont = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
        
        // Page 1: Executive Summary
        const page1 = pdfDoc.addPage([595.28, 841.89]); // A4
        const { width, height } = page1.getSize();
        
        // Title
        page1.drawText('Security Vulnerability Assessment Report', {
            x: 50,
            y: height - 80,
            size: 24,
            font: boldFont,
            color: rgb(0.2, 0.2, 0.2)
        });
        
        page1.drawText('Comprehensive API Security Analysis', {
            x: 50,
            y: height - 110,
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
            `Endpoints Discovered: ${scanData.endpointsDiscovered}`,
            `Total Risk Score: ${scanData.totalRiskScore}`,
            `CVSS Score: ${scanData.cvssScore}`,
            `Scan Duration: ${scanData.duration}s`
        ];
        
        let yPos = height - 160;
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
        const summary = `This security assessment identified ${scanData.vulnerabilities.length} vulnerabilities across ${scanData.endpointsDiscovered} API endpoints. The overall risk score of ${scanData.totalRiskScore} indicates ${scanData.totalRiskScore > 75 ? 'critical' : scanData.totalRiskScore > 50 ? 'high' : 'moderate'} security concerns requiring immediate attention.`;
        
        const summaryLines = splitTextToFit(summary, width - 100, font, 12);
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
        
        // Page 2: Detailed Vulnerabilities with AI Remediation
        const page2 = pdfDoc.addPage([595.28, 841.89]);
        
        page2.drawText('Detailed Vulnerability Analysis', {
            x: 50,
            y: height - 80,
            size: 20,
            font: boldFont,
            color: rgb(0.2, 0.2, 0.2)
        });
        
        yPos = height - 120;
        
        for (let i = 0; i < scanData.vulnerabilities.length && yPos > 100; i++) {
            const vuln = scanData.vulnerabilities[i];
            
            // Vulnerability header
            const severityColor = vuln.severity === 'CRITICAL' ? rgb(0.8, 0.2, 0.2) : 
                                 vuln.severity === 'HIGH' ? rgb(0.9, 0.5, 0.1) :
                                 vuln.severity === 'MEDIUM' ? rgb(0.9, 0.7, 0.1) :
                                 rgb(0.2, 0.6, 0.2);
            
            page2.drawText(`${vuln.type} - ${vuln.severity}`, {
                x: 50,
                y: yPos,
                size: 16,
                font: boldFont,
                color: severityColor
            });
            
            yPos -= 25;
            
            // Vulnerability details
            const details = [
                `Endpoint: ${vuln.endpoint}`,
                `Method: ${vuln.method}`,
                `CWE: ${vuln.cwe || 'N/A'}`,
                `CVSS: ${vuln.cvss || 'N/A'}`,
                `Description: ${vuln.description}`
            ];
            
            details.forEach(detail => {
                if (yPos > 100) {
                    page2.drawText(detail, {
                        x: 60,
                        y: yPos,
                        size: 11,
                        font: font,
                        color: rgb(0.3, 0.3, 0.3)
                    });
                    yPos -= 16;
                }
            });
            
            // AI Remediation
            yPos -= 10;
            if (yPos > 100) {
                page2.drawText('AI Remediation Plan:', {
                    x: 50,
                    y: yPos,
                    size: 14,
                    font: boldFont,
                    color: rgb(0.2, 0.2, 0.2)
                });
                
                yPos -= 20;
                
                try {
                    const aiRemediation = await generateAIRemediation(vuln);
                    const remediationLines = splitTextToFit(aiRemediation, width - 100, font, 11);
                    
                    remediationLines.forEach(line => {
                        if (yPos > 100) {
                            page2.drawText(line, {
                                x: 60,
                                y: yPos,
                                size: 11,
                                font: font,
                                color: rgb(0.3, 0.3, 0.3)
                            });
                            yPos -= 15;
                        }
                    });
                } catch (error) {
                    if (yPos > 100) {
                        page2.drawText('AI remediation generation failed. Please review manually.', {
                            x: 60,
                            y: yPos,
                            size: 11,
                            font: font,
                            color: rgb(0.6, 0.3, 0.3)
                        });
                        yPos -= 15;
                    }
                }
                
                yPos -= 20;
            }
            
            // Add new page if needed
            if (yPos < 150 && i < scanData.vulnerabilities.length - 1) {
                const newPage = pdfDoc.addPage([595.28, 841.89]);
                yPos = height - 80;
            }
        }
        
        // Page 3: Compliance and Recommendations
        const page3 = pdfDoc.addPage([595.28, 841.89]);
        
        page3.drawText('Compliance Assessment & Recommendations', {
            x: 50,
            y: height - 80,
            size: 20,
            font: boldFont,
            color: rgb(0.2, 0.2, 0.2)
        });
        
        yPos = height - 120;
        
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
        
        recommendations.forEach(rec => {
            if (yPos > 100) {
                page3.drawText(`• ${rec}`, {
                    x: 60,
                    y: yPos,
                    size: 11,
                    font: font,
                    color: rgb(0.3, 0.3, 0.3)
                });
                yPos -= 16;
            }
        });
        
        // Footer
        page3.drawText(`Report generated by AI-Powered Security Assessment Tool - Page ${pdfDoc.getPageCount()}`, {
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

function splitTextToFit(text: string, maxWidth: number, font: any, fontSize: number): string[] {
    const words = text.split(' ');
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
                currentLine = word;
            } else {
                // Word is too long, split it
                lines.push(word.substring(0, Math.floor(maxWidth / fontSize * 2)));
                currentLine = word.substring(Math.floor(maxWidth / fontSize * 2));
            }
        }
    }
    
    if (currentLine) {
        lines.push(currentLine);
    }
    
    return lines;
} 