import { MisconfigurationDetector, MisconfigurationResult, MisconfigurationScanOptions } from './misconfigurationDetector';
import { ConfigurationAnalyzer, ConfigurationFile, APIConfiguration } from './configurationAnalyzer';
import { logger } from '../utils/logger';
import axios from 'axios';

export interface MisconfigurationScanResult {
  target: string;
  scanStartTime: string;
  scanEndTime: string;
  scanDuration: number;
  totalIssues: number;
  issuesBySeverity: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
    INFO: number;
  };
  issuesByCategory: Record<string, number>;
  complianceStatus: {
    owaspTop10: {
      covered: string[];
      issues: number;
    };
    cweMapping: Record<string, number>;
  };
  findings: MisconfigurationResult[];
  recommendations: string[];
  executiveSummary: string;
}

export interface ComprehensiveScanOptions extends MisconfigurationScanOptions {
  includeConfigAnalysis?: boolean;
  analyzeSwagger?: boolean;
  checkCloudConfig?: boolean;
  generateReport?: boolean;
  exportFormat?: 'json' | 'html' | 'csv';
}

export class MisconfigurationScanner {
  private detector: MisconfigurationDetector;
  private configAnalyzer: ConfigurationAnalyzer;

  constructor(private options: ComprehensiveScanOptions = {}) {
    this.detector = new MisconfigurationDetector(options);
    this.configAnalyzer = new ConfigurationAnalyzer();
  }

  async scanTarget(
    target: string,
    progressCallback?: (progress: string) => void
  ): Promise<MisconfigurationScanResult> {
    const scanStartTime = new Date().toISOString();
    logger.info(`Starting comprehensive misconfiguration scan for: ${target}`);

    if (progressCallback) {
      progressCallback('🚀 Initializing misconfiguration scanner...');
    }

    try {
      const allFindings: MisconfigurationResult[] = [];
      let scanDuration = 0;

      // 1. Primary Misconfiguration Detection
      if (progressCallback) {
        progressCallback('🔍 Running primary misconfiguration detection...');
      }

      const primaryFindings = await this.detector.scanTarget(target, progressCallback);
      allFindings.push(...primaryFindings);

      // 2. Configuration File Analysis
      if (this.options.includeConfigAnalysis !== false) {
        if (progressCallback) {
          progressCallback('📋 Analyzing configuration files...');
        }

        const configFindings = await this.analyzeConfigurationFiles(target);
        allFindings.push(...configFindings);
      }

      // 3. Swagger/OpenAPI Analysis
      if (this.options.analyzeSwagger !== false) {
        if (progressCallback) {
          progressCallback('📚 Analyzing API documentation...');
        }

        const swaggerFindings = await this.analyzeSwaggerConfigurations(target);
        allFindings.push(...swaggerFindings);
      }

      // 4. Cloud Configuration Analysis (if applicable)
      if (this.options.checkCloudConfig) {
        if (progressCallback) {
          progressCallback('☁️ Checking cloud configurations...');
        }

        const cloudFindings = await this.analyzeCloudConfigurations(target);
        allFindings.push(...cloudFindings);
      }

      const scanEndTime = new Date().toISOString();
      scanDuration = new Date(scanEndTime).getTime() - new Date(scanStartTime).getTime();

      if (progressCallback) {
        progressCallback('📊 Generating comprehensive report...');
      }

      // Generate comprehensive report
      const scanResult = this.generateScanResult(
        target,
        scanStartTime,
        scanEndTime,
        scanDuration,
        allFindings
      );

      if (progressCallback) {
        progressCallback('✅ Misconfiguration scan completed successfully!');
      }

      logger.info(`Misconfiguration scan completed. Found ${allFindings.length} total issues.`);
      return scanResult;

    } catch (error: any) {
      logger.error(`Misconfiguration scan failed: ${error.message}`);
      throw new Error(`Scan failed: ${error.message}`);
    }
  }

  private async analyzeConfigurationFiles(target: string): Promise<MisconfigurationResult[]> {
    const findings: MisconfigurationResult[] = [];

    try {
      // Common configuration files to check
      const configFiles = [
        { path: '/.env', type: 'env' as const },
        { path: '/.env.production', type: 'env' as const },
        { path: '/config.json', type: 'json' as const },
        { path: '/package.json', type: 'json' as const },
        { path: '/composer.json', type: 'json' as const },
        { path: '/web.config', type: 'xml' as const },
        { path: '/docker-compose.yml', type: 'yaml' as const },
        { path: '/docker-compose.yaml', type: 'yaml' as const },
        { path: '/config.yml', type: 'yaml' as const },
        { path: '/config.yaml', type: 'yaml' as const },
        { path: '/database.yml', type: 'yaml' as const },
        { path: '/.github/workflows/main.yml', type: 'yaml' as const }
      ];

      for (const configFile of configFiles) {
        try {
          const fileUrl = `${target.replace(/\/$/, '')}${configFile.path}`;
          const response = await axios.get(fileUrl, {
            timeout: 10000,
            validateStatus: () => true
          });

          if (response.status === 200 && response.data) {
            const configFileData: ConfigurationFile = {
              filename: configFile.path,
              content: typeof response.data === 'string' ? response.data : JSON.stringify(response.data),
              type: configFile.type,
              url: fileUrl
            };

            const configResults = await this.configAnalyzer.analyzeConfiguration(configFileData);
            findings.push(...configResults);
          }
        } catch (error) {
          // Expected for most files - they should not be accessible
        }
      }

    } catch (error: any) {
      logger.warn(`Configuration file analysis failed: ${error.message}`);
    }

    return findings;
  }

  private async analyzeSwaggerConfigurations(target: string): Promise<MisconfigurationResult[]> {
    const findings: MisconfigurationResult[] = [];

    try {
      // Common Swagger/OpenAPI paths
      const swaggerPaths = [
        '/swagger.json',
        '/swagger.yaml',
        '/swagger.yml',
        '/openapi.json',
        '/openapi.yaml',
        '/openapi.yml',
        '/api-docs',
        '/api/swagger.json',
        '/api/docs',
        '/docs/swagger.json',
        '/v1/swagger.json',
        '/v2/swagger.json'
      ];

      for (const swaggerPath of swaggerPaths) {
        try {
          const swaggerUrl = `${target.replace(/\/$/, '')}${swaggerPath}`;
          const response = await axios.get(swaggerUrl, {
            timeout: 10000,
            validateStatus: () => true,
            headers: { 'Accept': 'application/json, application/yaml, text/yaml' }
          });

          if (response.status === 200 && response.data) {
            let swaggerData;
            try {
              swaggerData = typeof response.data === 'string' ? JSON.parse(response.data) : response.data;
            } catch {
              // If JSON parsing fails, try treating as YAML (simplified)
              continue;
            }

            if (swaggerData && (swaggerData.swagger || swaggerData.openapi)) {
              // Extract endpoints from Swagger
              const endpoints: any[] = [];
              if (swaggerData.paths) {
                for (const [path, pathObj] of Object.entries(swaggerData.paths)) {
                  if (typeof pathObj === 'object' && pathObj) {
                    for (const [method, methodObj] of Object.entries(pathObj)) {
                      if (['get', 'post', 'put', 'delete', 'patch', 'options', 'head'].includes(method)) {
                        endpoints.push({
                          path,
                          method: method.toUpperCase(),
                          authentication: (methodObj as any)?.security || swaggerData.security,
                          parameters: (methodObj as any)?.parameters
                        });
                      }
                    }
                  }
                }
              }

              const apiConfig: APIConfiguration = {
                endpoints,
                security: swaggerData.security,
                swagger: swaggerData
              };

              const swaggerResults = await this.configAnalyzer.analyzeAPIConfiguration(apiConfig, target);
              findings.push(...swaggerResults);
            }
          }
        } catch (error) {
          // Expected for most paths
        }
      }

    } catch (error: any) {
      logger.warn(`Swagger configuration analysis failed: ${error.message}`);
    }

    return findings;
  }

  private async analyzeCloudConfigurations(target: string): Promise<MisconfigurationResult[]> {
    const findings: MisconfigurationResult[] = [];

    try {
      // Check for cloud metadata endpoints
      const cloudMetadataPaths = [
        '/.well-known/cloud-metadata',
        '/metadata',
        '/latest/meta-data/',
        '/computeMetadata/v1/',
        '/metadata/instance'
      ];

      for (const metadataPath of cloudMetadataPaths) {
        try {
          const metadataUrl = `${target.replace(/\/$/, '')}${metadataPath}`;
          const response = await axios.get(metadataUrl, {
            timeout: 5000,
            validateStatus: () => true,
            headers: { 'Metadata-Flavor': 'Google' } // For GCP
          });

          if (response.status === 200 && response.data) {
            findings.push({
              category: 'Cloud Configuration',
              type: 'exposed_metadata_endpoint',
              severity: 'HIGH',
              confidence: 0.9,
              title: 'Exposed Cloud Metadata Endpoint',
              description: `Cloud metadata endpoint is accessible at ${metadataPath}, potentially exposing instance credentials.`,
              evidence: {
                url: metadataUrl,
                response: this.truncateContent(response.data),
                statusCode: response.status
              },
              cwe: 'CWE-200',
              owasp: 'A05:2021 – Security Misconfiguration',
              recommendation: 'Restrict access to cloud metadata endpoints and implement proper network controls.',
              impact: 'Exposed metadata can reveal instance credentials and sensitive cloud configuration.',
              references: [
                'https://owasp.org/www-project-cloud-security/',
                'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html'
              ]
            });
          }
        } catch (error) {
          // Expected for most endpoints
        }
      }

    } catch (error: any) {
      logger.warn(`Cloud configuration analysis failed: ${error.message}`);
    }

    return findings;
  }

  private generateScanResult(
    target: string,
    scanStartTime: string,
    scanEndTime: string,
    scanDuration: number,
    findings: MisconfigurationResult[]
  ): MisconfigurationScanResult {
    
    // Calculate issue counts by severity
    const issuesBySeverity = {
      CRITICAL: findings.filter(f => f.severity === 'CRITICAL').length,
      HIGH: findings.filter(f => f.severity === 'HIGH').length,
      MEDIUM: findings.filter(f => f.severity === 'MEDIUM').length,
      LOW: findings.filter(f => f.severity === 'LOW').length,
      INFO: findings.filter(f => f.severity === 'INFO').length
    };

    // Calculate issue counts by category
    const issuesByCategory: Record<string, number> = {};
    findings.forEach(finding => {
      issuesByCategory[finding.category] = (issuesByCategory[finding.category] || 0) + 1;
    });

    // OWASP Top 10 compliance analysis
    const owaspMappings = findings.map(f => f.owasp);
    const uniqueOwaspCategories = [...new Set(owaspMappings)];
    
    // CWE mapping analysis
    const cweMappings: Record<string, number> = {};
    findings.forEach(finding => {
      cweMappings[finding.cwe] = (cweMappings[finding.cwe] || 0) + 1;
    });

    // Generate recommendations
    const recommendations = this.generateRecommendations(findings, issuesBySeverity);

    // Generate executive summary
    const executiveSummary = this.generateExecutiveSummary(target, findings, issuesBySeverity);

    return {
      target,
      scanStartTime,
      scanEndTime,
      scanDuration,
      totalIssues: findings.length,
      issuesBySeverity,
      issuesByCategory,
      complianceStatus: {
        owaspTop10: {
          covered: uniqueOwaspCategories,
          issues: findings.length
        },
        cweMapping: cweMappings
      },
      findings,
      recommendations,
      executiveSummary
    };
  }

  private generateRecommendations(findings: MisconfigurationResult[], severityBreakdown: any): string[] {
    const recommendations: string[] = [];

    if (severityBreakdown.CRITICAL > 0) {
      recommendations.push('🚨 IMMEDIATE ACTION REQUIRED: Address all CRITICAL severity issues as they pose immediate security risks.');
    }

    if (severityBreakdown.HIGH > 0) {
      recommendations.push('⚠️ HIGH PRIORITY: Review and remediate HIGH severity issues within 24-48 hours.');
    }

    // Category-specific recommendations
    const categoryCount = findings.reduce((acc, finding) => {
      acc[finding.category] = (acc[finding.category] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    Object.entries(categoryCount).forEach(([category, count]) => {
      if (count >= 3) {
        switch (category) {
          case 'HTTP Security Headers':
            recommendations.push('🛡️ Implement comprehensive HTTP security headers to prevent common web attacks.');
            break;
          case 'Sensitive File Exposure':
            recommendations.push('📄 Review and secure all exposed configuration and sensitive files.');
            break;
          case 'CORS Misconfiguration':
            recommendations.push('🌐 Review and tighten CORS policies to prevent cross-origin attacks.');
            break;
          case 'Information Disclosure':
            recommendations.push('🔒 Minimize information disclosure in headers, error messages, and server responses.');
            break;
        }
      }
    });

    if (recommendations.length === 0) {
      recommendations.push('✅ Consider implementing additional security hardening measures as a best practice.');
    }

    return recommendations;
  }

  private generateExecutiveSummary(target: string, findings: MisconfigurationResult[], severityBreakdown: any): string {
    const totalIssues = findings.length;
    const riskLevel = this.calculateOverallRiskLevel(severityBreakdown);
    
    let summary = `Security misconfiguration assessment of ${target} identified ${totalIssues} potential issues. `;
    
    if (severityBreakdown.CRITICAL > 0) {
      summary += `${severityBreakdown.CRITICAL} CRITICAL issues require immediate attention. `;
    }
    
    if (severityBreakdown.HIGH > 0) {
      summary += `${severityBreakdown.HIGH} HIGH severity issues should be addressed promptly. `;
    }

    summary += `Overall security posture is assessed as ${riskLevel}. `;

    // Top categories
    const topCategories = Object.entries(
      findings.reduce((acc, f) => {
        acc[f.category] = (acc[f.category] || 0) + 1;
        return acc;
      }, {} as Record<string, number>)
    )
    .sort(([,a], [,b]) => b - a)
    .slice(0, 3)
    .map(([category, count]) => `${category} (${count})`);

    if (topCategories.length > 0) {
      summary += `Primary concern areas include: ${topCategories.join(', ')}.`;
    }

    return summary;
  }

  private calculateOverallRiskLevel(severityBreakdown: any): string {
    if (severityBreakdown.CRITICAL > 0) return 'HIGH RISK';
    if (severityBreakdown.HIGH >= 3) return 'HIGH RISK';
    if (severityBreakdown.HIGH > 0 || severityBreakdown.MEDIUM >= 5) return 'MEDIUM RISK';
    if (severityBreakdown.MEDIUM > 0 || severityBreakdown.LOW >= 3) return 'LOW RISK';
    return 'MINIMAL RISK';
  }

  private truncateContent(content: string): string {
    const str = typeof content === 'string' ? content : JSON.stringify(content);
    return str.length > 500 ? str.substring(0, 500) + '...[truncated]' : str;
  }

  // Export functionality
  async exportReport(scanResult: MisconfigurationScanResult, format: 'json' | 'html' | 'csv' = 'json'): Promise<string> {
    switch (format) {
      case 'json':
        return JSON.stringify(scanResult, null, 2);
      
      case 'html':
        return this.generateHTMLReport(scanResult);
      
      case 'csv':
        return this.generateCSVReport(scanResult);
      
      default:
        throw new Error(`Unsupported export format: ${format}`);
    }
  }

  private generateHTMLReport(scanResult: MisconfigurationScanResult): string {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Misconfiguration Scan Report - ${scanResult.target}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
        .header { background: #f4f4f4; padding: 20px; border-radius: 5px; margin-bottom: 30px; }
        .severity-critical { color: #dc3545; font-weight: bold; }
        .severity-high { color: #fd7e14; font-weight: bold; }
        .severity-medium { color: #ffc107; font-weight: bold; }
        .severity-low { color: #28a745; font-weight: bold; }
        .finding { border: 1px solid #ddd; margin: 15px 0; padding: 15px; border-radius: 5px; }
        .finding h3 { margin-top: 0; }
        .evidence { background: #f8f9fa; padding: 10px; border-radius: 3px; font-family: monospace; }
        .summary-stats { display: flex; gap: 20px; margin: 20px 0; }
        .stat-box { background: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Misconfiguration Report</h1>
        <p><strong>Target:</strong> ${scanResult.target}</p>
        <p><strong>Scan Date:</strong> ${scanResult.scanStartTime}</p>
        <p><strong>Duration:</strong> ${Math.round(scanResult.scanDuration / 1000)}s</p>
    </div>

    <h2>Executive Summary</h2>
    <p>${scanResult.executiveSummary}</p>

    <div class="summary-stats">
        <div class="stat-box">
            <h3>Total Issues</h3>
            <p style="font-size: 2em; margin: 0;">${scanResult.totalIssues}</p>
        </div>
        <div class="stat-box">
            <h3>Critical</h3>
            <p style="font-size: 2em; margin: 0; color: #dc3545;">${scanResult.issuesBySeverity.CRITICAL}</p>
        </div>
        <div class="stat-box">
            <h3>High</h3>
            <p style="font-size: 2em; margin: 0; color: #fd7e14;">${scanResult.issuesBySeverity.HIGH}</p>
        </div>
        <div class="stat-box">
            <h3>Medium</h3>
            <p style="font-size: 2em; margin: 0; color: #ffc107;">${scanResult.issuesBySeverity.MEDIUM}</p>
        </div>
    </div>

    <h2>Detailed Findings</h2>
    ${scanResult.findings.map(finding => `
        <div class="finding">
            <h3 class="severity-${finding.severity.toLowerCase()}">${finding.title}</h3>
            <p><strong>Category:</strong> ${finding.category}</p>
            <p><strong>Severity:</strong> <span class="severity-${finding.severity.toLowerCase()}">${finding.severity}</span></p>
            <p><strong>Confidence:</strong> ${Math.round(finding.confidence * 100)}%</p>
            <p><strong>Description:</strong> ${finding.description}</p>
            <p><strong>Impact:</strong> ${finding.impact}</p>
            <p><strong>Recommendation:</strong> ${finding.recommendation}</p>
            ${finding.evidence.url ? `<p><strong>URL:</strong> ${finding.evidence.url}</p>` : ''}
            ${finding.evidence.content ? `<div class="evidence"><strong>Evidence:</strong><br>${finding.evidence.content}</div>` : ''}
        </div>
    `).join('')}

    <h2>Recommendations</h2>
    <ul>
        ${scanResult.recommendations.map(rec => `<li>${rec}</li>`).join('')}
    </ul>
</body>
</html>`;
  }

  private generateCSVReport(scanResult: MisconfigurationScanResult): string {
    const headers = ['Category', 'Type', 'Severity', 'Title', 'Description', 'CWE', 'OWASP', 'Recommendation', 'URL'];
    const rows = scanResult.findings.map(finding => [
      finding.category,
      finding.type,
      finding.severity,
      finding.title,
      finding.description,
      finding.cwe,
      finding.owasp,
      finding.recommendation,
      finding.evidence.url || ''
    ]);

    return [headers, ...rows]
      .map(row => row.map(cell => `"${cell.replace(/"/g, '""')}"`).join(','))
      .join('\n');
  }
} 