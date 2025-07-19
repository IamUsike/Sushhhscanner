import { Vulnerability, VulnerabilitySeverity, VulnerabilityType } from '../types';
interface SensitiveDataFinding {
    type: VulnerabilityType;
    match: string;
    context: string;
    severity: VulnerabilitySeverity;
    description: string;
}
export declare class SensitiveDataDetector {
    private static readonly PATTERNS;
    /**
     * Scans text content (e.g., response body or headers) for sensitive data.
     * @param content The text content to scan.
     * @param context A string indicating where the content came from (e.g., "response_body", "header: Content-Type").
     * @returns An array of SensitiveDataFinding objects.
     */
    scan(content: string, context?: string): SensitiveDataFinding[];
    /**
     * Converts SensitiveDataFinding objects into Vulnerability objects.
     * This is a helper for integrating with the existing vulnerability reporting.
     * @param findings An array of SensitiveDataFinding objects.
     * @param endpoint The endpoint URL associated with the finding.
     * @param method The HTTP method associated with the finding.
     * @returns An array of Vulnerability objects.
     */
    static findingsToVulnerabilities(findings: SensitiveDataFinding[], endpoint: string, method: string): Vulnerability[];
}
export {};
//# sourceMappingURL=sensitiveDataDetector.d.ts.map