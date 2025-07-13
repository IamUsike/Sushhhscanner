import { logger } from '../utils/logger';
import { Vulnerability, VulnerabilitySeverity, VulnerabilityType } from '../types';

interface SensitiveDataFinding {
  type: VulnerabilityType;
  match: string;
  context: string; // e.g., "response_body", "header"
  severity: VulnerabilitySeverity;
  description: string;
}

interface PatternDefinition {
  regex: RegExp;
  type: VulnerabilityType;
  severity: VulnerabilitySeverity;
  description: string;
}

export class SensitiveDataDetector {
  // Regex patterns for common sensitive data types
  private static readonly PATTERNS: Record<string, PatternDefinition> = {
    EMAIL_ADDRESS: {
      regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
      type: 'PII_EXPOSURE',
      severity: 'HIGH',
      description: 'Potential exposure of email address.'
    },
    CREDIT_CARD_NUMBER: {
      // Visa, MasterCard, Amex, Discover, Diners Club, JCB
      regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b/g,
      type: 'SENSITIVE_DATA_EXPOSURE',
      severity: 'CRITICAL',
      description: 'Potential exposure of credit card number.'
    },
    SSN: {
      // Social Security Number (basic pattern for NNN-NN-NNNN or NNN NN NNNN)
      regex: /\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b/g,
      type: 'PII_EXPOSURE',
      severity: 'CRITICAL',
      description: 'Potential exposure of Social Security Number.'
    },
    API_KEY_GENERIC: {
      // Generic API Key pattern (e.g., starts with "sk-" or "api_key=" followed by alphanumeric)
      regex: /\b(?:api_key|api_secret|token|pass|secret|auth|access_key)[\s=:\"']{0,3}([A-Za-z0-9_\-]{16,64})\b/gi,
      type: 'SENSITIVE_DATA_EXPOSURE',
      severity: 'CRITICAL',
      description: 'Potential exposure of generic API key/secret.'
    },
    PRIVATE_KEY: {
      // Basic detection for RSA/SSH private keys
      regex: /-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----([\s\S]*?)-----END (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----/g,
      type: 'SENSITIVE_DATA_EXPOSURE',
      severity: 'CRITICAL',
      description: 'Potential exposure of private cryptographic key.'
    },
    JWT: {
      // JSON Web Token pattern (base64url-encoded header.payload.signature)
      regex: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+/g,
      type: 'SENSITIVE_DATA_EXPOSURE',
      severity: 'HIGH',
      description: 'Potential exposure of JSON Web Token (JWT).'
    }
    // Add more patterns as needed (e.g., AWS Access Keys, Google API Keys, database connection strings)
  };

  /**
   * Scans text content (e.g., response body or headers) for sensitive data.
   * @param content The text content to scan.
   * @param context A string indicating where the content came from (e.g., "response_body", "header: Content-Type").
   * @returns An array of SensitiveDataFinding objects.
   */
  public scan(content: string, context: string = 'unknown'): SensitiveDataFinding[] {
    const findings: SensitiveDataFinding[] = [];

    if (!content || typeof content !== 'string') {
      return findings;
    }

    for (const [key, patternInfo] of Object.entries(SensitiveDataDetector.PATTERNS)) {
      let match;
      while ((match = patternInfo.regex.exec(content)) !== null) {
        // Basic check to avoid very short or common false positives if necessary
        // For example, for generic API keys, ensure it's not just a common word
        if (key === 'API_KEY_GENERIC' && match[1].length < 16) { // Ensure key part is reasonable length
          continue;
        }

        findings.push({
          type: patternInfo.type,
          match: match[0],
          context: `${context} (Pattern: ${key})`,
          severity: patternInfo.severity,
          description: patternInfo.description
        });
        logger.warn(`Sensitive data detected: ${patternInfo.type} in ${context}. Match: ${match[0].substring(0, 50)}...`);
      }
    }
    return findings;
  }

  /**
   * Converts SensitiveDataFinding objects into Vulnerability objects.
   * This is a helper for integrating with the existing vulnerability reporting.
   * @param findings An array of SensitiveDataFinding objects.
   * @param endpoint The endpoint URL associated with the finding.
   * @param method The HTTP method associated with the finding.
   * @returns An array of Vulnerability objects.
   */
  public static findingsToVulnerabilities(
    findings: SensitiveDataFinding[],
    endpoint: string,
    method: string
  ): Vulnerability[] {
    return findings.map(finding => ({
      id: `vuln_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`, // Unique ID
      scanId: 'current_scan_id', // This should be replaced with actual scanId from context
      type: finding.type,
      severity: finding.severity,
      endpoint: endpoint,
      method: method,
      description: `Sensitive data exposure detected: ${finding.description} Found: "${finding.match.substring(0, 100)}${finding.match.length > 100 ? '...' : ''}" in ${finding.context}.`,
      impact: `Confidentiality breach due to exposure of sensitive data like ${finding.type.replace(/_/g, ' ').toLowerCase()}.`,
      confidence: 0.9, // High confidence for direct regex matches
      evidence: {
        response: finding.match, // Store the matched sensitive data as evidence
      },
      remediation: {
        priority: 1,
        effort: 'High',
        steps: [
          `Ensure no sensitive data like "${finding.type.replace(/_/g, ' ').toLowerCase()}" is exposed in API responses or headers.`,
          `Implement proper data redaction or encryption for all sensitive fields.`,
          `Review logging configurations to prevent sensitive data from being written to logs.`,
          `For API keys/secrets, enforce strict access controls and consider environment variables for storage.`,
          `Implement a Data Loss Prevention (DLP) solution for continuous monitoring.`
        ],
        automatable: false,
      },
      discoveredAt: new Date(),
    }));
  }
} 