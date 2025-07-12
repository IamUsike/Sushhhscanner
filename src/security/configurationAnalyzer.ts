import { logger } from '../utils/logger';
import { MisconfigurationResult } from './misconfigurationDetector';

export interface ConfigurationFile {
  filename: string;
  content: string;
  type: 'json' | 'yaml' | 'xml' | 'ini' | 'env' | 'unknown';
  url?: string;
}

export interface APIConfiguration {
  endpoints: Array<{
    path: string;
    method: string;
    authentication?: any;
    parameters?: any;
  }>;
  security?: any;
  swagger?: any;
}

export class ConfigurationAnalyzer {
  
  // Database connection patterns that indicate potential security issues
  private readonly dangerousDbPatterns = [
    /password\s*=\s*['""]?[^'"\s]+['""]?/i,
    /pwd\s*=\s*['""]?[^'"\s]+['""]?/i,
    /secret\s*=\s*['""]?[^'"\s]+['""]?/i,
    /token\s*=\s*['""]?[^'"\s]+['""]?/i,
    /api_key\s*=\s*['""]?[^'"\s]+['""]?/i,
    /private_key\s*=\s*['""]?[^'"\s]+['""]?/i
  ];

  // Weak or default credentials
  private readonly weakCredentials = [
    'admin', 'password', '123456', 'root', 'guest', 'test',
    'demo', 'user', 'default', 'changeme', '', 'null'
  ];

  // Dangerous configuration values
  private readonly dangerousConfigs = [
    { pattern: /debug\s*[:=]\s*true/i, issue: 'Debug mode enabled' },
    { pattern: /ssl\s*[:=]\s*false/i, issue: 'SSL disabled' },
    { pattern: /verify_ssl\s*[:=]\s*false/i, issue: 'SSL verification disabled' },
    { pattern: /auth\s*[:=]\s*false/i, issue: 'Authentication disabled' },
    { pattern: /cors\s*[:=]\s*\*/i, issue: 'CORS wildcard enabled' },
    { pattern: /x-frame-options\s*[:=]\s*allow/i, issue: 'X-Frame-Options permissive' }
  ];

  async analyzeConfiguration(configFile: ConfigurationFile): Promise<MisconfigurationResult[]> {
    logger.info(`Analyzing configuration file: ${configFile.filename}`);
    const results: MisconfigurationResult[] = [];

    try {
      // Parse the configuration based on type
      const parsedConfig = this.parseConfiguration(configFile);
      
      // Check for exposed credentials
      const credentialResults = this.checkExposedCredentials(configFile);
      results.push(...credentialResults);

      // Check for dangerous configurations
      const dangerousResults = this.checkDangerousConfigurations(configFile);
      results.push(...dangerousResults);

      // Check for weak credentials
      const weakCredResults = this.checkWeakCredentials(configFile);
      results.push(...weakCredResults);

      // Type-specific analysis
      if (configFile.type === 'json') {
        const jsonResults = this.analyzeJSONConfiguration(configFile, parsedConfig);
        results.push(...jsonResults);
      } else if (configFile.type === 'yaml') {
        const yamlResults = this.analyzeYAMLConfiguration(configFile, parsedConfig);
        results.push(...yamlResults);
      } else if (configFile.type === 'env') {
        const envResults = this.analyzeEnvConfiguration(configFile);
        results.push(...envResults);
      }

      return results;

    } catch (error: any) {
      logger.error(`Failed to analyze configuration: ${error.message}`);
      return [];
    }
  }

  async analyzeAPIConfiguration(apiConfig: APIConfiguration, baseUrl: string): Promise<MisconfigurationResult[]> {
    const results: MisconfigurationResult[] = [];

    try {
      // Check for endpoints without authentication
      const unauthEndpoints = apiConfig.endpoints.filter(ep => 
        !ep.authentication || ep.authentication.required === false
      );

      if (unauthEndpoints.length > 0) {
        results.push({
          category: 'API Configuration',
          type: 'unauthenticated_endpoints',
          severity: 'MEDIUM',
          confidence: 0.8,
          title: `${unauthEndpoints.length} Endpoints Without Authentication`,
          description: `Found ${unauthEndpoints.length} API endpoints that do not require authentication.`,
          evidence: {
            url: baseUrl,
            content: JSON.stringify(unauthEndpoints.map(ep => `${ep.method} ${ep.path}`), null, 2)
          },
          cwe: 'CWE-287',
          owasp: 'A07:2021 – Identification and Authentication Failures',
          recommendation: 'Review all endpoints and implement appropriate authentication mechanisms.',
          impact: 'Unauthenticated endpoints may expose sensitive data or functionality.',
          references: ['https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/']
        });
      }

      // Check for excessive permissions or wildcard CORS
      if (apiConfig.security) {
        const corsConfig = apiConfig.security.cors;
        if (corsConfig && (corsConfig.origin === '*' || corsConfig.origins?.includes('*'))) {
          results.push({
            category: 'API Configuration',
            type: 'cors_wildcard',
            severity: 'HIGH',
            confidence: 0.9,
            title: 'CORS Wildcard Origin Configured',
            description: 'The API is configured to accept requests from any origin (*), which poses security risks.',
            evidence: {
              url: baseUrl,
              content: JSON.stringify(corsConfig, null, 2)
            },
            cwe: 'CWE-346',
            owasp: 'A05:2021 – Security Misconfiguration',
            recommendation: 'Configure CORS to only allow trusted origins.',
            impact: 'Wildcard CORS can enable cross-origin attacks and data theft.',
            references: ['https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny']
          });
        }
      }

      // Check Swagger/OpenAPI security definitions
      if (apiConfig.swagger) {
        const swaggerResults = this.analyzeSwaggerSecurity(apiConfig.swagger, baseUrl);
        results.push(...swaggerResults);
      }

      return results;

    } catch (error: any) {
      logger.error(`Failed to analyze API configuration: ${error.message}`);
      return [];
    }
  }

  private parseConfiguration(configFile: ConfigurationFile): any {
    try {
      if (configFile.type === 'json') {
        return JSON.parse(configFile.content);
      } else if (configFile.type === 'yaml') {
        // Simple YAML parsing for basic key-value pairs
        const lines = configFile.content.split('\n');
        const config: any = {};
        
        for (const line of lines) {
          const trimmed = line.trim();
          if (trimmed && !trimmed.startsWith('#')) {
            const colonIndex = trimmed.indexOf(':');
            if (colonIndex > 0) {
              const key = trimmed.substring(0, colonIndex).trim();
              const value = trimmed.substring(colonIndex + 1).trim();
              config[key] = value;
            }
          }
        }
        return config;
      }
      
      return null;
    } catch (error) {
      return null;
    }
  }

  private checkExposedCredentials(configFile: ConfigurationFile): MisconfigurationResult[] {
    const results: MisconfigurationResult[] = [];

    for (const pattern of this.dangerousDbPatterns) {
      const matches = configFile.content.match(pattern);
      if (matches) {
        results.push({
          category: 'Credential Exposure',
          type: 'exposed_credentials',
          severity: 'CRITICAL',
          confidence: 0.9,
          title: 'Exposed Credentials in Configuration',
          description: `Found potentially exposed credentials in ${configFile.filename}.`,
          evidence: {
            file: configFile.filename,
            content: matches[0],
            url: configFile.url
          },
          cwe: 'CWE-798',
          owasp: 'A07:2021 – Identification and Authentication Failures',
          recommendation: 'Remove hardcoded credentials and use environment variables or secure vaults.',
          impact: 'Exposed credentials can lead to unauthorized access to databases and services.',
          references: [
            'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials'
          ]
        });
      }
    }

    return results;
  }

  private checkDangerousConfigurations(configFile: ConfigurationFile): MisconfigurationResult[] {
    const results: MisconfigurationResult[] = [];

    for (const dangerousConfig of this.dangerousConfigs) {
      if (dangerousConfig.pattern.test(configFile.content)) {
        results.push({
          category: 'Dangerous Configuration',
          type: 'dangerous_setting',
          severity: 'HIGH',
          confidence: 0.8,
          title: `Dangerous Configuration: ${dangerousConfig.issue}`,
          description: `Found dangerous configuration setting in ${configFile.filename}: ${dangerousConfig.issue}`,
          evidence: {
            file: configFile.filename,
            content: this.extractMatchingLine(configFile.content, dangerousConfig.pattern),
            url: configFile.url
          },
          cwe: 'CWE-16',
          owasp: 'A05:2021 – Security Misconfiguration',
          recommendation: `Review and secure the configuration setting: ${dangerousConfig.issue}`,
          impact: 'Dangerous configurations can expose the application to various security risks.',
          references: [
            'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/'
          ]
        });
      }
    }

    return results;
  }

  private checkWeakCredentials(configFile: ConfigurationFile): MisconfigurationResult[] {
    const results: MisconfigurationResult[] = [];

    for (const weakCred of this.weakCredentials) {
      const pattern = new RegExp(`(password|pwd|pass|secret|token)\\s*[:=]\\s*['""]?${weakCred}['""]?`, 'i');
      if (pattern.test(configFile.content)) {
        results.push({
          category: 'Weak Credentials',
          type: 'weak_credentials',
          severity: 'HIGH',
          confidence: 0.9,
          title: `Weak Credential Detected: ${weakCred}`,
          description: `Found weak or default credential "${weakCred}" in ${configFile.filename}.`,
          evidence: {
            file: configFile.filename,
            content: this.extractMatchingLine(configFile.content, pattern),
            url: configFile.url
          },
          cwe: 'CWE-521',
          owasp: 'A07:2021 – Identification and Authentication Failures',
          recommendation: 'Replace weak credentials with strong, unique passwords.',
          impact: 'Weak credentials can be easily guessed or brute-forced by attackers.',
          references: [
            'https://owasp.org/www-community/vulnerabilities/Weak_Passwords'
          ]
        });
      }
    }

    return results;
  }

  private analyzeJSONConfiguration(configFile: ConfigurationFile, parsedConfig: any): MisconfigurationResult[] {
    const results: MisconfigurationResult[] = [];

    if (!parsedConfig) return results;

    try {
      // Check for debug mode in package.json or other JSON configs
      if (parsedConfig.scripts && parsedConfig.scripts.start && parsedConfig.scripts.start.includes('--debug')) {
        results.push({
          category: 'JSON Configuration',
          type: 'debug_mode_enabled',
          severity: 'MEDIUM',
          confidence: 0.8,
          title: 'Debug Mode Enabled in Start Script',
          description: 'The application start script includes debug flags that should not be used in production.',
          evidence: {
            file: configFile.filename,
            content: JSON.stringify(parsedConfig.scripts, null, 2),
            url: configFile.url
          },
          cwe: 'CWE-489',
          owasp: 'A05:2021 – Security Misconfiguration',
          recommendation: 'Remove debug flags from production start scripts.',
          impact: 'Debug mode can expose sensitive information and increase attack surface.',
          references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/02-Testing_for_Stack_Traces']
        });
      }

      // Check for insecure dependencies in package.json
      if (parsedConfig.dependencies) {
        const insecurePackages = ['express', 'mysql', 'mongodb'].filter(pkg => 
          parsedConfig.dependencies[pkg] && parsedConfig.dependencies[pkg].includes('*')
        );

        if (insecurePackages.length > 0) {
          results.push({
            category: 'Dependency Configuration',
            type: 'wildcard_dependencies',
            severity: 'MEDIUM',
            confidence: 0.7,
            title: 'Wildcard Dependencies Detected',
            description: `Found wildcard version specifiers for: ${insecurePackages.join(', ')}`,
            evidence: {
              file: configFile.filename,
              content: JSON.stringify(
                Object.fromEntries(
                  insecurePackages.map(pkg => [pkg, parsedConfig.dependencies[pkg]])
                ), null, 2
              ),
              url: configFile.url
            },
            cwe: 'CWE-1104',
            owasp: 'A06:2021 – Vulnerable and Outdated Components',
            recommendation: 'Pin dependency versions to avoid automatically pulling vulnerable updates.',
            impact: 'Wildcard dependencies can introduce vulnerable versions automatically.',
            references: ['https://owasp.org/www-project-dependency-check/']
          });
        }
      }

    } catch (error: any) {
      logger.warn(`Failed to analyze JSON configuration: ${error.message}`);
    }

    return results;
  }

  private analyzeYAMLConfiguration(configFile: ConfigurationFile, parsedConfig: any): MisconfigurationResult[] {
    const results: MisconfigurationResult[] = [];

    if (!parsedConfig) return results;

    try {
      // Check for Docker-related security issues in docker-compose.yml
      if (configFile.filename.includes('docker-compose')) {
        // Check for privileged containers
        if (configFile.content.includes('privileged: true')) {
          results.push({
            category: 'Container Configuration',
            type: 'privileged_container',
            severity: 'HIGH',
            confidence: 0.9,
            title: 'Privileged Container Configuration',
            description: 'Found container configured with privileged mode, which grants extensive host access.',
            evidence: {
              file: configFile.filename,
              content: this.extractMatchingLine(configFile.content, /privileged:\s*true/i),
              url: configFile.url
            },
            cwe: 'CWE-250',
            owasp: 'A05:2021 – Security Misconfiguration',
            recommendation: 'Remove privileged mode unless absolutely necessary and implement proper security contexts.',
            impact: 'Privileged containers can compromise the host system if exploited.',
            references: ['https://owasp.org/www-project-docker-top-10/']
          });
        }

        // Check for host network mode
        if (configFile.content.includes('network_mode: host')) {
          results.push({
            category: 'Container Configuration',
            type: 'host_network_mode',
            severity: 'MEDIUM',
            confidence: 0.8,
            title: 'Host Network Mode Configuration',
            description: 'Container is configured to use host networking, which reduces isolation.',
            evidence: {
              file: configFile.filename,
              content: this.extractMatchingLine(configFile.content, /network_mode:\s*host/i),
              url: configFile.url
            },
            cwe: 'CWE-250',
            owasp: 'A05:2021 – Security Misconfiguration',
            recommendation: 'Use bridge networking instead of host mode for better isolation.',
            impact: 'Host network mode can expose container services directly on host interfaces.',
            references: ['https://owasp.org/www-project-docker-top-10/']
          });
        }
      }

    } catch (error: any) {
      logger.warn(`Failed to analyze YAML configuration: ${error.message}`);
    }

    return results;
  }

  private analyzeEnvConfiguration(configFile: ConfigurationFile): MisconfigurationResult[] {
    const results: MisconfigurationResult[] = [];

    try {
      const lines = configFile.content.split('\n');
      
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith('#')) {
          const [key, value] = trimmed.split('=', 2);
          
          if (key && value) {
            // Check for empty or weak values
            if (!value || this.weakCredentials.includes(value.toLowerCase())) {
              results.push({
                category: 'Environment Configuration',
                type: 'weak_env_value',
                severity: value ? 'HIGH' : 'MEDIUM',
                confidence: 0.8,
                title: `Weak Environment Variable: ${key}`,
                description: `Environment variable "${key}" has a ${value ? 'weak' : 'empty'} value.`,
                evidence: {
                  file: configFile.filename,
                  content: `${key}=${value || '(empty)'}`,
                  url: configFile.url
                },
                cwe: 'CWE-521',
                owasp: 'A07:2021 – Identification and Authentication Failures',
                recommendation: `Set a strong value for environment variable "${key}".`,
                impact: 'Weak environment variables can be easily compromised.',
                references: ['https://owasp.org/www-community/vulnerabilities/Weak_Passwords']
              });
            }

            // Check for URLs with credentials
            if (value.includes('://') && (value.includes('@') || value.includes(':'))) {
              results.push({
                category: 'Environment Configuration',
                type: 'credentials_in_url',
                severity: 'HIGH',
                confidence: 0.9,
                title: `Credentials in URL: ${key}`,
                description: `Environment variable "${key}" contains a URL with embedded credentials.`,
                evidence: {
                  file: configFile.filename,
                  content: `${key}=${value.substring(0, Math.min(50, value.length))}...`,
                  url: configFile.url
                },
                cwe: 'CWE-798',
                owasp: 'A07:2021 – Identification and Authentication Failures',
                recommendation: 'Use separate environment variables for credentials and connection strings.',
                impact: 'URLs with embedded credentials can be logged and exposed.',
                references: ['https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials']
              });
            }
          }
        }
      }

    } catch (error: any) {
      logger.warn(`Failed to analyze .env configuration: ${error.message}`);
    }

    return results;
  }

  private analyzeSwaggerSecurity(swaggerConfig: any, baseUrl: string): MisconfigurationResult[] {
    const results: MisconfigurationResult[] = [];

    try {
      // Check if security is defined globally
      if (!swaggerConfig.security || swaggerConfig.security.length === 0) {
        results.push({
          category: 'API Documentation',
          type: 'swagger_no_global_security',
          severity: 'MEDIUM',
          confidence: 0.8,
          title: 'No Global Security Requirements in Swagger',
          description: 'The Swagger/OpenAPI specification does not define global security requirements.',
          evidence: {
            url: baseUrl,
            content: JSON.stringify(swaggerConfig.security || 'undefined', null, 2)
          },
          cwe: 'CWE-306',
          owasp: 'A07:2021 – Identification and Authentication Failures',
          recommendation: 'Define global security requirements in the Swagger specification.',
          impact: 'Missing global security can result in unprotected endpoints.',
          references: ['https://swagger.io/docs/specification/authentication/']
        });
      }

      // Check for HTTP basic auth (should use HTTPS)
      if (swaggerConfig.securityDefinitions) {
        const basicAuthSchemes = Object.entries(swaggerConfig.securityDefinitions)
          .filter(([_, scheme]: [string, any]) => scheme.type === 'basic');

        if (basicAuthSchemes.length > 0 && !baseUrl.startsWith('https://')) {
          results.push({
            category: 'API Documentation',
            type: 'basic_auth_over_http',
            severity: 'HIGH',
            confidence: 0.9,
            title: 'Basic Authentication Over HTTP',
            description: 'The API uses Basic authentication but is not served over HTTPS.',
            evidence: {
              url: baseUrl,
              content: JSON.stringify(Object.fromEntries(basicAuthSchemes), null, 2)
            },
            cwe: 'CWE-319',
            owasp: 'A02:2021 – Cryptographic Failures',
            recommendation: 'Use HTTPS when implementing Basic authentication.',
            impact: 'Basic auth over HTTP transmits credentials in plain text.',
            references: ['https://owasp.org/www-community/vulnerabilities/Basic_Authentication_over_unencrypted_channel']
          });
        }
      }

    } catch (error: any) {
      logger.warn(`Failed to analyze Swagger security: ${error.message}`);
    }

    return results;
  }

  private extractMatchingLine(content: string, pattern: RegExp): string {
    const lines = content.split('\n');
    for (const line of lines) {
      if (pattern.test(line)) {
        return line.trim();
      }
    }
    return '';
  }
} 