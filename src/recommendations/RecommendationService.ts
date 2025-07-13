import { Vulnerability, RemediationGuidance, VulnerabilityType, VulnerabilitySeverity } from '../types';
import { logger } from '../utils/logger';

export class RecommendationService {

  constructor() {
    logger.info('RecommendationService initialized');
  }

  /**
   * Generates actionable remediation guidance for a given vulnerability.
   * @param vulnerability The detected vulnerability.
   * @returns RemediationGuidance object.
   */
  public generateRecommendation(vulnerability: Vulnerability): RemediationGuidance {
    let steps: string[] = [];
    let effort: 'low' | 'medium' | 'high' | 'critical' = 'medium';
    let priority: number = 5; // Default priority
    let codeExample: string | undefined = undefined;
    let resources: string[] = [];
    let automatable: boolean = false;

    switch (vulnerability.type) {
      case VulnerabilityType.SQL_INJECTION:
      case VulnerabilityType.NOSQL_INJECTION:
      case VulnerabilityType.COMMAND_INJECTION:
      case VulnerabilityType.LDAP_INJECTION:
        steps = [
          'Use parameterized queries or prepared statements for all database interactions.',
          'Implement strict input validation and sanitization for all user-supplied data.',
          'Employ an ORM (Object-Relational Mapper) that prevents injection by design.',
          'Apply the principle of least privilege to database user accounts.'
        ];
        effort = 'high';
        priority = this.getPriorityBySeverity(vulnerability.severity);
        codeExample = `// Example (Node.js with pg):
// import { Pool } from 'pg';
// const pool = new Pool();
// async function getUser(id: string) {
//   const res = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
//   return res.rows[0];
// }`;
        resources = [
          'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
          'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html'
        ];
        break;

      case VulnerabilityType.XSS:
        steps = [
          'Implement strict output encoding for all user-supplied data displayed on web pages.',
          'Use a Content Security Policy (CSP) to restrict sources of content and scripts.',
          'Sanitize HTML input using a robust library on the server-side.',
          'Consider using a framework that automatically escapes output (e.g., React, Angular, Vue).'
        ];
        effort = 'medium';
        priority = this.getPriorityBySeverity(vulnerability.severity);
        codeExample = `// Example (Node.js with Express and a templating engine like Pug/EJS):
// // In Pug, by default, content is escaped:
// // p= userSuppliedContent
// // If using raw HTML:
// // !{userSuppliedContent} // AVOID THIS unless content is sanitized
// // For manual escaping:
// // const escapeHtml = (str) => {
// //   return str.replace(/&/g, '&amp;')
// //             .replace(/</g, '&lt;')
// //             .replace(/>/g, '&gt;')
// //             .replace(/"/g, '&quot;')
// //             .replace(/'/g, '&#039;');
// // };`;
        resources = [
          'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
          'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy'
        ];
        break;

      case VulnerabilityType.SENSITIVE_DATA_EXPOSURE:
      case VulnerabilityType.PII_EXPOSURE:
      case VulnerabilityType.FILE_EXPOSURE:
        steps = [
          'Encrypt all sensitive data at rest and in transit.',
          'Implement strict access controls (authentication and authorization) for all data.',
          'Minimize sensitive data collection and retention.',
          'Redact sensitive information from logs and error messages.',
          'Ensure sensitive files (e.g., .env, config files, backups) are not publicly accessible and are outside the web root.',
          'Implement a Data Loss Prevention (DLP) solution.'
        ];
        effort = 'high';
        priority = this.getPriorityBySeverity(vulnerability.severity);
        resources = [
          'https://owasp.org/www-project-top-10/2021/A01_2021_Broken_Access_Control.html',
          'https://owasp.org/www-project-top-10/2021/A04_2021_Insecure_Design.html'
        ];
        break;

      case VulnerabilityType.MISSING_SECURITY_HEADERS:
        steps = [
          'Implement HTTP Strict Transport Security (HSTS) with a long `max-age` and `includeSubDomains`.',
          'Add `X-Content-Type-Options: nosniff` to prevent MIME sniffing.',
          'Add `X-Frame-Options: DENY` or `SAMEORIGIN` to prevent clickjacking.',
          'Implement a Content Security Policy (CSP) to mitigate XSS and data injection attacks.',
          'Ensure `Referrer-Policy` and `Permissions-Policy` headers are correctly configured.'
        ];
        effort = 'low';
        priority = this.getPriorityBySeverity(vulnerability.severity);
        codeExample = `// Example (Node.js with Helmet):
// import express from 'express';
// import helmet from 'helmet';
// const app = express();
// app.use(helmet()); // Adds most security headers by default
// app.use(helmet.hsts({
//   maxAge: 31536000,
//   includeSubDomains: true,
//   preload: true
// }));
// app.use(helmet.contentSecurityPolicy({
//   directives: {
//     defaultSrc: ["'self'"],
//     scriptSrc: ["'self'", "'unsafe-inline'"] // Example, refine as needed
//   }
// }));`;
        resources = [
          'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html',
          'https://helmetjs.github.io/'
        ];
        automatable = true;
        break;

      case VulnerabilityType.CORS_MISCONFIGURATION:
        steps = [
          'Restrict `Access-Control-Allow-Origin` to explicitly trusted domains.',
          'Avoid using wildcard (`*`) for `Access-Control-Allow-Origin` in production.',
          'Never set `Access-Control-Allow-Credentials` to `true` when `Access-Control-Allow-Origin` is `*`.',
          'Use separate CORS policies for different endpoints if necessary.'
        ];
        effort = 'medium';
        priority = this.getPriorityBySeverity(vulnerability.severity);
        codeExample = `// Example (Node.js with cors):
// import express from 'express';
// import cors from 'cors';
// const app = express();
// const corsOptions = {
//   origin: 'https://trusted-domain.com', // Replace with your trusted domain
//   methods: ['GET', 'POST'],
//   allowedHeaders: ['Content-Type', 'Authorization'],
//   credentials: true
// };
// app.use(cors(corsOptions));`;
        resources = [
          'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS',
          'https://portswigger.net/web-security/cors'
        ];
        break;
      
      case VulnerabilityType.RATE_LIMITING_BYPASS:
        steps = [
          'Implement robust rate limiting on all sensitive endpoints (e.g., login, password reset, API calls).',
          'Use a combination of IP address, session ID, and user ID for rate limiting.',
          'Deploy a Web Application Firewall (WAF) or API Gateway with rate limiting capabilities.',
          'Employ CAPTCHA or other challenge-response mechanisms for repeated failed attempts.'
        ];
        effort = 'high';
        priority = this.getPriorityBySeverity(vulnerability.severity);
        resources = [
          'https://cheatsheetseries.owasp.org/cheatsheets/Rate_Limiting_Cheat_Sheet.html',
          'https://owasp.org/www-project-api-security/api-security-top-10/#api7-2023-lack-of-rate-limiting'
        ];
        automatable = true;
        break;

      case VulnerabilityType.NO_AUTHENTICATION:
      case VulnerabilityType.WEAK_AUTHENTICATION:
        steps = [
          'Implement strong authentication mechanisms (e.g., OAuth 2.0, OpenID Connect, JWT with proper validation).',
          'Enforce strong, unique passwords for all user accounts.',
          'Implement multi-factor authentication (MFA) for all users, especially administrators.',
          'Ensure secure storage of credentials (hashed and salted passwords).',
          'Implement account lockout policies after multiple failed login attempts.',
          'Use generic error messages for authentication failures to prevent user enumeration.'
        ];
        effort = 'high';
        priority = this.getPriorityBySeverity(vulnerability.severity);
        resources = [
          'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html',
          'https://owasp.org/www-project-api-security/api-security-top-10/#api2-2023-broken-authentication'
        ];
        break;

      case VulnerabilityType.BROKEN_ACCESS_CONTROL:
        steps = [
          'Implement robust access control checks at every layer of the application (API, business logic, data).',
          'Enforce the principle of least privilege, granting only necessary permissions.',
          'Never trust client-side authorization checks; always validate on the server.',
          'Implement role-based access control (RBAC) or attribute-based access control (ABAC).',
          'Ensure that object-level access control is properly implemented (e.g., a user can only access their own data).'
        ];
        effort = 'high';
        priority = this.getPriorityBySeverity(vulnerability.severity);
        resources = [
          'https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html',
          'https://owasp.org/www-project-api-security/api-security-top-10/#api1-2023-broken-access-control'
        ];
        break;

      case VulnerabilityType.INFORMATION_DISCLOSURE:
        steps = [
          'Remove or generalize server banners, X-Powered-By headers, and other identifying information.',
          'Configure custom error pages that do not reveal detailed system information (e.g., stack traces, database errors).',
          'Ensure robots.txt and sitemap.xml do not expose sensitive paths that are not properly secured.',
          'Remove debug flags and unnecessary comments from production code.',
          'Do not leak internal IP addresses or hostnames in responses.',
          'Implement secure logging practices, redacting sensitive data before logging.'
        ];
        effort = 'medium';
        priority = this.getPriorityBySeverity(vulnerability.severity);
        resources = [
          'https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html',
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server'
        ];
        break;
      
      case VulnerabilityType.DIRECTORY_LISTING_ENABLED:
        steps = [
          'Disable directory listing on your web server (Apache, Nginx, IIS) for all directories.',
          'Configure the server to return a 403 Forbidden error or redirect to an error page instead of listing directory contents.',
          'Ensure that web server configurations prevent accidental exposure of sensitive directories.'
        ];
        effort = 'low';
        priority = this.getPriorityBySeverity(vulnerability.severity);
        resources = [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information'
        ];
        automatable = true;
        break;
      
      case VulnerabilityType.MISSING_SECURE_COOKIE_FLAG:
      case VulnerabilityType.MISSING_HTTPONLY_COOKIE_FLAG:
      case VulnerabilityType.MISSING_SAMESITE_COOKIE_FLAG:
        steps = [
          'Ensure all cookies carrying sensitive information or session identifiers are set with the `Secure` flag (requires HTTPS).',
          'Set the `HttpOnly` flag for all cookies that do not need to be accessed by client-side scripts to prevent XSS-based session hijacking.',
          'Implement the `SameSite` attribute (e.g., `Lax` or `Strict`) for all cookies to mitigate CSRF attacks. Use `SameSite=None` only with `Secure`.'
        ];
        effort = 'low';
        priority = this.getPriorityBySeverity(vulnerability.severity);
        resources = [
          'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite',
          'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html'
        ];
        automatable = true;
        break;

      case VulnerabilityType.UNSAFE_HTTP_METHOD_ALLOWED:
      case VulnerabilityType.HTTP_METHOD_ALLOWED_WITH_AUTH:
        steps = [
          'Restrict HTTP methods on all endpoints to only those strictly necessary (e.g., GET for retrieval, POST for creation, PUT for updates, DELETE for deletion).',
          'Implement proper access control checks for all allowed methods, even if a method is theoretically disallowed.',
          'Explicitly disallow unused or unsafe HTTP methods at the server or API gateway level (e.g., OPTIONS, TRACE, PUT, DELETE if not needed).'
        ];
        effort = 'medium';
        priority = this.getPriorityBySeverity(vulnerability.severity);
        resources = [
          'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Methods_Cheat_Sheet.html'
        ];
        automatable = true;
        break;

      case VulnerabilityType.MISSING_HSTS:
      case VulnerabilityType.TLS_CERT_HOSTNAME_MISMATCH:
      case VulnerabilityType.TLS_CERT_UNTRUSTED:
        steps = [
          'Implement HTTP Strict Transport Security (HSTS) with a long `max-age` and `includeSubDomains` directive to force secure connections.',
          'Ensure your TLS certificate is valid, not expired, and issued for the correct hostname.',
          'Install a valid TLS certificate from a trusted Certificate Authority (CA).',
          'Regularly monitor certificate expiration dates and renew them proactively.',
          'Configure your server to use strong cipher suites and disable weak TLS versions (e.g., TLS 1.0, 1.1).'
        ];
        effort = 'high';
        priority = this.getPriorityBySeverity(vulnerability.severity);
        resources = [
          'https://owasp.org/www-project-top-10/2021/A06_2021_Vulnerable_and_Outdated_Components.html',
          'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'
        ];
        automatable = true;
        break;

      case VulnerabilityType.CSP_MISSING:
      case VulnerabilityType.CSP_UNSAFE_INLINE:
      case VulnerabilityType.CSP_UNSAFE_EVAL:
      case VulnerabilityType.CSP_WEAK_DEFAULT_SRC:
        steps = [
          'Implement a strong Content Security Policy (CSP) to mitigate client-side attacks (XSS, data injection).',
          'Define strict `default-src` directives, restricting content sources to trusted origins. Avoid wildcards (`*`).',
          'Remove `unsafe-inline` and `unsafe-eval` from your CSP. Use nonces or hashes for inline scripts/styles, or move them to external files.',
          'Continuously monitor and refine your CSP to ensure maximum effectiveness without breaking legitimate functionality.'
        ];
        effort = 'medium';
        priority = this.getPriorityBySeverity(vulnerability.severity);
        resources = [
          'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy',
          'https://csp.withgoogle.com/'
        ];
        automatable = true;
        break;
      
      // Default case for unknown or general vulnerabilities
      default:
        steps = [
          'Review the vulnerability details and affected code/configuration.',
          'Consult relevant security best practices and OWASP guidelines.',
          'Apply input validation, output encoding, and access control where applicable.',
          'Consider a security audit or penetration test to identify root causes.'
        ];
        effort = 'medium';
        priority = this.getPriorityBySeverity(vulnerability.severity);
        resources = [
          'https://owasp.org/www-project-top-10/',
          'https://owasp.org/www-project-api-security/'
        ];
        break;
    }

    return {
      priority,
      effort,
      steps,
      codeExample,
      resources,
      automatable
    };
  }

  private getPriorityBySeverity(severity: VulnerabilitySeverity): number {
    switch (severity) {
      case 'CRITICAL': return 1;
      case 'HIGH': return 2;
      case 'MEDIUM': return 3;
      case 'LOW': return 4;
      case 'INFO': return 5;
      default: return 5;
    }
  }

  // Potentially add methods for aggregate recommendations or LLM integration later
  // public generateAggregateRecommendations(scanSummary: ScanSummary): RemediationGuidance[] { ... }
} 