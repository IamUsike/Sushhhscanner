// Core domain types
export interface User {
  id: string;
  email: string;
  passwordHash: string;
  role: 'admin' | 'user';
  createdAt: Date;
  updatedAt: Date;
  lastLoginAt?: Date;
}

export interface ScanTarget {
  baseUrl: string;
  authMethod: 'none' | 'bearer' | 'basic' | 'api-key' | 'oauth2';
  authToken?: string;
  authUsername?: string;
  authPassword?: string;
  headers?: Record<string, string>;
  endpoints?: string[];
  swaggerUrl?: string;
}

export interface ScanConfiguration {
  depth: 'basic' | 'comprehensive' | 'deep';
  includeAI: boolean;
  testTypes: SecurityTestType[];
  maxEndpoints?: number;
  timeout?: number;
  concurrent?: boolean;
  excludePatterns?: string[];
  customPayloads?: string[];
}

export type SecurityTestType = 
  | 'auth' 
  | 'injection' 
  | 'exposure' 
  | 'config' 
  | 'rate-limiting'
  | 'headers'
  | 'business-logic'
  | 'data-exposure';

export type VulnerabilitySeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type VulnerabilityType = 
  | 'NO_AUTHENTICATION'
  | 'WEAK_AUTHENTICATION'
  | 'BROKEN_ACCESS_CONTROL'
  | 'SQL_INJECTION'
  | 'NOSQL_INJECTION'
  | 'XSS'
  | 'COMMAND_INJECTION'
  | 'LDAP_INJECTION'
  | 'PII_EXPOSURE'
  | 'SENSITIVE_DATA_EXPOSURE'
  | 'MISSING_SECURITY_HEADERS'
  | 'CORS_MISCONFIGURATION'
  | 'RATE_LIMITING_BYPASS'
  | 'BUSINESS_LOGIC_FLAW'
  | 'INFORMATION_DISCLOSURE'
  | 'FILE_EXPOSURE'
  | 'DEBUG_MODE_ENABLED'
  | 'ADMIN_PANEL_EXPOSED'
  | 'MASS_ASSIGNMENT'
  | 'RACE_CONDITION'
  | 'DIRECTORY_LISTING_ENABLED'
  | 'SERVER_INFO_DISCLOSURE'
  | 'X_POWERED_BY_HEADER_DISCLOSURE'
  | 'DETAILED_ERROR_MESSAGES'
  | 'PERMISSIVE_CORS_WITH_CREDENTIALS'
  | 'PERMISSIVE_CORS'
  | 'CSP_UNSAFE_INLINE'
  | 'CSP_UNSAFE_EVAL'
  | 'CSP_WEAK_DEFAULT_SRC'
  | 'CSP_MISSING'
  | 'MISSING_HSTS'
  | 'TLS_CERT_HOSTNAME_MISMATCH'
  | 'TLS_CERT_UNTRUSTED'
  | 'EXPOSED_SENSITIVE_PATH_IN_ROBOTS_OR_SITEMAP'
  | 'MISSING_SECURE_COOKIE_FLAG'
  | 'MISSING_HTTPONLY_COOKIE_FLAG'
  | 'MISSING_SAMESITE_COOKIE_FLAG'
  | 'UNSAFE_HTTP_METHOD_ALLOWED'
  | 'HTTP_METHOD_ALLOWED_WITH_AUTH';

export interface Vulnerability {
  id: string;
  scanId: string;
  type: VulnerabilityType;
  severity: VulnerabilitySeverity;
  endpoint: string;
  method: string;
  parameter?: string;
  payload?: string;
  description: string;
  impact: string;
  confidence: number;
  cwe?: string;
  cvss?: number;
  evidence: {
    request?: string;
    response?: string;
    timeDelayDetected?: boolean;
    errorPattern?: string;
    statusCode?: number;
    headers?: Record<string, string>;
  };
  aiAnalysis?: AIVulnerabilityAnalysis;
  remediation: RemediationGuidance;
  discoveredAt: Date;
}

export interface AIVulnerabilityAnalysis {
  confidence: number;
  patternMatch: string;
  predictedExploitability: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  businessImpact: string;
  threatPrediction?: {
    timeToExploit: string;
    attackVectors: string[];
    similarBreaches: string[];
  };
  falsePositiveProbability: number;
}

export interface RemediationGuidance {
  priority: number;
  effort: string;
  steps: string[];
  codeExample?: string;
  resources?: string[];
  automatable: boolean;
}

export interface Scan {
  id: string;
  userId: string;
  target: ScanTarget;
  configuration: ScanConfiguration;
  status: 'pending' | 'discovering' | 'testing' | 'analyzing' | 'completed' | 'failed' | 'cancelled';
  progress: number; // 0-100
  currentStep: string;
  vulnerabilities: Vulnerability[];
  summary?: {
    totalEndpoints: number;
    vulnerabilities: {
      critical: number;
      high: number;
      medium: number;
      low: number;
      info: number;
    };
    overallRiskScore: number;
    aiPredictedRisk: number;
    complianceStatus?: {
      owaspApiTop10: Array<{
        requirement: string;
        status: 'PASS' | 'FAIL' | 'WARNING';
        details: string;
      }>;
    };
  };
  metadata: {
    userAgent: string;
    scannerVersion: string;
    startedAt: Date;
    completedAt?: Date;
    duration?: number;
    endpointsDiscovered: number;
    requestsSent: number;
    aiAnalysisEnabled: boolean;
    discoveryMethods?: {
      swagger: number;
      crawling: number;
      bruteForce: number;
      robots: number;
      manual: number;
    };
    discoveryDuration?: number;
    discoveryErrors?: string[];
  };
  createdAt: Date;
  updatedAt: Date;
}

export type ScanStatus = 
  | 'pending'
  | 'discovering'
  | 'testing'
  | 'analyzing'
  | 'completed'
  | 'failed'
  | 'cancelled';

export interface ScanSummary {
  totalEndpoints: number;
  vulnerabilities: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  overallRiskScore: number;
  aiPredictedRisk?: number;
  complianceStatus: {
    owaspApiTop10: ComplianceResult[];
    pciDss?: ComplianceResult[];
    hipaa?: ComplianceResult[];
  };
}

export interface ComplianceResult {
  requirement: string;
  status: 'PASS' | 'FAIL' | 'WARNING' | 'NOT_APPLICABLE';
  details: string;
}

export interface EndpointInfo {
  url: string;
  method: string;
  parameters: ParameterInfo[];
  authentication: AuthenticationInfo;
  discoveryMethod: 'swagger' | 'crawling' | 'brute-force' | 'manual' | 'robots' | 'known-api' | 'web-crawling' | 'swagger-parsing';
  responseTypes: string[];
  riskScore?: number;
  description?: string;
}

// Discovery engine types
export interface APIEndpoint {
  path: string;
  method: string;
  url: string;
  discoveredBy: string[];
  parameters?: Array<{ name: string; type: string; required?: boolean }>;
  authentication?: {
    required: boolean;
    type: string;
  };
  response?: {
    statusCode: number;
    headers: Record<string, string>;
    contentType: string;
  };
  description?: string;
  timestamp: string;
}

export interface DiscoveryProgress {
  phase: string;
  percentage: number;
  currentOperation?: string;
}

export interface ParameterInfo {
  name: string;
  type: 'query' | 'path' | 'header' | 'body';
  dataType: string;
  required: boolean;
  example?: any;
  location?: 'query' | 'body' | 'header' | 'path' | 'form'; // Add location field for compatibility
}

export interface AuthenticationInfo {
  required: boolean;
  methods?: string[];
  tested?: boolean;
  bypassed?: boolean;
}

// AI/ML related types
export interface AIModelConfig {
  provider: 'huggingface' | 'openai' | 'tensorflow' | 'local';
  modelName: string;
  apiKey?: string;
  endpoint?: string;
  confidenceThreshold: number;
  maxTokens?: number;
}

export interface AIAnalysisRequest {
  type: 'vulnerability_prediction' | 'code_analysis' | 'pattern_recognition' | 'threat_modeling';
  input: {
    codeSnippet?: string;
    endpointPattern?: string;
    context?: Record<string, any>;
  };
  modelConfig?: Partial<AIModelConfig>;
}

export interface AIAnalysisResponse {
  prediction: {
    vulnerable: boolean;
    confidence: number;
    vulnerabilityType?: VulnerabilityType;
    severity?: VulnerabilitySeverity;
    explanation: string;
    cwe?: string;
    remediation?: string;
  };
  performance: {
    processingTime: number;
    tokensUsed?: number;
    modelVersion: string;
  };
  metadata: {
    timestamp: Date;
    requestId: string;
  };
}

// WebSocket message types
export interface WebSocketMessage {
  type: 'progress' | 'vulnerability_found' | 'scan_completed' | 'error' | 'heartbeat';
  scanId?: string;
  data?: any;
  timestamp: Date;
}

// API response types
export interface APIResponse<T = any> {
  success: boolean;
  data?: T;
  error?: {
    message: string;
    code?: string;
    details?: any;
  };
  metadata?: {
    timestamp: Date;
    requestId?: string;
    pagination?: PaginationInfo;
  };
}

export interface PaginationInfo {
  page: number;
  limit: number;
  total: number;
  pages: number;
  hasNext: boolean;
  hasPrev: boolean;
}

// Report types
export interface Report {
  id: string;
  scanId: string;
  type: 'executive' | 'technical' | 'compliance' | 'developer';
  format: 'pdf' | 'html' | 'json' | 'csv';
  template: string;
  sections: string[];
  generatedAt: Date;
  downloadUrl: string;
  expiresAt: Date;
  size: number;
}

// Visualization data types
export interface HeatmapData {
  endpoint: string;
  method: string;
  riskScore: number;
  vulnerabilities: VulnerabilityType[];
  coordinates: { x: number; y: number };
  color: string;
}

export interface NetworkGraphData {
  nodes: NetworkNode[];
  edges: NetworkEdge[];
}

export interface NetworkNode {
  id: string;
  type: 'gateway' | 'service' | 'database' | 'external';
  label: string;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  vulnerabilities: number;
  size: number;
}

export interface NetworkEdge {
  source: string;
  target: string;
  strength: number;
  riskFlow: 'low' | 'medium' | 'high';
  label?: string;
}

// Configuration types
export interface AppConfig {
  server: {
    port: number;
    host: string;
    apiVersion: string;
  };
  database: {
    type: 'sqlite' | 'postgresql';
    url?: string;
    path?: string;
  };
  security: {
    jwtSecret: string;
    jwtExpiresIn: string;
    bcryptRounds: number;
  };
  ai: {
    providers: AIModelConfig[];
    defaultProvider: string;
    confidenceThreshold: number;
  };
  scanning: {
    maxConcurrentScans: number;
    defaultTimeout: number;
    maxEndpointsPerScan: number;
  };
}

// Utility types
export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

export type RequiredFields<T, K extends keyof T> = T & Required<Pick<T, K>>;

export type Optional<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>; 