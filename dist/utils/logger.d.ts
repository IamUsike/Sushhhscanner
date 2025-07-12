import winston from 'winston';
declare const logger: winston.Logger;
declare const securityLogger: winston.Logger;
declare const scanLogger: winston.Logger;
declare const logScanStart: (scanId: string, target: string, config: any) => void;
declare const logScanProgress: (scanId: string, step: string, progress: number, details?: any) => void;
declare const logVulnerabilityFound: (scanId: string, vulnerability: any) => void;
declare const logSecurityEvent: (event: string, details: any, severity?: "info" | "warn" | "error") => void;
declare const logAIAnalysis: (operation: string, input: any, output: any, performance?: any) => void;
export { logger, securityLogger, scanLogger, logScanStart, logScanProgress, logVulnerabilityFound, logSecurityEvent, logAIAnalysis, };
//# sourceMappingURL=logger.d.ts.map