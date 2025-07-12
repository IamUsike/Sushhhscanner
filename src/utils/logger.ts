import winston from 'winston';
import path from 'path';
import fs from 'fs';

// Ensure logs directory exists
const logsDir = path.join(process.cwd(), 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Custom log format
const logFormat = winston.format.combine(
  winston.format.timestamp({
    format: 'YYYY-MM-DD HH:mm:ss.SSS',
  }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
  winston.format.prettyPrint()
);

// Console format for development
const consoleFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp({
    format: 'HH:mm:ss',
  }),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    let metaString = '';
    if (Object.keys(meta).length > 0) {
      metaString = ` ${JSON.stringify(meta)}`;
    }
    return `${timestamp} [${level}]: ${message}${metaString}`;
  })
);

// Create logger instance
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: logFormat,
  defaultMeta: { 
    service: 'api-risk-visualizer',
    version: process.env.npm_package_version || '1.0.0',
  },
  transports: [
    // File transport for all logs
    new winston.transports.File({
      filename: path.join(logsDir, 'error.log'),
      level: 'error',
      maxsize: 10 * 1024 * 1024, // 10MB
      maxFiles: 5,
    }),
    new winston.transports.File({
      filename: path.join(logsDir, 'combined.log'),
      maxsize: 10 * 1024 * 1024, // 10MB
      maxFiles: 10,
    }),
  ],
});

// Add console transport for development
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: consoleFormat,
  }));
}

// Security-specific logger for audit trails
const securityLogger = winston.createLogger({
  level: 'info',
  format: logFormat,
  defaultMeta: { 
    service: 'api-risk-visualizer-security',
    type: 'security-audit',
  },
  transports: [
    new winston.transports.File({
      filename: path.join(logsDir, 'security-audit.log'),
      maxsize: 10 * 1024 * 1024, // 10MB
      maxFiles: 20, // Keep more security logs
    }),
  ],
});

// Scan-specific logger for detailed scan operations
const scanLogger = winston.createLogger({
  level: 'debug',
  format: logFormat,
  defaultMeta: { 
    service: 'api-risk-visualizer-scans',
    type: 'scan-operation',
  },
  transports: [
    new winston.transports.File({
      filename: path.join(logsDir, 'scans.log'),
      maxsize: 50 * 1024 * 1024, // 50MB for detailed scan logs
      maxFiles: 5,
    }),
  ],
});

// Helper functions for structured logging
const logScanStart = (scanId: string, target: string, config: any) => {
  scanLogger.info('Scan initiated', {
    scanId,
    target,
    config,
    event: 'scan_start',
    timestamp: new Date().toISOString(),
  });
};

const logScanProgress = (scanId: string, step: string, progress: number, details?: any) => {
  scanLogger.info('Scan progress update', {
    scanId,
    step,
    progress,
    details,
    event: 'scan_progress',
    timestamp: new Date().toISOString(),
  });
};

const logVulnerabilityFound = (scanId: string, vulnerability: any) => {
  securityLogger.warn('Vulnerability detected', {
    scanId,
    vulnerability,
    event: 'vulnerability_found',
    timestamp: new Date().toISOString(),
  });
};

const logSecurityEvent = (event: string, details: any, severity: 'info' | 'warn' | 'error' = 'info') => {
  securityLogger[severity]('Security event', {
    event,
    details,
    timestamp: new Date().toISOString(),
  });
};

const logAIAnalysis = (operation: string, input: any, output: any, performance?: any) => {
  logger.info('AI analysis performed', {
    operation,
    input: typeof input === 'string' ? input.substring(0, 100) + '...' : input,
    output,
    performance,
    event: 'ai_analysis',
    timestamp: new Date().toISOString(),
  });
};

export {
  logger,
  securityLogger,
  scanLogger,
  logScanStart,
  logScanProgress,
  logVulnerabilityFound,
  logSecurityEvent,
  logAIAnalysis,
}; 