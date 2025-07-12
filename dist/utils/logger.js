"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.logAIAnalysis = exports.logSecurityEvent = exports.logVulnerabilityFound = exports.logScanProgress = exports.logScanStart = exports.scanLogger = exports.securityLogger = exports.logger = void 0;
const winston_1 = __importDefault(require("winston"));
const path_1 = __importDefault(require("path"));
const fs_1 = __importDefault(require("fs"));
// Ensure logs directory exists
const logsDir = path_1.default.join(process.cwd(), 'logs');
if (!fs_1.default.existsSync(logsDir)) {
    fs_1.default.mkdirSync(logsDir, { recursive: true });
}
// Custom log format
const logFormat = winston_1.default.format.combine(winston_1.default.format.timestamp({
    format: 'YYYY-MM-DD HH:mm:ss.SSS',
}), winston_1.default.format.errors({ stack: true }), winston_1.default.format.json(), winston_1.default.format.prettyPrint());
// Console format for development
const consoleFormat = winston_1.default.format.combine(winston_1.default.format.colorize(), winston_1.default.format.timestamp({
    format: 'HH:mm:ss',
}), winston_1.default.format.printf(({ timestamp, level, message, ...meta }) => {
    let metaString = '';
    if (Object.keys(meta).length > 0) {
        metaString = ` ${JSON.stringify(meta)}`;
    }
    return `${timestamp} [${level}]: ${message}${metaString}`;
}));
// Create logger instance
const logger = winston_1.default.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: logFormat,
    defaultMeta: {
        service: 'api-risk-visualizer',
        version: process.env.npm_package_version || '1.0.0',
    },
    transports: [
        // File transport for all logs
        new winston_1.default.transports.File({
            filename: path_1.default.join(logsDir, 'error.log'),
            level: 'error',
            maxsize: 10 * 1024 * 1024, // 10MB
            maxFiles: 5,
        }),
        new winston_1.default.transports.File({
            filename: path_1.default.join(logsDir, 'combined.log'),
            maxsize: 10 * 1024 * 1024, // 10MB
            maxFiles: 10,
        }),
    ],
});
exports.logger = logger;
// Add console transport for development
if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston_1.default.transports.Console({
        format: consoleFormat,
    }));
}
// Security-specific logger for audit trails
const securityLogger = winston_1.default.createLogger({
    level: 'info',
    format: logFormat,
    defaultMeta: {
        service: 'api-risk-visualizer-security',
        type: 'security-audit',
    },
    transports: [
        new winston_1.default.transports.File({
            filename: path_1.default.join(logsDir, 'security-audit.log'),
            maxsize: 10 * 1024 * 1024, // 10MB
            maxFiles: 20, // Keep more security logs
        }),
    ],
});
exports.securityLogger = securityLogger;
// Scan-specific logger for detailed scan operations
const scanLogger = winston_1.default.createLogger({
    level: 'debug',
    format: logFormat,
    defaultMeta: {
        service: 'api-risk-visualizer-scans',
        type: 'scan-operation',
    },
    transports: [
        new winston_1.default.transports.File({
            filename: path_1.default.join(logsDir, 'scans.log'),
            maxsize: 50 * 1024 * 1024, // 50MB for detailed scan logs
            maxFiles: 5,
        }),
    ],
});
exports.scanLogger = scanLogger;
// Helper functions for structured logging
const logScanStart = (scanId, target, config) => {
    scanLogger.info('Scan initiated', {
        scanId,
        target,
        config,
        event: 'scan_start',
        timestamp: new Date().toISOString(),
    });
};
exports.logScanStart = logScanStart;
const logScanProgress = (scanId, step, progress, details) => {
    scanLogger.info('Scan progress update', {
        scanId,
        step,
        progress,
        details,
        event: 'scan_progress',
        timestamp: new Date().toISOString(),
    });
};
exports.logScanProgress = logScanProgress;
const logVulnerabilityFound = (scanId, vulnerability) => {
    securityLogger.warn('Vulnerability detected', {
        scanId,
        vulnerability,
        event: 'vulnerability_found',
        timestamp: new Date().toISOString(),
    });
};
exports.logVulnerabilityFound = logVulnerabilityFound;
const logSecurityEvent = (event, details, severity = 'info') => {
    securityLogger[severity]('Security event', {
        event,
        details,
        timestamp: new Date().toISOString(),
    });
};
exports.logSecurityEvent = logSecurityEvent;
const logAIAnalysis = (operation, input, output, performance) => {
    logger.info('AI analysis performed', {
        operation,
        input: typeof input === 'string' ? input.substring(0, 100) + '...' : input,
        output,
        performance,
        event: 'ai_analysis',
        timestamp: new Date().toISOString(),
    });
};
exports.logAIAnalysis = logAIAnalysis;
//# sourceMappingURL=logger.js.map