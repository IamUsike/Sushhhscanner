"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.securityHeaders = exports.asyncHandler = exports.validateRequest = exports.validateApiKey = exports.requireAdmin = exports.authenticate = exports.notFound = exports.errorHandler = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const logger_1 = require("@utils/logger");
// Error handling middleware
const errorHandler = (err, req, res, next) => {
    logger_1.logger.error('Unhandled error:', {
        error: err.message,
        stack: err.stack,
        url: req.url,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
    });
    // Don't leak error details in production
    const message = process.env.NODE_ENV === 'production'
        ? 'Internal server error'
        : err.message;
    const statusCode = err.statusCode || err.status || 500;
    res.status(statusCode).json({
        success: false,
        error: {
            message,
            ...(process.env.NODE_ENV !== 'production' && { stack: err.stack }),
        },
        timestamp: new Date().toISOString(),
    });
};
exports.errorHandler = errorHandler;
// 404 handler
const notFound = (req, res, next) => {
    logger_1.logger.warn('404 - Resource not found', {
        url: req.url,
        method: req.method,
        ip: req.ip,
    });
    res.status(404).json({
        success: false,
        error: {
            message: `Route ${req.originalUrl} not found`,
        },
        timestamp: new Date().toISOString(),
    });
};
exports.notFound = notFound;
// Authentication middleware
const authenticate = (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            (0, logger_1.logSecurityEvent)('unauthorized_access_attempt', {
                ip: req.ip,
                url: req.url,
                userAgent: req.get('User-Agent'),
            }, 'warn');
            return res.status(401).json({
                success: false,
                error: { message: 'Access token required' },
                timestamp: new Date().toISOString(),
            });
        }
        const token = authHeader.substring(7);
        const jwtSecret = process.env.JWT_SECRET;
        if (!jwtSecret) {
            logger_1.logger.error('JWT_SECRET not configured');
            return res.status(500).json({
                success: false,
                error: { message: 'Server configuration error' },
                timestamp: new Date().toISOString(),
            });
        }
        const decoded = jsonwebtoken_1.default.verify(token, jwtSecret);
        // Add user info to request
        req.user = {
            id: decoded.id,
            email: decoded.email,
            role: decoded.role,
        };
        next();
    }
    catch (error) {
        (0, logger_1.logSecurityEvent)('invalid_token', {
            ip: req.ip,
            error: error instanceof Error ? error.message : 'Unknown error',
            url: req.url,
        }, 'warn');
        res.status(401).json({
            success: false,
            error: { message: 'Invalid or expired token' },
            timestamp: new Date().toISOString(),
        });
    }
};
exports.authenticate = authenticate;
// Admin role middleware
const requireAdmin = (req, res, next) => {
    if (!req.user || req.user.role !== 'admin') {
        (0, logger_1.logSecurityEvent)('unauthorized_admin_access', {
            userId: req.user?.id,
            ip: req.ip,
            url: req.url,
        }, 'warn');
        return res.status(403).json({
            success: false,
            error: { message: 'Admin access required' },
            timestamp: new Date().toISOString(),
        });
    }
    next();
};
exports.requireAdmin = requireAdmin;
// API key validation middleware (for external integrations)
const validateApiKey = (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) {
        return res.status(401).json({
            success: false,
            error: { message: 'API key required' },
            timestamp: new Date().toISOString(),
        });
    }
    // In a real app, validate against database
    // For now, just check against environment variable
    const validApiKey = process.env.API_KEY;
    if (!validApiKey || apiKey !== validApiKey) {
        (0, logger_1.logSecurityEvent)('invalid_api_key', {
            providedKey: apiKey.substring(0, 8) + '...',
            ip: req.ip,
            url: req.url,
        }, 'warn');
        return res.status(401).json({
            success: false,
            error: { message: 'Invalid API key' },
            timestamp: new Date().toISOString(),
        });
    }
    next();
};
exports.validateApiKey = validateApiKey;
// Request validation helper
const validateRequest = (schema) => {
    return (req, res, next) => {
        const { error } = schema.validate(req.body);
        if (error) {
            logger_1.logger.warn('Request validation failed', {
                error: error.details[0].message,
                path: error.details[0].path,
                value: error.details[0].context?.value,
                ip: req.ip,
                url: req.url,
            });
            return res.status(400).json({
                success: false,
                error: {
                    message: 'Request validation failed',
                    details: error.details[0].message,
                },
                timestamp: new Date().toISOString(),
            });
        }
        next();
    };
};
exports.validateRequest = validateRequest;
// Async handler wrapper to catch async errors
const asyncHandler = (fn) => {
    return (req, res, next) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
};
exports.asyncHandler = asyncHandler;
// Security headers middleware for scan endpoints
const securityHeaders = (req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
};
exports.securityHeaders = securityHeaders;
//# sourceMappingURL=middleware.js.map