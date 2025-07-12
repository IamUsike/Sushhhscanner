"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.authRoutes = void 0;
const express_1 = require("express");
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const uuid_1 = require("uuid");
const joi_1 = __importDefault(require("joi"));
const middleware_1 = require("../utils/middleware");
const database_1 = require("../core/database");
const logger_1 = require("../utils/logger");
const router = (0, express_1.Router)();
exports.authRoutes = router;
// Validation schemas
const registerSchema = joi_1.default.object({
    email: joi_1.default.string().email().required(),
    password: joi_1.default.string().min(8).pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]')).required()
        .messages({
        'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
    }),
    role: joi_1.default.string().valid('user', 'admin').default('user'),
});
const loginSchema = joi_1.default.object({
    email: joi_1.default.string().email().required(),
    password: joi_1.default.string().required(),
});
// POST /api/v1/auth/register - Register a new user
router.post('/register', (0, middleware_1.validateRequest)(registerSchema), (0, middleware_1.asyncHandler)(async (req, res) => {
    const { email, password, role } = req.body;
    // Check if user already exists
    const existingUser = await database_1.database.getUserByEmail(email);
    if (existingUser) {
        (0, logger_1.logSecurityEvent)('registration_attempt_duplicate_email', {
            email,
            ip: req.ip,
        }, 'warn');
        return res.status(409).json({
            success: false,
            error: {
                message: 'User with this email already exists',
                code: 'USER_EXISTS',
            },
            timestamp: new Date().toISOString(),
        });
    }
    // Hash password
    const saltRounds = parseInt(process.env.BCRYPT_ROUNDS || '12');
    const passwordHash = await bcryptjs_1.default.hash(password, saltRounds);
    // Create user
    const userId = (0, uuid_1.v4)();
    const user = {
        id: userId,
        email,
        passwordHash,
        role: role || 'user',
    };
    await database_1.database.createUser(user);
    (0, logger_1.logSecurityEvent)('user_registered', {
        userId,
        email,
        role: user.role,
        ip: req.ip,
    });
    // Generate JWT token
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
        logger_1.logger.error('JWT_SECRET not configured');
        return res.status(500).json({
            success: false,
            error: { message: 'Server configuration error' },
            timestamp: new Date().toISOString(),
        });
    }
    const token = jsonwebtoken_1.default.sign({
        id: userId,
        email,
        role: user.role
    }, jwtSecret, {
        expiresIn: '24h',
        issuer: 'api-risk-visualizer',
        audience: 'api-risk-visualizer-users',
    });
    const response = {
        success: true,
        data: {
            user: {
                id: userId,
                email,
                role: user.role,
                createdAt: new Date(),
                updatedAt: new Date(),
            },
            token,
            expiresIn: process.env.JWT_EXPIRES_IN || '24h',
        },
        metadata: {
            timestamp: new Date(),
        },
    };
    res.status(201).json(response);
}));
// POST /api/v1/auth/login - Login user
router.post('/login', (0, middleware_1.validateRequest)(loginSchema), (0, middleware_1.asyncHandler)(async (req, res) => {
    const { email, password } = req.body;
    // Get user by email
    const user = await database_1.database.getUserByEmail(email);
    if (!user) {
        (0, logger_1.logSecurityEvent)('login_attempt_invalid_email', {
            email,
            ip: req.ip,
        }, 'warn');
        return res.status(401).json({
            success: false,
            error: {
                message: 'Invalid email or password',
                code: 'INVALID_CREDENTIALS',
            },
            timestamp: new Date().toISOString(),
        });
    }
    // Verify password
    const isValidPassword = await bcryptjs_1.default.compare(password, user.passwordHash);
    if (!isValidPassword) {
        (0, logger_1.logSecurityEvent)('login_attempt_invalid_password', {
            userId: user.id,
            email,
            ip: req.ip,
        }, 'warn');
        return res.status(401).json({
            success: false,
            error: {
                message: 'Invalid email or password',
                code: 'INVALID_CREDENTIALS',
            },
            timestamp: new Date().toISOString(),
        });
    }
    // Update last login time
    await database_1.database.updateUserLastLogin(user.id);
    // Generate JWT token
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
        logger_1.logger.error('JWT_SECRET not configured');
        return res.status(500).json({
            success: false,
            error: { message: 'Server configuration error' },
            timestamp: new Date().toISOString(),
        });
    }
    const token = jsonwebtoken_1.default.sign({
        id: user.id,
        email: user.email,
        role: user.role
    }, jwtSecret, {
        expiresIn: '24h',
        issuer: 'api-risk-visualizer',
        audience: 'api-risk-visualizer-users',
    });
    (0, logger_1.logSecurityEvent)('user_logged_in', {
        userId: user.id,
        email: user.email,
        ip: req.ip,
    });
    const response = {
        success: true,
        data: {
            user: {
                id: user.id,
                email: user.email,
                role: user.role,
                createdAt: user.createdAt,
                updatedAt: user.updatedAt,
                lastLoginAt: new Date(),
            },
            token,
            expiresIn: process.env.JWT_EXPIRES_IN || '24h',
        },
        metadata: {
            timestamp: new Date(),
        },
    };
    res.json(response);
}));
// POST /api/v1/auth/verify - Verify JWT token
router.post('/verify', (0, middleware_1.asyncHandler)(async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            success: false,
            error: { message: 'Authorization token required' },
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
    try {
        const decoded = jsonwebtoken_1.default.verify(token, jwtSecret);
        // Get fresh user data
        const user = await database_1.database.getUserByEmail(decoded.email);
        if (!user) {
            return res.status(401).json({
                success: false,
                error: { message: 'User not found' },
                timestamp: new Date().toISOString(),
            });
        }
        const response = {
            success: true,
            data: {
                valid: true,
                user: {
                    id: user.id,
                    email: user.email,
                    role: user.role,
                    createdAt: user.createdAt,
                    updatedAt: user.updatedAt,
                    lastLoginAt: user.lastLoginAt,
                },
                expiresAt: new Date(decoded.exp * 1000),
            },
            metadata: {
                timestamp: new Date(),
            },
        };
        res.json(response);
    }
    catch (error) {
        (0, logger_1.logSecurityEvent)('token_verification_failed', {
            error: error instanceof Error ? error.message : 'Unknown error',
            ip: req.ip,
        }, 'warn');
        res.status(401).json({
            success: false,
            error: { message: 'Invalid or expired token' },
            timestamp: new Date().toISOString(),
        });
    }
}));
// POST /api/v1/auth/logout - Logout user (for client-side token cleanup)
router.post('/logout', (0, middleware_1.asyncHandler)(async (req, res) => {
    // In a stateless JWT system, we can't invalidate tokens server-side
    // This endpoint exists for consistency and future token blacklisting implementation
    (0, logger_1.logSecurityEvent)('user_logged_out', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
    });
    const response = {
        success: true,
        data: { message: 'Logged out successfully' },
        metadata: {
            timestamp: new Date(),
        },
    };
    res.json(response);
}));
// GET /api/v1/auth/me - Get current user info (requires auth)
router.get('/me', (0, middleware_1.asyncHandler)(async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            success: false,
            error: { message: 'Authorization token required' },
            timestamp: new Date().toISOString(),
        });
    }
    const token = authHeader.substring(7);
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
        return res.status(500).json({
            success: false,
            error: { message: 'Server configuration error' },
            timestamp: new Date().toISOString(),
        });
    }
    try {
        const decoded = jsonwebtoken_1.default.verify(token, jwtSecret);
        const user = await database_1.database.getUserByEmail(decoded.email);
        if (!user) {
            return res.status(401).json({
                success: false,
                error: { message: 'User not found' },
                timestamp: new Date().toISOString(),
            });
        }
        const response = {
            success: true,
            data: {
                id: user.id,
                email: user.email,
                role: user.role,
                createdAt: user.createdAt,
                updatedAt: user.updatedAt,
                lastLoginAt: user.lastLoginAt,
            },
            metadata: {
                timestamp: new Date(),
            },
        };
        res.json(response);
    }
    catch (error) {
        res.status(401).json({
            success: false,
            error: { message: 'Invalid or expired token' },
            timestamp: new Date().toISOString(),
        });
    }
}));
//# sourceMappingURL=auth.js.map