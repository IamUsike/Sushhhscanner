import { Router } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import Joi from 'joi';
import { validateRequest, asyncHandler } from '../utils/middleware';
import { database } from '../core/database';
import { logger, logSecurityEvent } from '../utils/logger';
import { User, APIResponse } from '../types';

const router = Router();

// Validation schemas
const registerSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(8).pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]')).required()
    .messages({
      'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
    }),
  role: Joi.string().valid('user', 'admin').default('user'),
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});

// POST /api/v1/auth/register - Register a new user
router.post('/register',
  validateRequest(registerSchema),
  asyncHandler(async (req, res) => {
    const { email, password, role } = req.body;

    // Check if user already exists
    const existingUser = await database.getUserByEmail(email);
    if (existingUser) {
      logSecurityEvent('registration_attempt_duplicate_email', {
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
      } as APIResponse);
    }

    // Hash password
    const saltRounds = parseInt(process.env.BCRYPT_ROUNDS || '12');
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Create user
    const userId = uuidv4();
    const user: Omit<User, 'createdAt' | 'updatedAt'> = {
      id: userId,
      email,
      passwordHash,
      role: role || 'user',
    };

    await database.createUser(user);

    logSecurityEvent('user_registered', {
      userId,
      email,
      role: user.role,
      ip: req.ip,
    });

    // Generate JWT token
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      logger.error('JWT_SECRET not configured');
      return res.status(500).json({
        success: false,
        error: { message: 'Server configuration error' },
        timestamp: new Date().toISOString(),
      } as APIResponse);
    }

    const token = jwt.sign(
      { 
        id: userId, 
        email, 
        role: user.role 
      },
      jwtSecret,
      { 
        expiresIn: '24h',
        issuer: 'api-risk-visualizer',
        audience: 'api-risk-visualizer-users',
      }
    );

    const response: APIResponse<{
      user: Omit<User, 'passwordHash'>;
      token: string;
      expiresIn: string;
    }> = {
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
  })
);

// POST /api/v1/auth/login - Login user
router.post('/login',
  validateRequest(loginSchema),
  asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    // Get user by email
    const user = await database.getUserByEmail(email);
    if (!user) {
      logSecurityEvent('login_attempt_invalid_email', {
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
      } as APIResponse);
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.passwordHash);
    if (!isValidPassword) {
      logSecurityEvent('login_attempt_invalid_password', {
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
      } as APIResponse);
    }

    // Update last login time
    await database.updateUserLastLogin(user.id);

    // Generate JWT token
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      logger.error('JWT_SECRET not configured');
      return res.status(500).json({
        success: false,
        error: { message: 'Server configuration error' },
        timestamp: new Date().toISOString(),
      } as APIResponse);
    }

    const token = jwt.sign(
      { 
        id: user.id, 
        email: user.email, 
        role: user.role 
      },
      jwtSecret,
      { 
        expiresIn: '24h',
        issuer: 'api-risk-visualizer',
        audience: 'api-risk-visualizer-users',
      }
    );

    logSecurityEvent('user_logged_in', {
      userId: user.id,
      email: user.email,
      ip: req.ip,
    });

    const response: APIResponse<{
      user: Omit<User, 'passwordHash'>;
      token: string;
      expiresIn: string;
    }> = {
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
  })
);

// POST /api/v1/auth/verify - Verify JWT token
router.post('/verify',
  asyncHandler(async (req, res) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        error: { message: 'Authorization token required' },
        timestamp: new Date().toISOString(),
      } as APIResponse);
    }

    const token = authHeader.substring(7);
    const jwtSecret = process.env.JWT_SECRET;

    if (!jwtSecret) {
      logger.error('JWT_SECRET not configured');
      return res.status(500).json({
        success: false,
        error: { message: 'Server configuration error' },
        timestamp: new Date().toISOString(),
      } as APIResponse);
    }

    try {
      const decoded = jwt.verify(token, jwtSecret) as any;
      
      // Get fresh user data
      const user = await database.getUserByEmail(decoded.email);
      if (!user) {
        return res.status(401).json({
          success: false,
          error: { message: 'User not found' },
          timestamp: new Date().toISOString(),
        } as APIResponse);
      }

      const response: APIResponse<{
        valid: boolean;
        user: Omit<User, 'passwordHash'>;
        expiresAt: Date;
      }> = {
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
    } catch (error) {
      logSecurityEvent('token_verification_failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        ip: req.ip,
      }, 'warn');

      res.status(401).json({
        success: false,
        error: { message: 'Invalid or expired token' },
        timestamp: new Date().toISOString(),
      } as APIResponse);
    }
  })
);

// POST /api/v1/auth/logout - Logout user (for client-side token cleanup)
router.post('/logout',
  asyncHandler(async (req, res) => {
    // In a stateless JWT system, we can't invalidate tokens server-side
    // This endpoint exists for consistency and future token blacklisting implementation
    
    logSecurityEvent('user_logged_out', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
    });

    const response: APIResponse<{ message: string }> = {
      success: true,
      data: { message: 'Logged out successfully' },
      metadata: {
        timestamp: new Date(),
      },
    };

    res.json(response);
  })
);

// GET /api/v1/auth/me - Get current user info (requires auth)
router.get('/me',
  asyncHandler(async (req, res) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        error: { message: 'Authorization token required' },
        timestamp: new Date().toISOString(),
      } as APIResponse);
    }

    const token = authHeader.substring(7);
    const jwtSecret = process.env.JWT_SECRET;

    if (!jwtSecret) {
      return res.status(500).json({
        success: false,
        error: { message: 'Server configuration error' },
        timestamp: new Date().toISOString(),
      } as APIResponse);
    }

    try {
      const decoded = jwt.verify(token, jwtSecret) as any;
      const user = await database.getUserByEmail(decoded.email);
      
      if (!user) {
        return res.status(401).json({
          success: false,
          error: { message: 'User not found' },
          timestamp: new Date().toISOString(),
        } as APIResponse);
      }

      const response: APIResponse<Omit<User, 'passwordHash'>> = {
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
    } catch (error) {
      res.status(401).json({
        success: false,
        error: { message: 'Invalid or expired token' },
        timestamp: new Date().toISOString(),
      } as APIResponse);
    }
  })
);

export { router as authRoutes }; 