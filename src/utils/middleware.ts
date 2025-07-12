import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { logger, logSecurityEvent } from '@utils/logger';

// Error handling middleware
export const errorHandler = (err: any, req: Request, res: Response, next: NextFunction) => {
  logger.error('Unhandled error:', {
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

// 404 handler
export const notFound = (req: Request, res: Response, next: NextFunction) => {
  logger.warn('404 - Resource not found', {
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

// Authentication middleware
export const authenticate = (req: Request, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      logSecurityEvent('unauthorized_access_attempt', {
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
      logger.error('JWT_SECRET not configured');
      return res.status(500).json({
        success: false,
        error: { message: 'Server configuration error' },
        timestamp: new Date().toISOString(),
      });
    }

    const decoded = jwt.verify(token, jwtSecret) as any;
    
    // Add user info to request
    req.user = {
      id: decoded.id,
      email: decoded.email,
      role: decoded.role,
    };

    next();
  } catch (error) {
    logSecurityEvent('invalid_token', {
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

// Admin role middleware
export const requireAdmin = (req: Request, res: Response, next: NextFunction) => {
  if (!req.user || req.user.role !== 'admin') {
    logSecurityEvent('unauthorized_admin_access', {
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

// API key validation middleware (for external integrations)
export const validateApiKey = (req: Request, res: Response, next: NextFunction) => {
  const apiKey = req.headers['x-api-key'] as string;

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
    logSecurityEvent('invalid_api_key', {
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

// Request validation helper
export const validateRequest = (schema: any) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const { error } = schema.validate(req.body);
    
    if (error) {
      logger.warn('Request validation failed', {
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

// Async handler wrapper to catch async errors
export const asyncHandler = (fn: Function) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

// Security headers middleware for scan endpoints
export const securityHeaders = (req: Request, res: Response, next: NextFunction) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  next();
};

// Type declarations for Request extension
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        email: string;
        role: string;
      };
    }
  }
} 