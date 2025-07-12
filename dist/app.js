"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.server = exports.app = void 0;
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const helmet_1 = __importDefault(require("helmet"));
const http_1 = require("http");
const ws_1 = require("ws");
const dotenv_1 = __importDefault(require("dotenv"));
const rate_limiter_flexible_1 = require("rate-limiter-flexible");
const logger_1 = require("./utils/logger");
const database_1 = require("./core/database");
const middleware_1 = require("./utils/middleware");
const auth_1 = require("./routes/auth");
const scans_1 = require("./routes/scans");
const reports_1 = require("./routes/reports");
const ai_1 = require("./routes/ai");
const websocket_1 = require("./core/websocket");
// Load environment variables
dotenv_1.default.config();
const app = (0, express_1.default)();
exports.app = app;
const server = (0, http_1.createServer)(app);
exports.server = server;
const wss = new ws_1.WebSocketServer({ server });
// Security middleware
app.use((0, helmet_1.default)({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
}));
// CORS configuration
app.use((0, cors_1.default)({
    origin: process.env.CORS_ORIGIN || 'http://localhost:3001',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
}));
// Rate limiting
const rateLimiter = new rate_limiter_flexible_1.RateLimiterMemory({
    points: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100'),
    duration: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000') / 1000,
});
app.use('/api', async (req, res, next) => {
    try {
        await rateLimiter.consume(req.ip || 'unknown');
        next();
    }
    catch (rejRes) {
        res.status(429).json({
            error: 'Too many requests from this IP, please try again later.',
        });
    }
});
// Body parsing middleware
app.use(express_1.default.json({ limit: '10mb' }));
app.use(express_1.default.urlencoded({ extended: true, limit: '10mb' }));
// Logging middleware
app.use((req, res, next) => {
    logger_1.logger.info(`${req.method} ${req.path}`, {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString(),
    });
    next();
});
// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        version: process.env.npm_package_version || '1.0.0',
        environment: process.env.NODE_ENV || 'development',
    });
});
// API routes
const apiVersion = process.env.API_VERSION || 'v1';
app.use(`/api/${apiVersion}/auth`, auth_1.authRoutes);
app.use(`/api/${apiVersion}/scans`, scans_1.scanRoutes);
app.use(`/api/${apiVersion}/reports`, reports_1.reportRoutes);
app.use(`/api/${apiVersion}/ai`, ai_1.aiRoutes);
// WebSocket handling
(0, websocket_1.websocketHandler)(wss);
// Error handling middleware
app.use(middleware_1.notFound);
app.use(middleware_1.errorHandler);
// Graceful shutdown
process.on('SIGTERM', () => {
    logger_1.logger.info('SIGTERM received, shutting down gracefully');
    server.close(() => {
        logger_1.logger.info('HTTP server closed');
        database_1.database.close();
        process.exit(0);
    });
});
process.on('SIGINT', () => {
    logger_1.logger.info('SIGINT received, shutting down gracefully');
    server.close(() => {
        logger_1.logger.info('HTTP server closed');
        database_1.database.close();
        process.exit(0);
    });
});
// Start server
const PORT = process.env.PORT || 3000;
async function startServer() {
    try {
        // Initialize database
        await database_1.database.initialize();
        logger_1.logger.info('Database initialized successfully');
        // Start HTTP server
        server.listen(PORT, () => {
            logger_1.logger.info(`API Risk Visualizer server running on port ${PORT}`);
            logger_1.logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
            logger_1.logger.info(`API Version: ${apiVersion}`);
        });
    }
    catch (error) {
        logger_1.logger.error('Failed to start server:', error);
        process.exit(1);
    }
}
startServer();
//# sourceMappingURL=app.js.map