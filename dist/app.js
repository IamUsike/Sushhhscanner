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
const socket_io_1 = require("socket.io");
const dotenv_1 = __importDefault(require("dotenv"));
const path_1 = __importDefault(require("path"));
const logger_1 = require("./utils/logger");
const scans_1 = require("./routes/scans");
const reports_1 = require("./routes/reports");
const ml_1 = __importDefault(require("./routes/ml"));
const middleware_1 = require("./utils/middleware"); // Restore middleware
const database_1 = require("./core/database"); // Corrected import path
dotenv_1.default.config();
const app = (0, express_1.default)();
exports.app = app;
const server = (0, http_1.createServer)(app);
exports.server = server;
const io = new socket_io_1.Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});
console.log('app.ts starting');
// Restore original Helmet configuration with correct CSP
app.use((0, helmet_1.default)({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.socket.io", "https://cdn.jsdelivr.net", "https://d3js.org", "https://unpkg.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "ws://localhost:3000", "http://localhost:3000"]
        },
    },
}));
app.use((0, cors_1.default)());
app.use(express_1.default.json());
const PUBLIC_PATH = path_1.default.join(__dirname, '..', 'public');
app.use(express_1.default.static(PUBLIC_PATH));
const API_VERSION = process.env.API_VERSION || 'v1';
const apiRouter = (0, scans_1.scanRoutes)(io); // Get the router from the routes file
app.use(`/api/${API_VERSION}/scans`, apiRouter);
app.use(`/api/${API_VERSION}/reports`, reports_1.reportRoutes);
app.use(`/api/${API_VERSION}/ml`, ml_1.default);
app.get('/', (req, res) => {
    res.sendFile(path_1.default.join(PUBLIC_PATH, 'real_api_dashboard_revamped.html'));
});
io.on('connection', (socket) => {
    logger_1.logger.info(`✅ Client connected: ${socket.id}`);
    socket.on('subscribe', (scanId) => {
        logger_1.logger.info(`Client ${socket.id} subscribed to scan: ${scanId}`);
        socket.join(scanId);
    });
    socket.on('disconnect', () => {
        logger_1.logger.info(`❌ Client disconnected: ${socket.id}`);
    });
});
app.use(middleware_1.notFound);
app.use(middleware_1.errorHandler);
const PORT = process.env.PORT || 3000;
// --- Server Startup ---
const startServer = async () => {
    try {
        await database_1.database.initialize();
        logger_1.logger.info('🗃️  Database initialized successfully');
        server.listen(PORT, () => {
            logger_1.logger.info(`🚀 Server is stable and running on http://localhost:${PORT}`);
        });
    }
    catch (error) {
        logger_1.logger.error('❌ Failed to start server:', error);
        process.exit(1);
    }
};
startServer();
//# sourceMappingURL=app.js.map