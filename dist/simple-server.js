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
// Load environment variables
dotenv_1.default.config();
const app = (0, express_1.default)();
exports.app = app;
const server = (0, http_1.createServer)(app);
exports.server = server;
const wss = new ws_1.WebSocketServer({ server });
// Basic middleware
app.use((0, helmet_1.default)());
app.use((0, cors_1.default)());
app.use(express_1.default.json());
// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        environment: process.env.NODE_ENV || 'development',
    });
});
// Basic API info endpoint
app.get('/api/v1', (req, res) => {
    res.json({
        message: 'API Risk Visualizer - REST API',
        version: '1.0.0',
        endpoints: {
            health: '/health',
            auth: '/api/v1/auth',
            scans: '/api/v1/scans',
            reports: '/api/v1/reports',
            ai: '/api/v1/ai',
        },
        features: [
            'API Security Scanning',
            'AI-Powered Risk Prediction',
            'Real-time WebSocket Updates',
            'Comprehensive Reporting',
            'OWASP API Top 10 Compliance',
        ],
        timestamp: new Date().toISOString(),
    });
});
// Basic WebSocket handling
wss.on('connection', (ws) => {
    console.log('New WebSocket connection');
    ws.send(JSON.stringify({
        type: 'welcome',
        message: 'Connected to API Risk Visualizer',
        timestamp: new Date().toISOString(),
    }));
    ws.on('message', (message) => {
        console.log('Received:', message.toString());
        ws.send(JSON.stringify({
            type: 'echo',
            data: message.toString(),
            timestamp: new Date().toISOString(),
        }));
    });
    ws.on('close', () => {
        console.log('WebSocket connection closed');
    });
});
// Error handling
app.use((req, res) => {
    res.status(404).json({
        error: 'Not Found',
        message: `Route ${req.originalUrl} not found`,
        timestamp: new Date().toISOString(),
    });
});
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({
        error: 'Internal Server Error',
        message: process.env.NODE_ENV === 'production' ? 'Something went wrong' : err.message,
        timestamp: new Date().toISOString(),
    });
});
// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`🚀 API Risk Visualizer server running on port ${PORT}`);
    console.log(`📊 Health check: http://localhost:${PORT}/health`);
    console.log(`🔌 WebSocket: ws://localhost:${PORT}`);
    console.log(`📚 API Info: http://localhost:${PORT}/api/v1`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
});
//# sourceMappingURL=simple-server.js.map