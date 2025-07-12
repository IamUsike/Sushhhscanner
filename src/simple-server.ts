import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { createServer } from 'http';
import { WebSocketServer } from 'ws';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const app = express();
const server = createServer(app);
const wss = new WebSocketServer({ server });

// Basic middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

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

app.use((err: any, req: any, res: any, next: any) => {
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

export { app, server }; 