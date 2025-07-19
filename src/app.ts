import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import dotenv from 'dotenv';
import path from 'path';

import { logger } from './utils/logger';
import { scanRoutes } from './routes/scans';
import reportRoutes from './routes/reports';
import mlRoutes from './routes/ml';
import { notFound, errorHandler } from './utils/middleware'; // Restore middleware
import { database } from './core/database'; // Corrected import path

dotenv.config();

const app = express();
const server = createServer(app);

const io = new SocketIOServer(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});


console.log('app.ts starting');
// Restore original Helmet configuration with correct CSP
app.use(helmet({
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

app.use(cors());
app.use(express.json());

const PUBLIC_PATH = path.join(__dirname, '..', 'public');
app.use(express.static(PUBLIC_PATH));

const API_VERSION = process.env.API_VERSION || 'v1';
const apiRouter = scanRoutes(io); // Get the router from the routes file
app.use(`/api/${API_VERSION}/scans`, apiRouter);
app.use(`/api/${API_VERSION}/reports`, reportRoutes);
app.use(`/api/${API_VERSION}/ml`, mlRoutes);

app.get('/', (req, res) => {
  res.sendFile(path.join(PUBLIC_PATH, 'real_api_dashboard_revamped.html'));
});

io.on('connection', (socket) => {
    logger.info(`✅ Client connected: ${socket.id}`);
    socket.on('subscribe', (scanId) => {
        logger.info(`Client ${socket.id} subscribed to scan: ${scanId}`);
        socket.join(scanId);
});
    socket.on('disconnect', () => {
        logger.info(`❌ Client disconnected: ${socket.id}`);
  });
});

app.use(notFound);
app.use(errorHandler);

const PORT = process.env.PORT || 3000;

// --- Server Startup ---
const startServer = async () => {
  try {
    await database.initialize();
        logger.info('🗃️  Database initialized successfully');
    server.listen(PORT, () => {
            logger.info(`🚀 Server is stable and running on http://localhost:${PORT}`);
    });
  } catch (error) {
        logger.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

startServer();

export { app, server }; 