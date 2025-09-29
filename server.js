import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import authenticateToken , {authorizeRole} from './middleware/authenticate_token.js';
import { generalRateLimit, authRateLimit, startRateLimitCleanup } from './middleware/rate_limit.js';
import { metricsMiddleware } from './middleware/metrics.js';
import { initializeWebSocket } from './middleware/websocket.js';
import { initializeDatabase, closeDatabase } from './database/db.js';
import path from 'path'; //used in Express.js to serve static files (like HTML, CSS, JS, images, fonts, PDFs, etc.) from a folder.
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const _dirname = path.dirname(__filename);




// Import routes
import productsRoutes from './routes/products.js';
import cartRoutes from './routes/cart.js';
import secretProductRoutes from './routes/product_secret_endpoint.js';
import authRoutes from './routes/auth.js';
import metricsRoutes from './routes/metrics.js';
import http from 'http';

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3002;

// Production-ready CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    // Define allowed origins based on environment variables
    const getOriginsFromEnv = (envVar, fallbackOrigins) => {
      const envOrigins = process.env[envVar];
      if (envOrigins) {
        return envOrigins.split(',').map(origin => origin.trim());
      }
      return fallbackOrigins;
    };

    const allowedOrigins = process.env.NODE_ENV === 'production' 
      ? getOriginsFromEnv('PRODUCTION_ORIGINS', [
          'https://gouri-medable-assessment.onrender.com',
          'https://www.demo.com',
          'https://admin.demo.com'
        ])
      : getOriginsFromEnv('DEV_ORIGINS', [
          'http://localhost:3000',
          'http://localhost:3001',
          'http://localhost:8080',
          'http://127.0.0.1:3000',
          'http://localhost:8888'
        ]);
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn(`CORS blocked origin: ${origin}`);
      callback(new Error('Not allowed by CORS policy'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Origin',
    'X-Requested-With', 
    'Content-Type', 
    'Accept',
    'Authorization',
    'X-User-Id',
    'X-API-Key'
  ],
  credentials: true, // Allow cookies and authorization headers
  optionsSuccessStatus: 200, // For legacy browser support
  maxAge: 86400 // Cache preflight response for 24 hours
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' })); // Limit payload size
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(_dirname, 'public')));

// Apply general rate limiting to all routes
app.use(generalRateLimit);

// Apply metrics collection to all routes
app.use(metricsMiddleware);

// remove puzzle hint header 'X-Puzzle-Hint': 'base64_decode_this_cHJvZHVjdF9zZWNyZXRfZW5kcG9pbnQ=',
app.use((req, res, next) => {
  res.set({
    'X-API-Version': 'v2.0',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS'
  });
  next();
});

// Routes with specific rate limiting
app.use('/api/products', authenticateToken, productsRoutes);
app.use('/api/cart', authenticateToken, cartRoutes);
app.use('/api/product_secret_endpoint' , authenticateToken, authorizeRole(['admin']) , secretProductRoutes);
app.use('/api/auth', authRateLimit, authRoutes);
app.use('/api/metrics', authenticateToken, metricsRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Serve static files
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Error handler
app.use((error, req, res, next) => {
  console.error('Error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// Initialize database and start server
async function startServer() {
  try {
    // Initialize database
    await initializeDatabase();
    console.log('Database initialized successfully');
    
    // Start rate limit cleanup
    startRateLimitCleanup();
    console.log('Rate limit cleanup started');
    
    // Initialize WebSocket server
    initializeWebSocket(server);
    console.log('WebSocket server initialized');
    
    // Start server
    server.listen(PORT, () => {
      console.log(`Assessment 2: E-commerce Product API running on http://localhost:${PORT}`);
      console.log(`View instructions: http://localhost:${PORT}`);
      console.log(`CORS configured for ${process.env.NODE_ENV || 'development'} environment`);
      console.log(`Rate limiting enabled`);
      console.log(`Database persistence active`);
      console.log(`Performance metrics collection enabled`);
      console.log(`Advanced search with faceted filtering available`);
      console.log(`Product recommendation engine active`);
      console.log(`Product catalog export functionality enabled`);
      console.log(`Real-time WebSocket updates active`);
    });

    // Graceful shutdown
    process.on('SIGTERM', async () => {
      console.log('SIGTERM received, shutting down gracefully');
      server.close(async () => {
        await closeDatabase();
        process.exit(0);
      });
    });

    process.on('SIGINT', async () => {
      console.log('SIGINT received, shutting down gracefully');
      server.close(async () => {
        await closeDatabase();
        process.exit(0);
      });
    });

  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();
