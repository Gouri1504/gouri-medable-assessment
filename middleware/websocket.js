import { Server } from 'socket.io';
import jwt from 'jsonwebtoken';

let io;

// Initialize WebSocket server
export const initializeWebSocket = (server) => {
  // Get WebSocket CORS origins from environment variables
  const getWSOriginsFromEnv = (envVar, fallbackOrigins) => {
    const envOrigins = process.env[envVar];
    if (envOrigins) {
      return envOrigins.split(',').map(origin => origin.trim());
    }
    return fallbackOrigins;
  };

  const wsOrigins = process.env.NODE_ENV === 'production' 
    ? getWSOriginsFromEnv('WS_PRODUCTION_ORIGINS', 
        process.env.PRODUCTION_ORIGINS 
          ? process.env.PRODUCTION_ORIGINS.split(',').map(origin => origin.trim())
          : ["https://yourdomain.com", "https://www.yourdomain.com"]
      )
    : getWSOriginsFromEnv('WS_DEV_ORIGINS',
        process.env.DEV_ORIGINS
          ? process.env.DEV_ORIGINS.split(',').map(origin => origin.trim()) 
          : ["http://localhost:3000", "http://localhost:3001", "http://localhost:8080", "http://localhost:8888"]
      );

  io = new Server(server, {
    cors: {
      origin: wsOrigins,
      methods: process.env.WS_ALLOWED_METHODS ? process.env.WS_ALLOWED_METHODS.split(',') : ["GET", "POST"]
    }
  });

  // Authentication middleware for WebSocket connections
  io.use((socket, next) => {
    try {
      const token = socket.handshake.auth.token;
      if (!token) {
        return next(new Error('Authentication token required'));
      }

      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      socket.userId = decoded.userId;
      socket.userRole = decoded.role;
      socket.username = decoded.username;
      
      console.log(`WebSocket connection authenticated: ${decoded.username} (${decoded.role})`);
      next();
    } catch (error) {
      console.error('WebSocket authentication error:', error);
      next(new Error('Invalid authentication token'));
    }
  });

  // Handle WebSocket connections
  io.on('connection', (socket) => {
    console.log(`WebSocket connected: ${socket.username} (${socket.id})`);
    
    // Join user to their personal room for cart updates
    socket.join(`user:${socket.userId}`);
    
    // Join admins to admin room for inventory updates
    if (socket.userRole === 'admin') {
      socket.join('admin');
      
      // Send current connection stats to admin
      socket.emit('connection_stats', {
        totalConnections: io.engine.clientsCount,
        timestamp: new Date().toISOString()
      });
    }

    // Handle inventory subscription
    socket.on('subscribe_inventory', (data) => {
      try {
        const { productIds } = data;
        
        if (!Array.isArray(productIds)) {
          socket.emit('error', { message: 'Product IDs must be an array' });
          return;
        }
        
        // Join rooms for specific products
        productIds.forEach(productId => {
          socket.join(`product:${productId}`);
        });
        
        socket.emit('inventory_subscribed', {
          productIds,
          message: 'Subscribed to inventory updates',
          timestamp: new Date().toISOString()
        });
        
        console.log(`${socket.username} subscribed to inventory updates for products: ${productIds.join(', ')}`);
      } catch (error) {
        console.error('Inventory subscription error:', error);
        socket.emit('error', { message: 'Failed to subscribe to inventory updates' });
      }
    });

    // Handle unsubscribe from inventory
    socket.on('unsubscribe_inventory', (data) => {
      try {
        const { productIds } = data;
        
        if (!Array.isArray(productIds)) {
          socket.emit('error', { message: 'Product IDs must be an array' });
          return;
        }
        
        // Leave rooms for specific products
        productIds.forEach(productId => {
          socket.leave(`product:${productId}`);
        });
        
        socket.emit('inventory_unsubscribed', {
          productIds,
          message: 'Unsubscribed from inventory updates',
          timestamp: new Date().toISOString()
        });
        
        console.log(`${socket.username} unsubscribed from inventory updates for products: ${productIds.join(', ')}`);
      } catch (error) {
        console.error('Inventory unsubscription error:', error);
        socket.emit('error', { message: 'Failed to unsubscribe from inventory updates' });
      }
    });

    // Handle cart sync requests
    socket.on('sync_cart', () => {
      socket.emit('cart_sync_requested', {
        message: 'Cart sync requested',
        timestamp: new Date().toISOString()
      });
    });

    // Handle disconnect
    socket.on('disconnect', (reason) => {
      console.log(`WebSocket disconnected: ${socket.username} (${socket.id}) - Reason: ${reason}`);
    });

    // Send welcome message
    socket.emit('connected', {
      message: 'Connected to real-time updates',
      userId: socket.userId,
      role: socket.userRole,
      timestamp: new Date().toISOString()
    });
  });

  console.log('✅ WebSocket server initialized');
  return io;
};

// Broadcast inventory update to subscribers
export const broadcastInventoryUpdate = (productId, inventoryData) => {
  if (!io) return;
  
  io.to(`product:${productId}`).emit('inventory_update', {
    productId,
    ...inventoryData,
    timestamp: new Date().toISOString()
  });
  
  console.log(`Broadcasted inventory update for product ${productId} to subscribers`);
};

// Broadcast cart update to specific user
export const broadcastCartUpdate = (userId, cartData) => {
  if (!io) return;
  
  io.to(`user:${userId}`).emit('cart_update', {
    ...cartData,
    timestamp: new Date().toISOString()
  });
  
  console.log(`Broadcasted cart update to user ${userId}`);
};

// Broadcast admin notification
export const broadcastAdminNotification = (notification) => {
  if (!io) return;
  
  io.to('admin').emit('admin_notification', {
    ...notification,
    timestamp: new Date().toISOString()
  });
  
  console.log('Broadcasted admin notification');
};

// Get WebSocket connection stats
export const getConnectionStats = () => {
  if (!io) return null;
  
  return {
    totalConnections: io.engine.clientsCount,
    rooms: Array.from(io.sockets.adapter.rooms.keys()),
    timestamp: new Date().toISOString()
  };
};

export default {
  initializeWebSocket,
  broadcastInventoryUpdate,
  broadcastCartUpdate,
  broadcastAdminNotification,
  getConnectionStats
};
