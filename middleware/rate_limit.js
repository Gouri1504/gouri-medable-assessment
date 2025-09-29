import rateLimit from 'express-rate-limit';
import { rateLimitDB } from '../database/db.js';

// Custom rate limit store using our database
class DatabaseStore {
  constructor(windowMs = parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, maxRequests = parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100) {
    this.windowMs = windowMs;
    this.maxRequests = maxRequests;
  }

  async increment(key) {
    try {
      const [ip, endpoint] = key.split(':');
      const result = await rateLimitDB.checkRateLimit(
        ip, 
        endpoint, 
        this.maxRequests, // max requests per window from environment
        this.windowMs
      );
      
      return {
        totalHits: result.requests,
        resetTime: new Date(result.resetTime)
      };
    } catch (error) {
      console.error('Rate limit store error:', error);
      // Fallback to allow request if database fails
      return {
        totalHits: 1,
        resetTime: new Date(Date.now() + this.windowMs)
      };
    }
  }

  async decrement(key) {
    // Not implemented for this simple store
    return;
  }

  async resetKey(key) {
    // Not implemented for this simple store
    return;
  }
}

// General API rate limiter
export const generalRateLimit = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100, // Limit each IP to 100 requests per windowMs
  message: {
    error: process.env.RATE_LIMIT_ERROR_MESSAGE || 'Too many requests from this IP',
    message: process.env.RATE_LIMIT_MESSAGE || 'Please try again later',
    retryAfter: process.env.RATE_LIMIT_RETRY_AFTER || '15 minutes'
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  store: new DatabaseStore(parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000),
  keyGenerator: (req) => `${req.ip}:general`,
  handler: (req, res) => {
    console.warn(`Rate limit exceeded for IP: ${req.ip} on ${req.path}`);
    res.status(429).json({
      error: 'Too many requests',
      message: 'Rate limit exceeded. Please try again later.',
      retryAfter: Math.ceil(req.rateLimit.resetTime.getTime() - Date.now()) / 1000
    });
  }
});

// Strict rate limiter for authentication endpoints
export const authRateLimit = rateLimit({
  windowMs: parseInt(process.env.AUTH_RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.AUTH_RATE_LIMIT_MAX_REQUESTS) || 10, // Limit each IP to 10 auth requests per windowMs
  message: {
    error: process.env.AUTH_RATE_LIMIT_ERROR_MESSAGE || 'Too many authentication attempts',
    message: process.env.AUTH_RATE_LIMIT_MESSAGE || 'Please try again later',
    retryAfter: process.env.AUTH_RATE_LIMIT_RETRY_AFTER || '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
  store: new DatabaseStore(parseInt(process.env.AUTH_RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000),
  keyGenerator: (req) => `${req.ip}:auth`,
  handler: (req, res) => {
    console.warn(`Auth rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({
      error: 'Too many authentication attempts',
      message: 'Please wait before trying to authenticate again.',
      retryAfter: Math.ceil(req.rateLimit.resetTime.getTime() - Date.now()) / 1000
    });
  }
});

// Strict rate limiter for product creation/modification
export const adminRateLimit = rateLimit({
  windowMs: parseInt(process.env.ADMIN_RATE_LIMIT_WINDOW_MS) || 5 * 60 * 1000, // 5 minutes
  max: parseInt(process.env.ADMIN_RATE_LIMIT_MAX_REQUESTS) || 20, // Limit each IP to 20 admin operations per 5 minutes
  message: {
    error: process.env.ADMIN_RATE_LIMIT_ERROR_MESSAGE || 'Too many admin operations',
    message: process.env.ADMIN_RATE_LIMIT_MESSAGE || 'Please slow down your requests',
    retryAfter: process.env.ADMIN_RATE_LIMIT_RETRY_AFTER || '5 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
  store: new DatabaseStore(parseInt(process.env.ADMIN_RATE_LIMIT_WINDOW_MS) || 5 * 60 * 1000),
  keyGenerator: (req) => `${req.ip}:admin`,
  handler: (req, res) => {
    console.warn(`Admin rate limit exceeded for IP: ${req.ip} on ${req.path}`);
    res.status(429).json({
      error: 'Too many admin operations',
      message: 'Please slow down your administrative requests.',
      retryAfter: Math.ceil(req.rateLimit.resetTime.getTime() - Date.now()) / 1000
    });
  }
});

// Cart operations rate limiter
export const cartRateLimit = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 30, // Limit each IP to 30 cart operations per minute
  message: {
    error: 'Too many cart operations',
    message: 'Please slow down your cart modifications',
    retryAfter: '1 minute'
  },
  standardHeaders: true,
  legacyHeaders: false,
  store: new DatabaseStore(1 * 60 * 1000),
  keyGenerator: (req) => `${req.ip}:cart`,
  handler: (req, res) => {
    console.warn(`Cart rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({
      error: 'Too many cart operations',
      message: 'Please slow down your cart modifications.',
      retryAfter: Math.ceil(req.rateLimit.resetTime.getTime() - Date.now()) / 1000
    });
  }
});

// Clean old rate limit records periodically
export function startRateLimitCleanup() {
  // Clean every hour
  setInterval(async () => {
    try {
      const result = await rateLimitDB.cleanOldRecords();
      console.log(`Cleaned ${result.deletedRows} old rate limit records`);
    } catch (error) {
      console.error('Error cleaning rate limit records:', error);
    }
  }, 60 * 60 * 1000); // 1 hour
}

export default {
  generalRateLimit,
  authRateLimit,
  adminRateLimit,
  cartRateLimit,
  startRateLimitCleanup
};
