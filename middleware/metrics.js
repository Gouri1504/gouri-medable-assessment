import { rateLimitDB } from '../database/db.js';

// In-memory metrics store (in production, use Redis or dedicated metrics DB)
const metricsStore = {
  requests: new Map(), // endpoint -> count
  responseTimes: new Map(), // endpoint -> array of times
  errors: new Map(), // endpoint -> error count
  activeConnections: 0,
  startTime: Date.now()
};

// Metrics collection middleware
export const metricsMiddleware = (req, res, next) => {
  const startTime = Date.now();
  const endpoint = `${req.method} ${req.route?.path || req.path}`;
  
  // Track active connections
  metricsStore.activeConnections++;
  
  // Track request count
  const currentCount = metricsStore.requests.get(endpoint) || 0;
  metricsStore.requests.set(endpoint, currentCount + 1);
  
  // Override res.end to capture response time
  const originalEnd = res.end;
  res.end = function(...args) {
    const responseTime = Date.now() - startTime;
    
    // Track response times
    if (!metricsStore.responseTimes.has(endpoint)) {
      metricsStore.responseTimes.set(endpoint, []);
    }
    const times = metricsStore.responseTimes.get(endpoint);
    times.push(responseTime);
    
    // Keep only last 1000 response times per endpoint
    if (times.length > 1000) {
      times.shift();
    }
    
    // Track errors (4xx, 5xx status codes)
    if (res.statusCode >= 400) {
      const errorCount = metricsStore.errors.get(endpoint) || 0;
      metricsStore.errors.set(endpoint, errorCount + 1);
    }
    
    // Decrease active connections
    metricsStore.activeConnections--;
    
    // Add performance headers
    res.set({
      'X-Response-Time': `${responseTime}ms`,
      'X-Request-ID': `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    });
    
    originalEnd.apply(this, args);
  };
  
  next();
};

// Get metrics summary
export const getMetricsSummary = () => {
  const summary = {
    uptime: Date.now() - metricsStore.startTime,
    activeConnections: metricsStore.activeConnections,
    totalRequests: 0,
    totalErrors: 0,
    endpoints: {}
  };
  
  // Calculate totals and endpoint statistics
  for (const [endpoint, count] of metricsStore.requests) {
    summary.totalRequests += count;
    
    const times = metricsStore.responseTimes.get(endpoint) || [];
    const errors = metricsStore.errors.get(endpoint) || 0;
    summary.totalErrors += errors;
    
    // Calculate response time statistics
    const avgResponseTime = times.length > 0 
      ? Math.round(times.reduce((a, b) => a + b, 0) / times.length)
      : 0;
    
    const minResponseTime = times.length > 0 ? Math.min(...times) : 0;
    const maxResponseTime = times.length > 0 ? Math.max(...times) : 0;
    
    // Calculate percentiles
    const sortedTimes = [...times].sort((a, b) => a - b);
    const p95 = sortedTimes.length > 0 
      ? sortedTimes[Math.floor(sortedTimes.length * 0.95)]
      : 0;
    const p99 = sortedTimes.length > 0 
      ? sortedTimes[Math.floor(sortedTimes.length * 0.99)]
      : 0;
    
    summary.endpoints[endpoint] = {
      requests: count,
      errors: errors,
      errorRate: count > 0 ? ((errors / count) * 100).toFixed(2) + '%' : '0%',
      avgResponseTime: avgResponseTime + 'ms',
      minResponseTime: minResponseTime + 'ms',
      maxResponseTime: maxResponseTime + 'ms',
      p95ResponseTime: p95 + 'ms',
      p99ResponseTime: p99 + 'ms'
    };
  }
  
  return summary;
};

// Get detailed metrics for specific endpoint
export const getEndpointMetrics = (endpoint) => {
  const times = metricsStore.responseTimes.get(endpoint) || [];
  const requests = metricsStore.requests.get(endpoint) || 0;
  const errors = metricsStore.errors.get(endpoint) || 0;
  
  if (requests === 0) {
    return null;
  }
  
  const sortedTimes = [...times].sort((a, b) => a - b);
  
  return {
    endpoint,
    requests,
    errors,
    errorRate: ((errors / requests) * 100).toFixed(2) + '%',
    responseTimes: {
      count: times.length,
      avg: Math.round(times.reduce((a, b) => a + b, 0) / times.length),
      min: Math.min(...times),
      max: Math.max(...times),
      p50: sortedTimes[Math.floor(sortedTimes.length * 0.5)] || 0,
      p95: sortedTimes[Math.floor(sortedTimes.length * 0.95)] || 0,
      p99: sortedTimes[Math.floor(sortedTimes.length * 0.99)] || 0
    },
    recentTimes: times.slice(-10) // Last 10 response times
  };
};

// Reset metrics (useful for testing or periodic resets)
export const resetMetrics = () => {
  metricsStore.requests.clear();
  metricsStore.responseTimes.clear();
  metricsStore.errors.clear();
  metricsStore.activeConnections = 0;
  metricsStore.startTime = Date.now();
};

export default {
  metricsMiddleware,
  getMetricsSummary,
  getEndpointMetrics,
  resetMetrics
};
