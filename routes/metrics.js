import express from 'express';
import { authorizeRole } from '../middleware/authenticate_token.js';
import { adminRateLimit } from '../middleware/rate_limit.js';
import { getMetricsSummary, getEndpointMetrics, resetMetrics } from '../middleware/metrics.js';

const router = express.Router();

// Get API metrics summary - admin only
router.get('/summary', adminRateLimit, authorizeRole(['admin']), (req, res) => {
  try {
    const metrics = getMetricsSummary();
    
    res.set({
      'Cache-Control': 'no-cache',
      'X-Metrics-Collection': 'enabled'
    });
    
    res.json({
      message: 'API performance metrics',
      timestamp: new Date().toISOString(),
      metrics: {
        uptime: {
          milliseconds: metrics.uptime,
          seconds: Math.floor(metrics.uptime / 1000),
          minutes: Math.floor(metrics.uptime / 60000),
          hours: Math.floor(metrics.uptime / 3600000)
        },
        requests: {
          total: metrics.totalRequests,
          active: metrics.activeConnections,
          errors: metrics.totalErrors,
          errorRate: metrics.totalRequests > 0 
            ? ((metrics.totalErrors / metrics.totalRequests) * 100).toFixed(2) + '%'
            : '0%'
        },
        endpoints: metrics.endpoints
      }
    });
  } catch (error) {
    console.error('Metrics summary error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Unable to retrieve metrics at this time'
    });
  }
});

// Get detailed metrics for specific endpoint - admin only
router.get('/endpoint/*', adminRateLimit, authorizeRole(['admin']), (req, res) => {
  try {
    // Extract endpoint from URL (everything after /endpoint/)
    const endpoint = req.params[0];
    
    if (!endpoint) {
      return res.status(400).json({ 
        error: 'Endpoint parameter required',
        example: '/api/metrics/endpoint/GET%20/api/products'
      });
    }
    
    const decodedEndpoint = decodeURIComponent(endpoint);
    const metrics = getEndpointMetrics(decodedEndpoint);
    
    if (!metrics) {
      return res.status(404).json({ 
        error: 'No metrics found for this endpoint',
        endpoint: decodedEndpoint
      });
    }
    
    res.set({
      'Cache-Control': 'no-cache',
      'X-Endpoint-Metrics': 'detailed'
    });
    
    res.json({
      message: 'Detailed endpoint metrics',
      timestamp: new Date().toISOString(),
      metrics
    });
  } catch (error) {
    console.error('Endpoint metrics error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Unable to retrieve endpoint metrics at this time'
    });
  }
});

// Health check with basic metrics - public endpoint
router.get('/health', (req, res) => {
  try {
    const metrics = getMetricsSummary();
    
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: Math.floor(metrics.uptime / 1000) + 's',
      activeConnections: metrics.activeConnections,
      totalRequests: metrics.totalRequests,
      memoryUsage: process.memoryUsage(),
      nodeVersion: process.version
    });
  } catch (error) {
    console.error('Health check error:', error);
    res.status(500).json({ 
      status: 'unhealthy',
      error: 'Unable to retrieve health metrics'
    });
  }
});

// Reset metrics - admin only (useful for testing)
router.post('/reset', adminRateLimit, authorizeRole(['admin']), (req, res) => {
  try {
    resetMetrics();
    
    console.log(`Metrics reset by admin: ${req.user.username}`);
    
    res.json({
      message: 'Metrics reset successfully',
      timestamp: new Date().toISOString(),
      resetBy: req.user.username
    });
  } catch (error) {
    console.error('Metrics reset error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Unable to reset metrics at this time'
    });
  }
});

// Get real-time metrics stream (Server-Sent Events) - admin only
router.get('/stream', adminRateLimit, authorizeRole(['admin']), (req, res) => {
  try {
    // Set up Server-Sent Events
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*'
    });
    
    // Send initial metrics
    const sendMetrics = () => {
      const metrics = getMetricsSummary();
      const data = JSON.stringify({
        timestamp: new Date().toISOString(),
        activeConnections: metrics.activeConnections,
        totalRequests: metrics.totalRequests,
        totalErrors: metrics.totalErrors,
        uptime: metrics.uptime
      });
      
      res.write(`data: ${data}\n\n`);
    };
    
    // Send metrics every 5 seconds
    sendMetrics();
    const interval = setInterval(sendMetrics, 5000);
    
    // Clean up on client disconnect
    req.on('close', () => {
      clearInterval(interval);
    });
    
  } catch (error) {
    console.error('Metrics stream error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Unable to start metrics stream'
    });
  }
});

export default router;
