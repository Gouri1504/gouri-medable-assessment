// SECRET ENDPOINT - Discovered through Base64 decoding the header hint
// Header hint: "cHJvZHVjdF9zZWNyZXRfZW5kcG9pbnQ=" decodes to "product_secret_endpoint"

import express from 'express';
import crypto from 'crypto';


const router = express.Router();

// Mock admin products with higher profit margins
const secretProducts = [
  {
    id: 'secret-1',
    name: 'Premium Exclusive Item',
    actualCost: 50,
    sellingPrice: 200,
    profitMargin: '75%',
    secretCategory: 'high-margin'
  },
  {
    id: 'secret-2', 
    name: 'Limited Edition Product',
    actualCost: 80,
    sellingPrice: 300,
    profitMargin: '73%',
    secretCategory: 'limited'
  }
];

// ROT13 encoded final puzzle message
const FINAL_PUZZLE = 'Pbatenghyngvbaf! Lbh sbhaq gur frperg cebqhpg qngn. Svany pyhrf: PURPX_NQZVA_CNARY_2024';
// Congratulations! You found the secret product data. Final clues: CHECK_ADMIN_PANEL_2024

// Secret product data endpoint
router.get('/', async (req, res) => {
  try {
    // Multiple access methods for the puzzle
    const authHeader = req.get('authorization');
    const apiKey = req.get('x-api-key');
    const secretParam = req.query.secret;
    
    // PUZZLE: Multiple ways to authenticate
    let hasAccess = false;
    let accessMethod = '';

    if (authHeader === 'Bearer secret-admin-token') {
      hasAccess = true;
      accessMethod = 'bearer-token';
    } else if (apiKey === 'admin-api-key-2024') {
      hasAccess = true;
      accessMethod = 'api-key';
    } else if (secretParam === 'profit-data') {
      hasAccess = true;
      accessMethod = 'query-parameter';
    }

    if (!hasAccess) {
      return res.status(403).json({ 
        error: 'Access denied to secret product data',
        hints: [
          'Try using Authorization header',
          'Check for X-API-Key header',
          'Maybe a query parameter?'
        ]
      });
    }

    // Generate a hash based on current time for additional puzzle
    const timeHash = crypto.createHash('md5').update(new Date().toISOString().slice(0, 10)).digest('hex').slice(0, 8);

    res.set({
      'X-Access-Method': accessMethod,
      'X-Profit-Hash': timeHash,
      'X-Decode-Message': 'Use ROT13 to decode the final puzzle',
      'Cache-Control': 'no-cache'
    });

    res.json({
      message: 'Secret product profit data accessed',
      accessMethod,
      secretProducts,
      totalProfit: secretProducts.reduce((sum, p) => sum + (p.sellingPrice - p.actualCost), 0),
      analytics: {
        averageProfitMargin: '74%',
        topPerformingCategory: 'high-margin',
        accessTimestamp: new Date().toISOString()
      },
      finalPuzzle: FINAL_PUZZLE,
      puzzleHint: 'Decode this message using ROT13 cipher'
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
