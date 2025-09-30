import express from 'express';
import validator from 'validator';
import {authorizeRole} from '../middleware/authenticate_token.js';
import { cartRateLimit } from '../middleware/rate_limit.js';
import { cartDB } from '../database/db.js';
import { broadcastCartUpdate } from '../middleware/websocket.js';

const router = express.Router();

// PERFORMANCE FIX: Enhanced cart storage with database persistence and caching
const cartTotalsCache = new Map(); // Cache for cart totals
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// Mock product prices for cart calculations (in real app, this would come from product service)
const productPrices = {
  '1': 100, '2': 200, '3': 150, '4': 75, '5': 300,
  '6': 120, '7': 180, '8': 90, '9': 250, '10': 320
};

// PERFORMANCE FIX: Efficient cart total calculation with caching
function calculateCartTotal(userId, cart) {
  const cacheKey = `${userId}-${cart.items.length}-${Date.now()}`;
  
  if (cartTotalsCache.has(userId)) {
    const cached = cartTotalsCache.get(userId);
    if (Date.now() - cached.timestamp < CACHE_TTL) {
      return cached.total;
    }
  }

  let total = 0;
  cart.items.forEach(item => {
    const price = productPrices[item.productId] || 0;
    total += price * item.quantity;
  });

  // Cache the result
  cartTotalsCache.set(userId, {
    total: total,
    timestamp: Date.now()
  });

  return total;
}

// Clear cache when cart changes
function clearCartCache(userId) {
  cartTotalsCache.delete(userId);
}

// Get cart - SECURITY FIX: Authentication required
router.get('/', cartRateLimit, authorizeRole(['customer','admin']), async (req, res) => {
  try {
    // SECURITY FIX: Use authenticated user ID
    const userId = req.user.userId;
    
    // PERSISTENCE FIX: Load cart from database
    let cart = await cartDB.getCart(userId);
    
    if (!cart) {
      cart = { items: [], total: 0, createdAt: new Date().toISOString() };
    }
    
    // PERFORMANCE FIX: Use cached total calculation
    cart.total = calculateCartTotal(userId, cart);
    
    // Save updated cart to database
    await cartDB.saveCart(userId, { items: cart.items }, cart.total);

    // SECURITY FIX: Remove debug headers
    res.set({
      'X-Cart-Items': cart.items.length.toString(),
      'Cache-Control': 'private, no-cache' // Cart data is private
    });

    res.json({
      cart: {
        items: cart.items.map(item => ({
          productId: item.productId,
          quantity: item.quantity,
          price: productPrices[item.productId] || 0,
          subtotal: (productPrices[item.productId] || 0) * item.quantity,
          addedAt: item.addedAt
        })),
        total: cart.total,
        itemCount: cart.items.length,
        createdAt: cart.createdAt
      },
      metadata: {
        lastUpdated: new Date().toISOString(),
        itemCount: cart.items.length
      }
    });
  } catch (error) {
    console.error('Get cart error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Unable to retrieve cart at this time'
    });
  }
});

// Add to cart - SECURITY FIX: Authentication required (Checking customer or admin role)
router.post('/', cartRateLimit, authorizeRole(['customer','admin']), async (req, res) => {
  try {
    const userId = req.user.userId;
    const { productId, quantity = 1 } = req.body;
    
    // SECURITY FIX: Comprehensive input validation
    if (!productId || !validator.isAlphanumeric(productId.toString())) {
      return res.status(400).json({ error: 'Valid product ID is required' });
    }

    if (!quantity || !Number.isInteger(quantity) || quantity < 1 || quantity > 100) {
      return res.status(400).json({ error: 'Quantity must be between 1 and 100' });
    }

    // SECURITY FIX: Check if product exists in catalog
    if (!productPrices[productId]) {
      return res.status(404).json({ error: 'Product not found' });
    }

    // PERSISTENCE FIX: Load cart from database
    let cart = await cartDB.getCart(userId);
    
    if (!cart) {
      cart = { items: [], total: 0, createdAt: new Date().toISOString() };
    }
    
    const existingItemIndex = cart.items.findIndex(item => item.productId === productId);
    
    if (existingItemIndex >= 0) {
      // SECURITY FIX: Check maximum quantity limits
      const newQuantity = cart.items[existingItemIndex].quantity + quantity;
      if (newQuantity > 100) {
        return res.status(400).json({ error: 'Maximum quantity per item is 100' });
      }
      cart.items[existingItemIndex].quantity = newQuantity;
      cart.items[existingItemIndex].updatedAt = new Date().toISOString();
    } else {
      cart.items.push({
        productId,
        quantity,
        addedAt: new Date().toISOString()
      });
    }

    // Clear cache and recalculate total
    clearCartCache(userId);
    cart.total = calculateCartTotal(userId, cart);
    
    // PERSISTENCE FIX: Save cart to database
    await cartDB.saveCart(userId, { items: cart.items }, cart.total);

    // Broadcast cart update via WebSocket
    const cartData = {
      action: 'item_added',
      cart: {
        items: cart.items.map(item => ({
          productId: item.productId,
          quantity: item.quantity,
          price: productPrices[item.productId] || 0,
          subtotal: (productPrices[item.productId] || 0) * item.quantity
        })),
        total: cart.total,
        itemCount: cart.items.length
      },
      addedItem: { productId, quantity }
    };
    
    broadcastCartUpdate(userId, cartData);

    res.json({
      message: 'Item added to cart',
      cart: cartData.cart,
      addedItem: cartData.addedItem
    });
  } catch (error) {
    console.error('Add to cart error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Unable to add item to cart at this time'
    });
  }
});

// Update cart item - SECURITY FIX: Authentication required (Checking customer or admin role)
router.put('/', cartRateLimit, authorizeRole(['customer','admin']), async (req, res) => {
  try {
    const userId = req.user.userId;
    const { productId, quantity } = req.body;
    
    // SECURITY FIX: Comprehensive validation
    if (!productId || !validator.isAlphanumeric(productId.toString())) {
      return res.status(400).json({ error: 'Valid product ID is required' });
    }

    if (quantity === undefined || !Number.isInteger(quantity) || quantity < 0 || quantity > 100) {
      return res.status(400).json({ error: 'Quantity must be between 0 and 100' });
    }

    // PERSISTENCE FIX: Load cart from database
    let cart = await cartDB.getCart(userId);
    
    if (!cart) {
      cart = { items: [], total: 0 };
    }
    
    const itemIndex = cart.items.findIndex(item => item.productId === productId);
    
    if (itemIndex === -1) {
      return res.status(404).json({ error: 'Item not found in cart' });
    }

    if (quantity === 0) {
      // Remove item when quantity is 0
      cart.items.splice(itemIndex, 1);
    } else {
      cart.items[itemIndex].quantity = quantity;
      cart.items[itemIndex].updatedAt = new Date().toISOString();
    }

    // Clear cache and recalculate total
    clearCartCache(userId);
    cart.total = calculateCartTotal(userId, cart);
    
    // PERSISTENCE FIX: Save cart to database
    await cartDB.saveCart(userId, { items: cart.items }, cart.total);

    res.json({
      message: quantity === 0 ? 'Item removed from cart' : 'Cart item updated',
      cart: {
        items: cart.items.map(item => ({
          productId: item.productId,
          quantity: item.quantity,
          price: productPrices[item.productId] || 0,
          subtotal: (productPrices[item.productId] || 0) * item.quantity
        })),
        total: cart.total,
        itemCount: cart.items.length
      }
    });
  } catch (error) {
    console.error('Update cart error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Unable to update cart item at this time'
    });
  }
});

// Remove from cart - SECURITY FIX: Authentication required (Checking customer or admin role)
router.delete('/', cartRateLimit, authorizeRole(['customer','admin']), async (req, res) => {
  try {
    const userId = req.user.userId;
    const { productId } = req.query;
    
    // SECURITY FIX: Input validation
    if (!productId || !validator.isAlphanumeric(productId.toString())) {
      return res.status(400).json({ error: 'Valid product ID is required' });
    }

    // PERSISTENCE FIX: Load cart from database
    let cart = await cartDB.getCart(userId);
    
    if (!cart) {
      cart = { items: [], total: 0 };
    }
    
    const itemIndex = cart.items.findIndex(item => item.productId === productId);
    
    if (itemIndex === -1) {
      return res.status(404).json({ error: 'Item not found in cart' });
    }

    const removedItem = cart.items.splice(itemIndex, 1)[0];

    // PERFORMANCE FIX: Use cached calculation
    clearCartCache(userId);
    cart.total = calculateCartTotal(userId, cart);
    
    // PERSISTENCE FIX: Save cart to database
    await cartDB.saveCart(userId, { items: cart.items }, cart.total);

    res.json({
      message: 'Item removed from cart',
      cart: {
        items: cart.items.map(item => ({
          productId: item.productId,
          quantity: item.quantity,
          price: productPrices[item.productId] || 0,
          subtotal: (productPrices[item.productId] || 0) * item.quantity
        })),
        total: cart.total,
        itemCount: cart.items.length
      },
      removedItem: {
        productId: removedItem.productId,
        quantity: removedItem.quantity
      }
    });
  } catch (error) {
    console.error('Remove from cart error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Unable to remove item from cart at this time'
    });
  }
});

// Clear entire cart - Additional feature
router.delete('/clear', cartRateLimit, authorizeRole(['customer','admin']), async (req, res) => {
  try {
    const userId = req.user.userId;
    
    // PERSISTENCE FIX: Delete cart from database
    await cartDB.deleteCart(userId);
    
    // Clear cache
    clearCartCache(userId);
    
    res.json({
      message: 'Cart cleared successfully',
      cart: {
        items: [],
        total: 0,
        itemCount: 0
      }
    });
  } catch (error) {
    console.error('Clear cart error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Unable to clear cart at this time'
    });
  }
});

export default router;
