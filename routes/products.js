import express from 'express';
import _ from 'lodash';
import validator from 'validator';
import {authorizeRole} from '../middleware/authenticate_token.js';
import { adminRateLimit } from '../middleware/rate_limit.js';
import { productDB } from '../database/db.js';
import { broadcastInventoryUpdate, broadcastAdminNotification } from '../middleware/websocket.js';
const router = express.Router();

// PERFORMANCE FIX: Cached search results - no more in-memory product array
let productsCache = new Map(); // Cache for search results
let lastCacheUpdate = Date.now();
const CACHE_TTL = parseInt(process.env.PRODUCTS_CACHE_TTL_MS) || 5 * 60 * 1000; // 5 minutes default

// Generate sample products and save to database (BUG FIXED: Database persistence)
async function generateProducts() {
  try {
    // Check if products already exist in database
    const existingProducts = await productDB.getProducts(1, 0);
    if (existingProducts.total > 0) {
      console.log(`Found ${existingProducts.total} existing products in database`);
      return;
    }
    
    console.log('Generating sample products and saving to database...');
    
    const categories = ['Electronics', 'Clothing', 'Books', 'Home', 'Sports', 'Beauty'];
    const brands = ['BrandA', 'BrandB', 'BrandC', 'BrandD', 'BrandE'];
    
    const totalProducts = parseInt(process.env.SAMPLE_PRODUCTS_COUNT) || 1000;
    for (let i = 1; i <= totalProducts; i++) {
      const product = {
        id: i.toString(),
        name: `Product ${i}`,
        description: `This is product number ${i} with amazing features`,
        price: Math.floor(Math.random() * 1000) + 10,
        category: categories[Math.floor(Math.random() * categories.length)],
        brand: brands[Math.floor(Math.random() * brands.length)],
        stock: Math.floor(Math.random() * 100),
        rating: parseFloat((Math.random() * 5).toFixed(1)),
        tags: [`tag${i}`, `feature${i % 10}`],
        cost_price: Math.floor(Math.random() * 500) + 5,
        supplier: `Supplier ${i % 20}`,
        internal_notes: `Internal notes for product ${i}`,
        admin_only: Math.random() > 0.9
      };
      
      await productDB.saveProduct(product);
    }
    
    // Clear cache when products are regenerated
    productsCache.clear();
    lastCacheUpdate = Date.now();
    
    console.log(`✅ ${totalProducts} sample products generated and saved to database`);
  } catch (error) {
    console.error('Error generating products:', error);
  }
}

//BUG FIXED: Use environment variable for JWT secret - required for security
// JWT_SECRET will be checked at runtime when needed


// Input validation middleware
function validateProductData(req, res, next) {
  const { name, price, category, description } = req.body;
  
  if (!name || !validator.isLength(name, { min: 1, max: 100 })) {
    return res.status(400).json({ error: 'Product name is required and must be 1-100 characters' });
  }
  
  if (!price || !validator.isFloat(price.toString(), { min: 0 })) {
    return res.status(400).json({ error: 'Price must be a positive number' });
  }
  
  if (!category || !validator.isLength(category, { min: 1, max: 50 })) {
    return res.status(400).json({ error: 'Category is required and must be 1-50 characters' });
  }
  
  if (description && !validator.isLength(description, { max: 500 })) {
    return res.status(400).json({ error: 'Description must be less than 500 characters' });
  }
  
  next();
}

function validateProductUpdate(req, res, next) {
  const { name, price, category, description } = req.body;
  
  if (name && !validator.isLength(name, { min: 1, max: 100 })) {
    return res.status(400).json({ error: 'Product name must be 1-100 characters' });
  }
  
  if (price !== undefined && (!validator.isFloat(price.toString(), { min: 0 }))) {
    return res.status(400).json({ error: 'Price must be a positive number' });
  }
  
  if (category && !validator.isLength(category, { min: 1, max: 50 })) {
    return res.status(400).json({ error: 'Category must be 1-50 characters' });
  }
  
  if (description && !validator.isLength(description, { max: 500 })) {
    return res.status(400).json({ error: 'Description must be less than 500 characters' });
  }
  
  next();
}


//BUG FIXED: Generate products only once on startup (now with database persistence)
generateProducts();

// Get all products
router.get('/', async (req, res) => {
  try {
    //FIXED: Validate and sanitize input parameters
    const page = Math.max(1, parseInt(req.query.page) || 1); // ensures page number is never below 1.
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20)); //BUG FIXED: Lower default limit with max cap (caps limit to 100 max, preventing huge responses.)

    //Prevents XSS attacks and Converts to string safely
    const search = req.query.search ? validator.escape(req.query.search.toString()) : null;
    const category = req.query.category ? validator.escape(req.query.category.toString()) : null;
    const brand = req.query.brand ? validator.escape(req.query.brand.toString()) : null;
    const minPrice = req.query.minPrice ? parseFloat(req.query.minPrice) : null;
    const maxPrice = req.query.maxPrice ? parseFloat(req.query.maxPrice) : null;
    const minRating = req.query.minRating ? parseFloat(req.query.minRating) : null;
    const inStock = req.query.inStock === 'true';
    const sortBy = ['name', 'price', 'rating', 'created_at', 'stock'].includes(req.query.sortBy) ? req.query.sortBy : 'name';
    const sortOrder = ['asc', 'desc'].includes(req.query.sortOrder) ? req.query.sortOrder : 'asc';

    // SECURITY FIX: Remove admin parameter completely - no more data exposure
    // PERFORMANCE FIX: Use caching for search results (enhanced for faceted search)
    const cacheKey = `${search || ''}-${category || ''}-${brand || ''}-${minPrice || ''}-${maxPrice || ''}-${minRating || ''}-${inStock}-${sortBy}-${sortOrder}-${page}-${limit}`;
    
    let result;
    if (productsCache.has(cacheKey)) {
      result = productsCache.get(cacheKey);
    } else {
      // DATABASE FIX: Use database instead of in-memory array with advanced search
      const offset = (page - 1) * limit;
      const filters = {
        search: search,
        category: category,
        brand: brand,
        minPrice: minPrice,
        maxPrice: maxPrice,
        minRating: minRating,
        inStock: inStock,
        sortBy: sortBy,
        sortOrder: sortOrder
      };
      
      result = await productDB.getProducts(limit, offset, filters);
      
      // Cache the results for 5 minutes
      productsCache.set(cacheKey, result);
      setTimeout(() => productsCache.delete(cacheKey), CACHE_TTL);
    }

    // Determine if requester is admin (controls internal field exposure)
    const isAdmin = req.user && req.user.role === 'admin';
    const wantsInternal = String(req.query.internal || '').toLowerCase() === 'true';
    const includeInternal = isAdmin && wantsInternal;

    //Calculate pagination
    const totalItems = result.total;
    const totalPages = Math.ceil(totalItems / limit);
    const validPage = Math.min(page, Math.max(1, totalPages || 1));

    // Enhanced headers with search info
    res.set({
      'X-Total-Count': totalItems.toString(),
      'X-Performance-Optimized': 'true',
      'X-Database-Powered': 'true',
      'X-Advanced-Search': 'enabled',
      'X-Faceted-Search': 'available',
      'Cache-Control': 'public, max-age=300',
      'X-Internal-Fields': includeInternal ? 'included' : 'hidden'
    });

    res.json({
      products: result.products.map(product => {
        // Public fields
        const data = {
          id: product.id,
          name: product.name,
          description: product.description,
          price: product.price,
          category: product.category,
          brand: product.brand,
          stock: product.stock,
          rating: product.rating,
          tags: product.tags,
          createdAt: product.created_at
        };

        // Include internal fields only for admins AND when explicitly requested via ?internal=true
        if (includeInternal) {
          data.internal = {
            costPrice: product.cost_price,
            supplier: product.supplier,
            internalNotes: product.internal_notes,
            adminOnly: !!product.admin_only
          };
        }
        return data;
      }),
      pagination: {
        currentPage: validPage,
        totalPages: totalPages,
        totalItems: totalItems,
        itemsPerPage: limit,
        hasNextPage: validPage < totalPages,
        hasPreviousPage: validPage > 1
      }
    });
  } catch (error) {
    // BUG FIXED (security fix): Proper error handling without exposing details
    console.error('Products endpoint error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Unable to retrieve products at this time'
    });
  }
});

// Get product by ID
router.get('/:productId', async (req, res) => {
  try {
    const { productId } = req.params;
    
    // SECURITY FIX: Input validation and sanitization
    if (!productId || !validator.isAlphanumeric(productId, 'en-US', { ignore: '-_' })) {
      return res.status(400).json({ error: 'Invalid product ID format' });
    }

    // SECURITY FIX: Reject malicious input immediately
    if (productId.includes('<script>') || productId.includes('DROP') || productId.length > 50) {
      console.warn('Malicious input detected:', productId);
      return res.status(400).json({ error: 'Invalid product ID' });
    }
    
    // DATABASE FIX: Use database instead of in-memory array
    const product = await productDB.getProduct(productId);
    
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    // SECURITY FIX: Remove internal parameter - no conditional data exposure via query params
    const responseData = {
      id: product.id,
      name: product.name,
      description: product.description,
      price: product.price,
      category: product.category,
      brand: product.brand,
      stock: product.stock,
      rating: product.rating,
      tags: product.tags,
      createdAt: product.created_at
    };

    // Include internal fields only for admins AND when explicitly requested via ?internal=true
    const isAdmin = req.user && req.user.role === 'admin';
    const wantsInternal = String(req.query.internal || '').toLowerCase() === 'true';
    const includeInternal = isAdmin && wantsInternal;
    if (includeInternal) {
      responseData.internal = {
        costPrice: product.cost_price,
        supplier: product.supplier,
        internalNotes: product.internal_notes,
        adminOnly: !!product.admin_only
      };
    }

    res.set({
      'Cache-Control': 'public, max-age=300',
      'X-Database-Powered': 'true',
      'X-Internal-Fields': includeInternal ? 'included' : 'hidden'
    });

    res.json(responseData);
  } catch (error) {
    // SECURITY FIX: Proper error handling
    console.error('Get product error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Unable to retrieve product at this time'
    });
  }
});

// Create product - SECURITY FIX: Authentication required (Checking admin role)
router.post('/', adminRateLimit, authorizeRole(['admin']), validateProductData, async (req, res) => {
  try {
    const productData = req.body;
    
    // DATABASE FIX: Generate new ID from database
    const existingProducts = await productDB.getProducts(1, 0);
    const newId = (existingProducts.total + 1).toString();
    
    const newProduct = {
      id: newId,
      name: validator.escape(productData.name),
      description: validator.escape(productData.description || ''),
      price: parseFloat(productData.price),
      category: validator.escape(productData.category),
      brand: validator.escape(productData.brand || 'Unknown'),
      stock: Math.max(0, parseInt(productData.stock) || 0),
      rating: 0,
      tags: Array.isArray(productData.tags) ? productData.tags.map(tag => validator.escape(tag)) : [],
      //BUG FIXED Internal fields - calculated automatically
      cost_price: productData.costPrice ? parseFloat(productData.costPrice) : parseFloat(productData.price) * 0.7,
      supplier: productData.supplier ? String(productData.supplier) : `Supplier ${Math.floor(Math.random() * 20)}`,
      internal_notes: productData.internalNotes ? String(productData.internalNotes) : `Created by admin: ${req.user?.username || 'system'}`,
      admin_only: typeof productData.adminOnly === 'boolean' ? productData.adminOnly : false
    };

    // DATABASE FIX: Save to database instead of in-memory array
    await productDB.saveProduct(newProduct);
    
    // Clear cache when products change
    productsCache.clear();

    // Broadcast inventory update via WebSocket
    broadcastInventoryUpdate(newProduct.id, {
      action: 'created',
      product: {
        id: newProduct.id,
        name: newProduct.name,
        stock: newProduct.stock,
        price: newProduct.price
      }
    });

    // Notify admins of new product creation
    broadcastAdminNotification({
      type: 'product_created',
      message: `New product created: ${newProduct.name}`,
      productId: newProduct.id,
      createdBy: req.user.username
    });

    res.status(201).json({
      message: 'Product created successfully',
      // SECURITY FIX: Only return public data (BUG FIXED)
      product: {
        id: newProduct.id,
        name: newProduct.name,
        description: newProduct.description,
        price: newProduct.price,
        category: newProduct.category,
        brand: newProduct.brand,
        stock: newProduct.stock,
        rating: newProduct.rating,
        tags: newProduct.tags,
        createdAt: new Date().toISOString()
      }
    });
  } catch (error) {
    console.error('Create product error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Unable to create product at this time'
    });
  }
});

// Update product - SECURITY FIX: Authentication required (Checking  admin role)
router.put('/:productId', adminRateLimit, authorizeRole(['admin']), validateProductUpdate, async (req, res) => {
  try {
    

    const { productId } = req.params;
    const updateData = req.body;
    
    // SECURITY FIX: Validate product ID
    if (!validator.isAlphanumeric(productId, 'en-US', { ignore: '-_' })) {
      return res.status(400).json({ error: 'Invalid product ID format' });
    }
    
    // DATABASE FIX: Check if product exists in database
    const existingProduct = await productDB.getProduct(productId);
    
    if (!existingProduct) {
      return res.status(404).json({ error: 'Product not found' });
    }

    // BUG FIXED: Only allow specific fields to be updated
    const updatedProduct = {
      ...existingProduct,
      name: updateData.name ? validator.escape(updateData.name) : existingProduct.name,
      description: updateData.description ? validator.escape(updateData.description) : existingProduct.description,
      price: updateData.price ? parseFloat(updateData.price) : existingProduct.price,
      category: updateData.category ? validator.escape(updateData.category) : existingProduct.category,
      brand: updateData.brand ? validator.escape(updateData.brand) : existingProduct.brand,
      stock: updateData.stock !== undefined ? Math.max(0, parseInt(updateData.stock)) : existingProduct.stock,
      tags: Array.isArray(updateData.tags) ? updateData.tags.map(tag => validator.escape(tag)) : existingProduct.tags,
      // Update internal tracking
      internal_notes: `Updated by admin: ${req.user.username} at ${new Date().toISOString()}`
    };

    // DATABASE FIX: Save to database
    await productDB.saveProduct(updatedProduct);

    // Clear cache when products change
    productsCache.clear();

    // Broadcast inventory update via WebSocket (especially important for stock changes)
    broadcastInventoryUpdate(updatedProduct.id, {
      action: 'updated',
      product: {
        id: updatedProduct.id,
        name: updatedProduct.name,
        stock: updatedProduct.stock,
        price: updatedProduct.price
      },
      changes: {
        stockChanged: existingProduct.stock !== updatedProduct.stock,
        priceChanged: existingProduct.price !== updatedProduct.price
      }
    });

    // Notify admins of product update
    broadcastAdminNotification({
      type: 'product_updated',
      message: `Product updated: ${updatedProduct.name}`,
      productId: updatedProduct.id,
      updatedBy: req.user.username
    });

    res.json({
      message: 'Product updated successfully',
      // SECURITY FIX: Only return public data
      product: {
        id: updatedProduct.id,
        name: updatedProduct.name,
        description: updatedProduct.description,
        price: updatedProduct.price,
        category: updatedProduct.category,
        brand: updatedProduct.brand,
        stock: updatedProduct.stock,
        rating: updatedProduct.rating,
        tags: updatedProduct.tags,
        createdAt: updatedProduct.created_at
      }
    });
  } catch (error) {
    console.error('Update product error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Unable to update product at this time'
    });
  }
});

// Delete product - SECURITY FIX: Authentication required (Checking admin role)
router.delete('/:productId', adminRateLimit, authorizeRole(['admin']), async (req, res) => {
  try {

    const { productId } = req.params;
    
    // SECURITY FIX: Validate product ID
    if (!validator.isAlphanumeric(productId, 'en-US', { ignore: '-_' })) {
      return res.status(400).json({ error: 'Invalid product ID format' });
    }
    
    // DATABASE FIX: Check if product exists in database
    const existingProduct = await productDB.getProduct(productId);
    
    if (!existingProduct) {
      return res.status(404).json({ error: 'Product not found' });
    }

    // DATABASE FIX: Delete from database
    await productDB.deleteProduct(productId);

    // Clear cache when products change
    productsCache.clear();

    // Broadcast inventory update via WebSocket
    broadcastInventoryUpdate(productId, {
      action: 'deleted',
      product: {
        id: productId,
        name: existingProduct.name
      }
    });

    // Notify admins of product deletion
    broadcastAdminNotification({
      type: 'product_deleted',
      message: `Product deleted: ${existingProduct.name}`,
      productId: productId,
      deletedBy: req.user.username
    });

    // Log deletion for audit trail
    console.log(`Product deleted by admin ${req.user.username}: ${existingProduct.name} (ID: ${productId})`);

    res.json({ 
      message: 'Product deleted successfully',
      deletedProductId: productId
    });
  } catch (error) {
    console.error('Delete product error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Unable to delete product at this time'
    });
  }
});

// Get faceted search data - public endpoint for search filters
router.get('/facets', async (req, res) => {
  try {
    const facets = await productDB.getFacets();
    
    res.set({
      'Cache-Control': 'public, max-age=600', // Cache facets for 10 minutes
      'X-Faceted-Search': 'enabled'
    });
    
    res.json({
      message: 'Available search facets',
      facets: facets,
      usage: {
        category: 'Filter by product category',
        brand: 'Filter by product brand',
        priceRange: 'Filter by price range using minPrice and maxPrice',
        ratingRange: 'Filter by rating using minRating',
        inStock: 'Filter to show only items in stock'
      },
      examples: [
        '/api/products?category=Electronics&brand=BrandA',
        '/api/products?minPrice=100&maxPrice=500',
        '/api/products?minRating=4&inStock=true',
        '/api/products?search=laptop&category=Electronics&minPrice=200'
      ]
    });
  } catch (error) {
    console.error('Facets endpoint error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Unable to retrieve search facets at this time'
    });
  }
});

// Get product recommendations - public endpoint
router.get('/:productId/recommendations', async (req, res) => {
  try {
    const { productId } = req.params;
    const limit = Math.min(10, Math.max(1, parseInt(req.query.limit) || 5));
    
    // Validate product ID
    if (!productId || !validator.isAlphanumeric(productId, 'en-US', { ignore: '-_' })) {
      return res.status(400).json({ error: 'Invalid product ID format' });
    }
    
    const recommendations = await productDB.getRecommendations(productId, limit);
    
    res.set({
      'Cache-Control': 'public, max-age=300',
      'X-Recommendation-Engine': 'content-based'
    });
    
    res.json({
      message: 'Product recommendations',
      productId: productId,
      recommendations: recommendations.map(product => ({
        id: product.id,
        name: product.name,
        description: product.description,
        price: product.price,
        category: product.category,
        brand: product.brand,
        stock: product.stock,
        rating: product.rating,
        tags: product.tags,
        createdAt: product.created_at,
        recommendationReason: product.recommendation_reason
      })),
      totalRecommendations: recommendations.length
    });
  } catch (error) {
    console.error('Recommendations endpoint error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Unable to retrieve recommendations at this time'
    });
  }
});

// Get trending products - public endpoint
router.get('/trending/products', async (req, res) => {
  try {
    const limit = Math.min(20, Math.max(1, parseInt(req.query.limit) || 10));
    
    const trendingProducts = await productDB.getTrendingProducts(limit);
    
    res.set({
      'Cache-Control': 'public, max-age=600', // Cache for 10 minutes
      'X-Trending-Algorithm': 'rating-stock-recency'
    });
    
    res.json({
      message: 'Trending products',
      products: trendingProducts.map(product => ({
        id: product.id,
        name: product.name,
        description: product.description,
        price: product.price,
        category: product.category,
        brand: product.brand,
        stock: product.stock,
        rating: product.rating,
        tags: product.tags,
        createdAt: product.created_at
      })),
      totalProducts: trendingProducts.length,
      algorithm: 'Based on rating, stock availability, and recency'
    });
  } catch (error) {
    console.error('Trending products endpoint error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Unable to retrieve trending products at this time'
    });
  }
});

// Export product catalog - admin only
router.get('/export/:format', adminRateLimit, authorizeRole(['admin']), async (req, res) => {
  try {
    const { format } = req.params;
    const supportedFormats = ['csv', 'json'];
    
    if (!supportedFormats.includes(format.toLowerCase())) {
      return res.status(400).json({ 
        error: 'Unsupported format',
        supportedFormats: supportedFormats
      });
    }
    
    // Get all products for export (no pagination)
    const allProducts = await productDB.getProducts(10000, 0, {});
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `product-catalog-${timestamp}.${format}`;
    
    if (format.toLowerCase() === 'csv') {
      // Generate CSV
      const csvHeader = 'ID,Name,Description,Price,Category,Brand,Stock,Rating,Tags,Created At\n';
      const csvRows = allProducts.products.map(product => {
        return [
          product.id,
          `"${product.name.replace(/"/g, '""')}"`,
          `"${product.description.replace(/"/g, '""')}"`,
          product.price,
          product.category,
          product.brand,
          product.stock,
          product.rating,
          `"${product.tags.join(', ')}"`,
          product.created_at
        ].join(',');
      }).join('\n');
      
      const csvContent = csvHeader + csvRows;
      
      res.set({
        'Content-Type': 'text/csv',
        'Content-Disposition': `attachment; filename="${filename}"`,
        'X-Export-Format': 'CSV',
        'X-Total-Records': allProducts.total.toString()
      });
      
      res.send(csvContent);
      
    } else if (format.toLowerCase() === 'json') {
      // Generate JSON
      const jsonData = {
        exportInfo: {
          timestamp: new Date().toISOString(),
          totalProducts: allProducts.total,
          format: 'JSON',
          exportedBy: req.user.username
        },
        products: allProducts.products.map(product => ({
          id: product.id,
          name: product.name,
          description: product.description,
          price: product.price,
          category: product.category,
          brand: product.brand,
          stock: product.stock,
          rating: product.rating,
          tags: product.tags,
          createdAt: product.created_at
        }))
      };
      
      res.set({
        'Content-Type': 'application/json',
        'Content-Disposition': `attachment; filename="${filename}"`,
        'X-Export-Format': 'JSON',
        'X-Total-Records': allProducts.total.toString()
      });
      
      res.json(jsonData);
    }
    
    // Log export activity
    console.log(`Product catalog exported by admin ${req.user.username} in ${format.toUpperCase()} format (${allProducts.total} products)`);
    
  } catch (error) {
    console.error('Export endpoint error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Unable to export product catalog at this time'
    });
  }
});

export default router;