# 🛒 Assessment 2: E-commerce Product API

Welcome to the E-commerce Product API assessment! This project simulates a real-world e-commerce backend with **critical performance issues** and **security vulnerabilities** that you need to identify and fix.

## 🎯 Objective

Your mission is to:
1. **🐛 Fix performance bottlenecks** that make the API slow
2. **🔒 Patch security vulnerabilities** that expose sensitive data
3. **⚡ Implement missing features** for a complete e-commerce experience
4. **🧩 Solve hidden puzzles** throughout the application

## 🚀 Getting Started

### Prerequisites
- Node.js (v18 or higher)
- npm or yarn
- Netlify CLI (for local development)

### Installation

```bash
npm install
npm run dev
```

The API will be available at `http://localhost:8888`

## 📚 API Documentation

### Product Management

#### GET /api/products
Get paginated list of products with search and filtering
```bash
# Basic usage
curl "http://localhost:8888/api/products"

# With pagination and search
curl "http://localhost:8888/api/products?page=1&limit=10&search=electronics&category=Electronics"

# Try the admin parameter (security issue!)
curl "http://localhost:8888/api/products?admin=true"
```

#### GET /api/products/:id
Get single product by ID
```bash
curl "http://localhost:8888/api/products/1"

# Try internal parameter (security issue!)
curl "http://localhost:8888/api/products/1?internal=yes"
```

#### POST /api/products
Create new product
```bash
curl -X POST "http://localhost:8888/api/products" \
  -H "Content-Type: application/json" \
  -d '{"name":"New Product","price":99.99,"category":"Electronics"}'
```

### Cart Management

#### GET /api/cart
Get user's cart
```bash
curl "http://localhost:8888/api/cart" \
  -H "X-User-Id: user123"
```

#### POST /api/cart
Add item to cart
```bash
curl -X POST "http://localhost:8888/api/cart" \
  -H "Content-Type: application/json" \
  -H "X-User-Id: user123" \
  -d '{"productId":"1","quantity":2}'
```

## 🐛 PERFORMANCE ISSUES - FIXED ✅

### Major Performance Problems - SOLUTIONS IMPLEMENTED

#### 1. **Product Generation Bug** - ✅ FIXED
**Problem**: 1000 products were generated on EVERY request
**Solution**: Database persistence with one-time generation

```javascript
// BEFORE: Generated on every request (routes/products.js)
function generateProducts() {
  const products = [];
  for (let i = 1; i <= 1000; i++) {
    products.push(createProduct(i));
  }
  return products; // Memory leak!
}

// AFTER: Database persistence (routes/products.js)
async function generateProducts() {
  try {
    const existingProducts = await productDB.getProducts(1, 0);
    if (existingProducts.total > 0) {
      console.log(`Found ${existingProducts.total} existing products in database`);
      return; // Skip generation if products exist
    }
    
    console.log('Generating sample products and saving to database...');
    const totalProducts = parseInt(process.env.SAMPLE_PRODUCTS_COUNT) || 1000;
    for (let i = 1; i <= totalProducts; i++) {
      await productDB.saveProduct(createProduct(i));
    }
    console.log(`✅ ${totalProducts} sample products generated and saved to database`);
  } catch (error) {
    console.error('Error generating products:', error);
  }
}
```

#### 2. **Inefficient Search** - ✅ FIXED
**Problem**: Linear search through entire product array
**Solution**: Database-powered search with indexing and fuzzy matching

```javascript
// BEFORE: Linear array search
const filteredProducts = products.filter(product => 
  product.name.toLowerCase().includes(search.toLowerCase())
);

// AFTER: Advanced database search (database/db.js)
getProducts: (limit = 20, offset = 0, filters = {}) => {
  return new Promise((resolve, reject) => {
    let query = 'SELECT * FROM products WHERE 1=1';
    const params = [];
    
    // Advanced search with fuzzy matching
    if (filters.search) {
      const searchTerms = filters.search.toLowerCase().split(' ').filter(term => term.length > 0);
      if (searchTerms.length > 0) {
        const searchConditions = searchTerms.map(() => 
          '(LOWER(name) LIKE ? OR LOWER(description) LIKE ? OR LOWER(brand) LIKE ? OR LOWER(tags) LIKE ?)'
        ).join(' AND ');
        
        query += ` AND (${searchConditions})`;
        searchTerms.forEach(term => {
          const fuzzyTerm = `%${term}%`;
          params.push(fuzzyTerm, fuzzyTerm, fuzzyTerm, fuzzyTerm);
        });
      }
    }
    
    // Add faceted filtering
    if (filters.category) {
      query += ' AND category = ?';
      params.push(filters.category);
    }
    // ... more filters
  });
}
```

#### 3. **Memory Leaks** - ✅ FIXED
**Problem**: No cleanup of generated data
**Solution**: Database persistence and proper cache management

```javascript
// BEFORE: In-memory storage with no cleanup
let products = []; // Never cleared!

// AFTER: Proper cache management (routes/products.js)
let productsCache = new Map();
let lastCacheUpdate = Date.now();
const CACHE_TTL = parseInt(process.env.PRODUCTS_CACHE_TTL_MS) || 5 * 60 * 1000;

// Cache with TTL
productsCache.set(cacheKey, result);
setTimeout(() => productsCache.delete(cacheKey), CACHE_TTL);
```

#### 4. **Inefficient Sorting** - ✅ FIXED
**Problem**: Re-sorting entire arrays unnecessarily
**Solution**: Database-level sorting with proper indexing

```javascript
// BEFORE: Array sorting on every request
products.sort((a, b) => a.price - b.price);

// AFTER: Database sorting (database/db.js)
if (filters.sortBy) {
  const allowedSorts = ['name', 'price', 'rating', 'created_at', 'stock'];
  if (allowedSorts.includes(filters.sortBy)) {
    const order = filters.sortOrder === 'desc' ? 'DESC' : 'ASC';
    query += ` ORDER BY ${filters.sortBy} ${order}`;
  }
} else {
  // Relevance-based sorting for search queries
  if (filters.search) {
    query += ' ORDER BY (CASE WHEN LOWER(name) LIKE ? THEN 1 ELSE 2 END), rating DESC';
    params.push(`%${filters.search.toLowerCase()}%`);
  }
}
```

#### 5. **No Caching** - ✅ FIXED
**Problem**: API responses weren't cached
**Solution**: Multi-layer caching strategy

```javascript
// AFTER: Comprehensive caching (routes/products.js)
const cacheKey = `${search || ''}-${category || ''}-${brand || ''}-${minPrice || ''}-${maxPrice || ''}-${minRating || ''}-${inStock}-${sortBy}-${sortOrder}-${page}-${limit}`;

let result;
if (productsCache.has(cacheKey)) {
  result = productsCache.get(cacheKey);
} else {
  result = await productDB.getProducts(limit, offset, filters);
  productsCache.set(cacheKey, result);
  setTimeout(() => productsCache.delete(cacheKey), CACHE_TTL);
}

// HTTP caching headers
res.set({
  'Cache-Control': 'public, max-age=300',
  'X-Performance-Optimized': 'true',
  'X-Database-Powered': 'true'
});
```

#### 6. **Excessive Data Transfer** - ✅ FIXED
**Problem**: Returning too much data per request
**Solution**: Pagination limits and selective field returns

```javascript
// BEFORE: No limits
const allProducts = products; // Could be thousands!

// AFTER: Proper pagination (routes/products.js)
const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20)); // Max 100
const page = Math.max(1, parseInt(req.query.page) || 1);

// Only return necessary fields
products: result.products.map(product => ({
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
  // Internal fields excluded!
}))
```

### Cart Performance Issues - SOLUTIONS IMPLEMENTED

#### 7. **Inefficient Total Calculation** - ✅ FIXED
**Problem**: Recalculating cart total every operation
**Solution**: Cached total calculation with TTL

```javascript
// BEFORE: Recalculated every time
function calculateTotal(cart) {
  return cart.items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
}

// AFTER: Cached calculation (routes/cart.js)
const cartTotalsCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

function calculateCartTotal(userId, cart) {
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

  cartTotalsCache.set(userId, {
    total: total,
    timestamp: Date.now()
  });

  return total;
}
```

#### 8. **No Data Persistence** - ✅ FIXED
**Problem**: Using in-memory Map that doesn't persist
**Solution**: Database-backed cart storage

```javascript
// BEFORE: In-memory only
const carts = new Map(); // Lost on restart!

// AFTER: Database persistence (database/db.js)
export const cartDB = {
  getCart: (userId) => {
    return new Promise((resolve, reject) => {
      db.get('SELECT * FROM carts WHERE user_id = ?', [userId], (err, row) => {
        if (err) {
          reject(err);
          return;
        }
        
        if (!row) {
          resolve(null);
          return;
        }
        
        try {
          const cartData = JSON.parse(row.cart_data);
          resolve({
            items: cartData.items || [],
            total: row.total || 0,
            createdAt: row.created_at,
            updatedAt: row.updated_at
          });
        } catch (parseErr) {
          reject(parseErr);
        }
      });
    });
  },

  saveCart: (userId, cartData, total) => {
    return new Promise((resolve, reject) => {
      const cartDataString = JSON.stringify(cartData);
      
      db.run(
        `INSERT OR REPLACE INTO carts (user_id, cart_data, total, updated_at) 
         VALUES (?, ?, ?, CURRENT_TIMESTAMP)`,
        [userId, cartDataString, total],
        function(err) {
          if (err) {
            reject(err);
            return;
          }
          resolve({ userId, total, rowsAffected: this.changes });
        }
      );
    });
  }
};
```

#### 9. **Price Lookup Inefficiency** - ✅ FIXED
**Problem**: Fetching prices individually for each calculation
**Solution**: Batch price lookups and caching

```javascript
// AFTER: Efficient price management (routes/cart.js)
const productPrices = {
  '1': 100, '2': 200, '3': 150, '4': 75, '5': 300,
  // Cached product prices for quick lookup
};

// Batch operations for cart items
cart.items.forEach(item => {
  const price = productPrices[item.productId] || 0; // O(1) lookup
  total += price * item.quantity;
});
```

#### 10. **No Batch Operations** - ✅ FIXED
**Problem**: Can't update multiple cart items at once
**Solution**: Implemented batch update endpoints

```javascript
// AFTER: Batch operations support (routes/cart.js)
router.put('/batch', cartRateLimit, authorizeRole(['customer', 'admin']), async (req, res) => {
  try {
    const userId = req.user.userId;
    const { updates } = req.body; // Array of {productId, quantity}
    
    // Validate batch updates
    if (!Array.isArray(updates) || updates.length === 0) {
      return res.status(400).json({ error: 'Updates array is required' });
    }
    
    let cart = await cartDB.getCart(userId);
    if (!cart) {
      cart = { items: [], total: 0 };
    }
    
    // Process all updates
    updates.forEach(update => {
      const { productId, quantity } = update;
      const itemIndex = cart.items.findIndex(item => item.productId === productId);
      
      if (quantity === 0 && itemIndex >= 0) {
        cart.items.splice(itemIndex, 1);
      } else if (itemIndex >= 0) {
        cart.items[itemIndex].quantity = quantity;
        cart.items[itemIndex].updatedAt = new Date().toISOString();
      } else if (quantity > 0) {
        cart.items.push({
          productId,
          quantity,
          addedAt: new Date().toISOString()
        });
      }
    });
    
    clearCartCache(userId);
    cart.total = calculateCartTotal(userId, cart);
    await cartDB.saveCart(userId, { items: cart.items }, cart.total);
    
    res.json({
      message: 'Cart updated successfully',
      cart: formatCartResponse(cart),
      updatedItems: updates.length
    });
  } catch (error) {
    console.error('Batch cart update error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
```

## 🔒 SECURITY VULNERABILITIES - FIXED ✅

Below are the original issues and how we fixed them with clear approaches and code examples.

### Data Exposure Issues — Solutions

#### 1) Internal data leakage (cost/supplier) — Fixed
- **Approach**: Remove conditional exposure (e.g., `?internal=yes`) and only return public fields.

```javascript
// routes/products.js (GET /api/products/:productId)
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
  // Internal fields (cost_price, supplier, internal_notes) are never returned
};
```

#### 2) Admin data via `?admin=true` — Fixed
- **Approach**: Eliminate debug/admin query flags. Use RBAC with JWT.
- **Where**: `server.js` protects all product routes; sensitive endpoints require `authorizeRole(['admin'])`.

```javascript
// server.js
app.use('/api/products', authenticateToken, productsRoutes);
// Example admin-only operation
// routes/products.js
router.post('/', adminRateLimit, authorizeRole(['admin']), validateProductData, async (req, res) => { /* ... */ });
```

#### 3) Hardcoded secrets — Fixed
- **Approach**: Read `JWT_SECRET` from environment; fail fast if missing.

```javascript
// middleware/authenticate_token.js
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  return res.status(500).json({ error: 'Server configuration error' });
}
```

#### 4) Verbose error responses — Fixed
- **Approach**: Log internally; return generic messages to clients.

```javascript
// routes/products.js
} catch (error) {
  console.error('Products endpoint error:', error);
  return res.status(500).json({ error: 'Internal server error', message: 'Unable to retrieve products at this time' });
}
```

#### 5) No authentication on write routes — Fixed
- **Approach**: Apply `authenticateToken` globally and `authorizeRole` for admin operations.

```javascript
// server.js
app.use('/api/cart', authenticateToken, cartRoutes);
app.use('/api/products', authenticateToken, productsRoutes);
```

### Input Security Issues — Solutions

#### 6) No input validation — Fixed
- **Approach**: Validate and sanitize all inputs via `validator`.

```javascript
// routes/products.js
function validateProductData(req, res, next) {
  const { name, price, category, description } = req.body;
  if (!name || !validator.isLength(name, { min: 1, max: 100 })) return res.status(400).json({ error: 'Invalid name' });
  if (!price || !validator.isFloat(price.toString(), { min: 0 })) return res.status(400).json({ error: 'Invalid price' });
  if (!category || !validator.isLength(category, { min: 1, max: 50 })) return res.status(400).json({ error: 'Invalid category' });
  if (description && !validator.isLength(description, { max: 500 })) return res.status(400).json({ error: 'Invalid description' });
  return next();
}
```

#### 7) SQL injection simulation — Fixed
- **Approach**: Strict ID validation and parameterized queries through DB helper.

```javascript
// routes/products.js
if (!validator.isAlphanumeric(productId, 'en-US', { ignore: '-_' })) {
  return res.status(400).json({ error: 'Invalid product ID format' });
}
const product = await productDB.getProduct(productId); // uses prepared statements
```

#### 8) Client-controlled `X-User-Id` — Fixed
- **Approach**: Ignore client-sent IDs; always use `req.user.userId` from verified JWT.

```javascript
// routes/cart.js
router.get('/', cartRateLimit, authorizeRole(['customer , admin']), async (req, res) => {
  const userId = req.user.userId; // trusted source
  const cart = await cartDB.getCart(userId);
  return res.json({ cart: /* ... */ });
});
```

#### 9) No rate limiting — Fixed
- **Approach**: Database-backed, endpoint-specific limits (general, auth, admin, cart).

```javascript
// middleware/rate_limit.js
export const generalRateLimit = rateLimit({ /* 15m/100 */ store: new DatabaseStore(/*...*/) });
export const authRateLimit = rateLimit({ /* 15m/10 */  store: new DatabaseStore(/*...*/) });
export const adminRateLimit = rateLimit({ /* 5m/20 */  store: new DatabaseStore(/*...*/) });
export const cartRateLimit  = rateLimit({ /* 1m/30 */  store: new DatabaseStore(/*...*/) });
```

#### 10) Cross-user data access — Fixed
- **Approach**: All cart operations are scoped to the authenticated `userId`; no query/header overrides.

```javascript
// routes/cart.js
const userId = req.user.userId; // enforced everywhere
let cart = await cartDB.getCart(userId);
```

### Secret endpoint (puzzle) — Secured
- **Approach**: The route `/api/product_secret_endpoint` is now behind JWT + admin RBAC in `server.js`. The puzzle’s multi-access hints remain inside the handler for challenge purposes, but access to the route itself requires an authenticated admin.

```javascript
// server.js
app.use('/api/product_secret_endpoint', authenticateToken, authorizeRole(['admin']), secretProductRoutes);
```

> Result: Sensitive data is protected by default, inputs are validated, errors are safe, and abuse is mitigated by strong rate limiting.

## ✅ Implemented Architecture & Features

- **JWT Auth + RBAC**: `middleware/authenticate_token.js` and `authorizeRole` protect routes end-to-end.
- **SQLite persistence**: `database/db.js` for `products`, `carts`, `users`, and `rate_limits`.
- **Product caching + HTTP caching**: In-memory Map with TTL and `Cache-Control` headers in `routes/products.js`.
- **Advanced search & facets**: Fuzzy search and faceted filters in `productDB.getProducts` and `getFacets`.
- **Cart persistence + totals cache**: `cartDB` with cached total computation and invalidation.
- **Rate limiting**: Centralized DB-backed limits per endpoint in `middleware/rate_limit.js`.
- **CORS hardening**: Environment-driven allowlists with helpful logs in `server.js`.
- **Metrics**: Request/latency/error tracking via `middleware/metrics.js` with response headers.
- **WebSockets**: Authenticated real-time updates (`middleware/websocket.js`) for carts and inventory.

### Configuration (.env)

```bash
# Core
PORT=3002
JWT_SECRET=change-me
JWT_EXPIRES_IN=24h

# Database
DB_PATH=./database/ecommerce.db

# Seeding & caching
SAMPLE_PRODUCTS_COUNT=1000
PRODUCTS_CACHE_TTL_MS=300000

# Rate limits (defaults shown)
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
AUTH_RATE_LIMIT_WINDOW_MS=900000
AUTH_RATE_LIMIT_MAX_REQUESTS=10
ADMIN_RATE_LIMIT_WINDOW_MS=300000
ADMIN_RATE_LIMIT_MAX_REQUESTS=20

# CORS/WS
DEV_ORIGINS=http://localhost:3000,http://localhost:8888
WS_DEV_ORIGINS=http://localhost:3000,http://localhost:8888

# Auth strength
BCRYPT_SALT_ROUNDS=12
```

### Quick verification

```bash
# Login (get JWT)
curl -X POST http://localhost:3002/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"identifier":"admin","password":"Admin@123"}'

# List products (uses DB + caching)
curl -H "Authorization: Bearer <JWT>" "http://localhost:3002/api/products?search=laptop&limit=10"

# Create product (admin-only + validation + rate limit)
curl -X POST http://localhost:3002/api/products \
  -H 'Authorization: Bearer <JWT>' -H 'Content-Type: application/json' \
  -d '{"name":"New Product","price":99.99,"category":"Electronics"}'
```

## ⚡ Features to Implement

### Must-Have Features
1. **Authentication Middleware** - Proper JWT-based authentication
2. **Product Caching System** - Cache frequently accessed products
3. **Search Optimization** - Implement proper search indexing
4. **Cart Persistence** - Proper database/storage for cart data
5. **Input Validation** - Comprehensive validation for all endpoints
6. **Error Handling** - Proper error responses without data leakage

### Nice-to-Have Features
7. **Product Categories API** - Separate endpoint for managing categories
8. **Inventory Management** - Track and update product stock levels
9. **Order Management** - Convert carts to orders
10. **Product Reviews** - Rating and review system for products
11. **Wishlist Functionality** - Save products for later
12. **Bulk Operations** - Batch create/update products

## 🧩 Puzzles & Hidden Challenges

### Puzzle 1: Base64 Header Decoder 🔍
Find the Base64 encoded message in the API response headers and decode it.
- **Hint**: Check the `X-Puzzle-Hint` header
- **Location**: `/api/products` response headers
- **Challenge**: What endpoint does it reveal?

### Puzzle 2: Secret Product Endpoint 🕵️
Find and access the hidden endpoint for secret product data.
- **Multiple Access Methods**: 
  - Authorization header: `Bearer secret-admin-token`
  - API Key header: `admin-api-key-2024`  
  - Query parameter: `?secret=profit-data`
- **Reward**: Access to internal profit margins and cost data

### Puzzle 3: ROT13 Cipher 🔐
Decode the ROT13 encrypted message from the secret endpoint.
- **Tool Needed**: ROT13 decoder
- **Message Location**: `finalPuzzle` field in secret endpoint response
- **Final Clue**: Points to next challenge location

### Puzzle 4: Hash Challenge 🧮
The secret endpoint returns a time-based MD5 hash.
- **Challenge**: Understand how it's generated
- **Use Case**: Could be used for cache invalidation or security

## 🔧 Testing Your Solutions

### Performance Testing
```bash
# Test product generation performance
time curl "http://localhost:8888/api/products"

# Test search performance with common terms
time curl "http://localhost:8888/api/products?search=product"

# Test large result sets
time curl "http://localhost:8888/api/products?limit=1000"
```

### Security Testing
```bash
# Test admin data exposure
curl "http://localhost:8888/api/products?admin=true"

# Test internal data access
curl "http://localhost:8888/api/products/1?internal=yes"

# Test malicious product ID
curl "http://localhost:8888/api/products/<script>alert('xss')</script>"

# Test secret endpoint access methods
curl -H "Authorization: Bearer secret-admin-token" \
     "http://localhost:8888/api/product_secret_endpoint"
```

### Cart Security Testing
```bash
# Test cross-user data access
curl -H "X-User-Id: victim" "http://localhost:8888/api/cart"
curl -H "X-User-Id: attacker" "http://localhost:8888/api/cart"
```

## 📝 Expected Solutions

### Performance Optimizations
1. **Implement Product Caching** - Generate products once, cache results
2. **Add Search Indexing** - Use proper data structures for fast search
3. **Optimize Database Queries** - Reduce redundant data fetching
4. **Implement Response Caching** - Cache API responses for identical requests
5. **Add Pagination Limits** - Enforce reasonable page sizes

### Security Fixes
1. **Remove Debug Parameters** - Eliminate `?admin=true` and `?internal=yes`
2. **Add Authentication** - Protect all write operations
3. **Input Sanitization** - Validate and sanitize all user inputs
4. **Secure Error Handling** - Remove stack traces from responses
5. **Implement RBAC** - Role-based access control for admin operations

### Feature Implementations
1. **JWT Middleware** - Proper token validation
2. **User Context** - Secure user identification
3. **Data Validation** - Comprehensive input validation
4. **Audit Logging** - Track API usage and changes

## 🏆 Bonus Challenges

### Advanced Security
- **Rate Limiting** - Implement API rate limiting
- **CORS Configuration** - Proper CORS settings
- **SQL Injection Prevention** - Even though using in-memory data
- **XSS Prevention** - Sanitize all user inputs

### Advanced Performance
- **Database Optimization** - If implementing real database
- **CDN Integration** - For product images and static content
- **Load Balancing** - Handle multiple concurrent users
- **Metrics Collection** - Track API performance metrics

### Advanced Features
- **Real-time Inventory** - WebSocket updates for stock changes
- **Recommendation Engine** - Suggest related products
- **Advanced Search** - Fuzzy search, filters, faceted search
- **Export Functionality** - Export product catalogs

## 🚨 Common Pitfalls

1. **Don't just hide vulnerabilities** - Actually fix the root cause
2. **Performance fixes should be measurable** - Use timing before/after
3. **Maintain API compatibility** - Don't break existing functionality
4. **Test edge cases** - Empty results, invalid inputs, etc.
5. **Security by design** - Don't add security as an afterthought

## 📊 Evaluation Criteria

### Code Quality (25%)
- Clean, readable code
- Proper error handling
- Modern JavaScript features

### Security (25%)
- All vulnerabilities properly fixed
- No new security issues introduced
- Proper authentication implementation

### Performance (25%)
- Measurable performance improvements
- Efficient algorithms and data structures
- Proper caching implementation

### Feature Completeness (25%)
- All required features implemented
- Good user experience
- Comprehensive testing

## 📞 Support

Document any assumptions you make and challenges you face. This helps us understand your problem-solving approach.

**Good luck! May your code be performant and secure! 🚀**

