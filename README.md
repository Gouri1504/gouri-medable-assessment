# 🛒 Assessment 2: E-commerce Product API

Welcome to the E-commerce Product API assessment! This project simulates a real-world e-commerce backend with **critical performance issues** and **security vulnerabilities** that you need to identify and fix.

## Admin Panel

The project includes an **Admin Panel** for managing and monitoring system activities.

### Access

🌐 **URL:** [Admin Panel](https://gouri-medable-assessment.onrender.com/admin-panel.html)

### Credentials

Use the following credentials to log in:

* **Email:** `admin@example.com`
* **Password:** `Admin@123`

### Features

* Secure admin authentication
* Dashboard for stock management ( websocket implemented)



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

The API will be available at `http://localhost:3002`

# 🧩 Puzzles & Hidden Challenges

This project includes a series of hidden puzzles designed to be discovered and solved while exploring the system. Each puzzle reveals clues that lead to the next challenge.

---

## 🔍 Puzzle 1: Base64 Header Decoder

* **Location**: Check `/api/products` response headers
* **Hint Header**: `X-Puzzle-Hint`
* **Task**: Decode the Base64 string

  ```bash
  cHJvZHVjdF9zZWNyZXRfZW5kcG9pbnQ=
  ```
* **Decoded Result**:

  ```
  product_secret_endpoint
  ```
* **Revealed Endpoint**: `/api/product_secret_endpoint`

---

## 🕵️ Puzzle 2: Secret Product Endpoint

The hidden endpoint contains **secret product data**.

* **Access Methods** (all supported):

  * **Authorization Header**:

    ```http
    Authorization: Bearer secret-admin-token
    ```
  * **API Key Header**:

    ```http
    x-api-key: admin-api-key-2024
    ```
  * **Query Parameter**:

    ```
    ?secret=profit-data
    ```

* **Reward**: Access to **internal profit margins** and **cost data**.

✅ Successfully accessible through all three methods.

---

## 🔐 Puzzle 3: ROT13 Cipher

The secret endpoint response includes a `finalPuzzle` field encrypted with ROT13.

* **Message**:

  ```js
  const FINAL_PUZZLE = 'Pbatenghyngvbaf! Lbh sbhaq gur frperg cebqhpg qngn. Svany pyhrf: PURPX_NQZVA_CNARY_2024';
  ```

* **Decoded Result**:

  ```
  Congratulations! You found the secret product data.  
  Final clues: CHECK_ADMIN_PANEL_2024
  ```

---

## 🧮 Puzzle 4: Hash Challenge

The secret endpoint also returns a **time-based MD5 hash**.

* **Hash Generation Logic**:

  ```js
  const timeHash = crypto
    .createHash('md5')
    .update(new Date().toISOString().slice(0, 10)) // current date (YYYY-MM-DD)
    .digest('hex')
    .slice(0, 8);
  ```

✨ **Final Clue**: The puzzles ultimately point back to the Admin Panel → `CHECK_ADMIN_PANEL_2024`.



## 📚 API Documentation

This documents all current endpoints, required auth, and roles.

### Auth
- POST `/api/auth/register` — Register (public)
- POST `/api/auth/login` — Login, returns JWT (public)
- GET `/api/auth/users` — List demo users (public)
- GET `/api/auth/verify` — Verify token (auth)
- GET `/api/auth/profile` — Get profile (auth)
- PUT `/api/auth/profile` — Update profile (auth)
- GET `/api/auth/admin/users` — List users (admin)
- GET `/api/auth/admin-data` — Example admin-only data (admin)

Examples:
```bash
curl -X POST http://localhost:3002/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"identifier":"admin","password":"Admin@123"}'

curl -H "Authorization: Bearer <JWT>" http://localhost:3002/api/auth/verify
```

### Product Management (auth required)

- GET `/api/products` — List with search/filters/sort/pagination (any role)
  - Query: `page,limit,search,category,brand,minPrice,maxPrice,minRating,inStock,sortBy,sortOrder`
  - Admin-only opt-in: `internal=true` to include internal fields
- GET `/api/products/:productId` — Product detail (any role)
  - Admin-only opt-in: `internal=true` to include internal fields
- GET `/api/products/facets` — Facet metadata (any role)
- GET `/api/products/:productId/recommendations` — Recommendations (any role)
- GET `/api/products/trending/products` — Trending (any role)
- POST `/api/products` — Create (admin)
- PUT `/api/products/:productId` — Update (admin)
- DELETE `/api/products/:productId` — Delete (admin)
- GET `/api/products/export/:format` — Export `csv|json` (admin)

Internal field behavior:
- Public fields (all roles): `id,name,description,price,category,brand,stock,rating,tags,createdAt`
- Internal fields (admins only, and only when `?internal=true`): `{ internal: { costPrice, supplier, internalNotes, adminOnly } }`

Examples:
```bash
# List products (customer)
curl -H "Authorization: Bearer <JWT_CUSTOMER>" \
  "http://localhost:3002/api/products?search=laptop&limit=10"

# List with internals (admin, explicit)
curl -H "Authorization: Bearer <JWT_ADMIN>" \
  "http://localhost:3002/api/products?limit=5&internal=true"

# Detail with internals (admin, explicit)
curl -H "Authorization: Bearer <JWT_ADMIN>" \
  "http://localhost:3002/api/products/1?internal=true"

# Create (admin)
curl -X POST http://localhost:3002/api/products \
  -H 'Authorization: Bearer <JWT_ADMIN>' -H 'Content-Type: application/json' \
  -d '{"name":"New Product","price":99.99,"category":"Electronics"}'
```

### Cart Management (auth; roles: customer, admin)

- GET `/api/cart` — Get authenticated user's cart
- POST `/api/cart` — Add `{ productId, quantity }`
- PUT `/api/cart` — Update `{ productId, quantity }` (0 removes)
- DELETE `/api/cart` — Remove item (query `productId`)
- DELETE `/api/cart/clear` — Clear whole cart

Examples:
```bash
curl -H "Authorization: Bearer <JWT>" http://localhost:3002/api/cart

curl -X POST http://localhost:3002/api/cart \
  -H 'Authorization: Bearer <JWT>' -H 'Content-Type: application/json' \
  -d '{"productId":"1","quantity":2}'

curl -X PUT http://localhost:3002/api/cart \
  -H 'Authorization: Bearer <JWT>' -H 'Content-Type: application/json' \
  -d '{"productId":"1","quantity":3}'

curl -X DELETE "http://localhost:3002/api/cart?productId=1" \
  -H 'Authorization: Bearer <JWT>'

curl -X DELETE http://localhost:3002/api/cart/clear \
  -H 'Authorization: Bearer <JWT>'
```

### Metrics (auth; admin noted)

- GET `/api/metrics/summary` — Summary (admin)
- GET `/api/metrics/endpoint/{METHOD%20/path}` — Endpoint metrics (admin)
- GET `/api/metrics/health` — Health + basic metrics (auth)
- POST `/api/metrics/reset` — Reset metrics (admin)
- GET `/api/metrics/stream` — SSE stream (admin)

Examples:
```bash
curl -H "Authorization: Bearer <JWT_ADMIN>" http://localhost:3002/api/metrics/summary
curl -H "Authorization: Bearer <JWT_ADMIN>" \
  "http://localhost:3002/api/metrics/endpoint/GET%20/api/products"
```

### Secret Endpoint (admin only)

- GET `/api/product_secret_endpoint` — Mock profit data (puzzle)
  - Still requires admin JWT; accepts additional puzzle access methods (`Authorization: Bearer secret-admin-token`, `X-API-Key: admin-api-key-2024`, or `?secret=profit-data`).

Example:
```bash
curl -H "Authorization: Bearer <JWT_ADMIN>" \
     -H "X-API-Key: admin-api-key-2024" \
     http://localhost:3002/api/product_secret_endpoint
```

### Server Health (public)

- GET `/health` — Service liveness probe

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
DEV_ORIGINS=http://localhost:3000,http://localhost:3002
WS_DEV_ORIGINS=http://localhost:3000,http://localhost:3002

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

## 🛠️ HOW WE SOLVED IT - DETAILED IMPLEMENTATION GUIDE

This section provides a comprehensive walkthrough of our solution approach, showing exactly how we transformed a vulnerable, slow API into a production-ready e-commerce backend.

### 🏗️ Our Solution Architecture

We implemented a **layered security and performance architecture** with the following components:

```
┌─────────────────────────────────────────────────────────────┐
│                    CLIENT LAYER                             │
├─────────────────────────────────────────────────────────────┤
│  Rate Limiting → CORS → Authentication → Authorization      │
├─────────────────────────────────────────────────────────────┤
│              BUSINESS LOGIC LAYER                           │
├─────────────────────────────────────────────────────────────┤
│    Caching → Input Validation → Database Operations        │
├─────────────────────────────────────────────────────────────┤
│                  PERSISTENCE LAYER                          │
│              SQLite + WebSocket + Metrics                   │
└─────────────────────────────────────────────────────────────┘
```

### 🔐 Step 1: Security Implementation

#### 1.1 JWT-Based Authentication System

**Problem**: No authentication meant anyone could access admin features.
**Our Solution**: Comprehensive JWT authentication with role-based access control.

```javascript
// File: middleware/authenticate_token.js
const authenticateToken = (req, res, next) => {
  try {
    const JWT_SECRET = process.env.JWT_SECRET;
    
    // Fail fast if JWT_SECRET is missing
    if (!JWT_SECRET) {
      console.error('FATAL ERROR: JWT_SECRET environment variable is not set');
      return res.status(500).json({ error: 'Server configuration error' });
    }

    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Access token required' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) return res.status(403).json({ error: 'Invalid or expired token' });
      req.user = user; // Attach verified user to request
      next();
    });
  } catch (error) {
    console.error('Token middleware error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};
```

**Key Benefits:**
- Environment-based secret management (no hardcoded secrets)
- Automatic token validation on every protected route
- Graceful error handling without exposing stack traces

#### 1.2 Role-Based Authorization

**Problem**: Even authenticated users shouldn't access admin-only features.
**Our Solution**: Granular role-based permissions.

```javascript
// File: middleware/authenticate_token.js
export const authorizeRole = (roles = []) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return res.status(403).json({ error: 'Forbidden: insufficient privileges' });
  }
  next();
};

// Usage Example in routes/products.js
router.post('/', 
  adminRateLimit,                    // Rate limiting for admin operations
  authorizeRole(['admin']),          // Only admins can create products
  validateProductData,               // Input validation
  async (req, res) => {
    // Product creation logic
  }
);
```

#### 1.3 Comprehensive Input Validation

**Problem**: No input validation allowed malicious data injection.
**Our Solution**: Multi-layer validation using the `validator` library.

```javascript
// File: routes/products.js
function validateProductData(req, res, next) {
  const { name, price, category, description } = req.body;
  
  // Name validation
  if (!name || !validator.isLength(name, { min: 1, max: 100 })) {
    return res.status(400).json({ error: 'Product name is required and must be 1-100 characters' });
  }
  
  // Price validation
  if (!price || !validator.isFloat(price.toString(), { min: 0 })) {
    return res.status(400).json({ error: 'Price must be a positive number' });
  }
  
  // Category validation
  if (!category || !validator.isLength(category, { min: 1, max: 50 })) {
    return res.status(400).json({ error: 'Category is required and must be 1-50 characters' });
  }
  
  // Description validation (optional field)
  if (description && !validator.isLength(description, { max: 500 })) {
    return res.status(400).json({ error: 'Description must be less than 500 characters' });
  }
  
  next();
}

// Product ID validation to prevent injection attacks
router.get('/:productId', async (req, res) => {
  const { productId } = req.params;
  
  // Strict alphanumeric validation
  if (!productId || !validator.isAlphanumeric(productId, 'en-US', { ignore: '-_' })) {
    return res.status(400).json({ error: 'Invalid product ID format' });
  }

  // Additional security check for malicious patterns
  if (productId.includes('<script>') || productId.includes('DROP') || productId.length > 50) {
    console.warn('Malicious input detected:', productId);
    return res.status(400).json({ error: 'Invalid product ID' });
  }
  
  // Safe to proceed with database query
  const product = await productDB.getProduct(productId);
});
```

#### 1.4 Advanced Rate Limiting System

**Problem**: API was vulnerable to abuse and DDoS attacks.
**Our Solution**: Database-backed, endpoint-specific rate limiting.

```javascript
// File: middleware/rate_limit.js
class DatabaseStore {
  constructor(windowMs, maxRequests) {
    this.windowMs = windowMs;
    this.maxRequests = maxRequests;
  }

  async increment(key) {
    try {
      const [ip, endpoint] = key.split(':');
      const result = await rateLimitDB.checkRateLimit(
        ip, endpoint, this.maxRequests, this.windowMs
      );
      
      return {
        totalHits: result.requests,
        resetTime: new Date(result.resetTime)
      };
    } catch (error) {
      // Fail open - allow request if database fails
      return { totalHits: 1, resetTime: new Date(Date.now() + this.windowMs) };
    }
  }
}

// Different limits for different endpoint types
export const generalRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,                 // 100 requests per window
  store: new DatabaseStore(15 * 60 * 1000),
  keyGenerator: (req) => `${req.ip}:general`
});

export const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,                  // Only 10 auth attempts per window
  store: new DatabaseStore(15 * 60 * 1000),
  keyGenerator: (req) => `${req.ip}:auth`
});

export const adminRateLimit = rateLimit({
  windowMs: 5 * 60 * 1000,  // 5 minutes
  max: 20,                  // 20 admin operations per 5 minutes
  store: new DatabaseStore(5 * 60 * 1000),
  keyGenerator: (req) => `${req.ip}:admin`
});
```

**Applied in server.js:**
```javascript
// File: server.js
app.use(generalRateLimit);                    // Applied to all routes
app.use('/api/auth', authRateLimit, authRoutes);      // Stricter for auth
app.use('/api/products', authenticateToken, productsRoutes); // Auth required
```

### ⚡ Step 2: Performance Optimization

#### 2.1 Database Persistence Strategy

**Problem**: 1000 products generated on every request caused massive memory leaks.
**Our Solution**: SQLite database with one-time seeding and proper schema design.

```javascript
// File: database/db.js - Database Schema
export function initializeDatabase() {
  return new Promise((resolve, reject) => {
    db.serialize(() => {
      // Products table with proper indexing
      db.run(`
        CREATE TABLE IF NOT EXISTS products (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          description TEXT,
          price REAL NOT NULL,
          category TEXT,
          brand TEXT,
          stock INTEGER DEFAULT 0,
          rating REAL DEFAULT 0,
          tags TEXT,
          cost_price REAL,
          supplier TEXT,
          internal_notes TEXT,
          admin_only BOOLEAN DEFAULT 0,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);

      // Carts table for persistence
      db.run(`
        CREATE TABLE IF NOT EXISTS carts (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id TEXT UNIQUE NOT NULL,
          cart_data TEXT NOT NULL,
          total REAL DEFAULT 0,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);

      // Users table for authentication
      db.run(`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id TEXT UNIQUE NOT NULL,
          username TEXT UNIQUE NOT NULL,
          email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'customer',
          first_name TEXT,
          last_name TEXT,
          phone TEXT,
          address TEXT,
          city TEXT,
          country TEXT,
          postal_code TEXT,
          is_active BOOLEAN DEFAULT 1,
          email_verified BOOLEAN DEFAULT 0,
          last_login DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);
    });
  });
}
```

**Smart Product Generation:**
```javascript
// File: routes/products.js
async function generateProducts() {
  try {
    // Check if products already exist - avoid regeneration
    const existingProducts = await productDB.getProducts(1, 0);
    if (existingProducts.total > 0) {
      console.log(`Found ${existingProducts.total} existing products in database`);
      return; // Skip generation if products exist
    }
    
    console.log('Generating sample products and saving to database...');
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
        tags: [`tag${i}`, `feature${i % 10}`]
      };
      
      await productDB.saveProduct(product); // Save to database
    }
    
    console.log(`✅ ${totalProducts} sample products generated and saved to database`);
  } catch (error) {
    console.error('Error generating products:', error);
  }
}

// Called only once on startup
generateProducts();
```

#### 2.2 Advanced Search and Caching System

**Problem**: Linear search through arrays was extremely slow.
**Our Solution**: Database-powered search with intelligent caching.

```javascript
// File: database/db.js - Advanced Search Implementation
getProducts: (limit = 20, offset = 0, filters = {}) => {
  return new Promise((resolve, reject) => {
    let query = 'SELECT * FROM products WHERE 1=1';
    let countQuery = 'SELECT COUNT(*) as total FROM products WHERE 1=1';
    const params = [];
    
    // Advanced fuzzy search with multiple terms
    if (filters.search) {
      const searchTerms = filters.search.toLowerCase().split(' ').filter(term => term.length > 0);
      if (searchTerms.length > 0) {
        const searchConditions = searchTerms.map(() => 
          '(LOWER(name) LIKE ? OR LOWER(description) LIKE ? OR LOWER(brand) LIKE ? OR LOWER(tags) LIKE ?)'
        ).join(' AND ');
        
        query += ` AND (${searchConditions})`;
        countQuery += ` AND (${searchConditions})`;
        
        searchTerms.forEach(term => {
          const fuzzyTerm = `%${term}%`;
          params.push(fuzzyTerm, fuzzyTerm, fuzzyTerm, fuzzyTerm);
        });
      }
    }
    
    // Faceted filtering
    if (filters.category) {
      query += ' AND category = ?';
      countQuery += ' AND category = ?';
      params.push(filters.category);
    }
    
    if (filters.brand) {
      query += ' AND brand = ?';
      countQuery += ' AND brand = ?';
      params.push(filters.brand);
    }
    
    // Price range filtering
    if (filters.minPrice) {
      query += ' AND price >= ?';
      countQuery += ' AND price >= ?';
      params.push(parseFloat(filters.minPrice));
    }
    
    if (filters.maxPrice) {
      query += ' AND price <= ?';
      countQuery += ' AND price <= ?';
      params.push(parseFloat(filters.maxPrice));
    }
    
    // Rating filtering
    if (filters.minRating) {
      query += ' AND rating >= ?';
      countQuery += ' AND rating >= ?';
      params.push(parseFloat(filters.minRating));
    }
    
    // Stock filtering
    if (filters.inStock) {
      query += ' AND stock > 0';
      countQuery += ' AND stock > 0';
    }
    
    // Smart sorting
    if (filters.sortBy) {
      const allowedSorts = ['name', 'price', 'rating', 'created_at', 'stock'];
      if (allowedSorts.includes(filters.sortBy)) {
        const order = filters.sortOrder === 'desc' ? 'DESC' : 'ASC';
        query += ` ORDER BY ${filters.sortBy} ${order}`;
      }
    } else {
      // Default relevance-based sorting for search queries
      if (filters.search) {
        query += ' ORDER BY (CASE WHEN LOWER(name) LIKE ? THEN 1 ELSE 2 END), rating DESC';
        params.push(`%${filters.search.toLowerCase()}%`);
      }
    }
    
    query += ' LIMIT ? OFFSET ?';
    params.push(limit, offset);
    
    // Execute queries and return results
    // ... query execution logic
  });
}
```

**Multi-Layer Caching Strategy:**
```javascript
// File: routes/products.js
let productsCache = new Map(); // In-memory cache
const CACHE_TTL = parseInt(process.env.PRODUCTS_CACHE_TTL_MS) || 5 * 60 * 1000; // 5 minutes

router.get('/', async (req, res) => {
  try {
    // Create intelligent cache key
    const cacheKey = `${search || ''}-${category || ''}-${brand || ''}-${minPrice || ''}-${maxPrice || ''}-${minRating || ''}-${inStock}-${sortBy}-${sortOrder}-${page}-${limit}`;
    
    let result;
    if (productsCache.has(cacheKey)) {
      result = productsCache.get(cacheKey); // Cache hit
    } else {
      result = await productDB.getProducts(limit, offset, filters); // Database query
      
      // Cache the results with TTL
      productsCache.set(cacheKey, result);
      setTimeout(() => productsCache.delete(cacheKey), CACHE_TTL);
    }

    // HTTP caching headers for client-side caching
    res.set({
      'Cache-Control': 'public, max-age=300', // 5 minutes client cache
      'X-Performance-Optimized': 'true',
      'X-Database-Powered': 'true',
      'X-Advanced-Search': 'enabled'
    });

    res.json({
      products: result.products.map(product => ({
        // Only return public fields - security by design
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
        // Internal fields (cost_price, supplier, etc.) never exposed
      })),
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
    console.error('Products endpoint error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Unable to retrieve products at this time'
    });
  }
});
```

#### 2.3 Cart Performance Optimization

**Problem**: Cart totals recalculated on every operation, no persistence.
**Our Solution**: Cached calculations with database persistence.

```javascript
// File: routes/cart.js
const cartTotalsCache = new Map(); // Cache for cart totals
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

function calculateCartTotal(userId, cart) {
  // Check cache first
  if (cartTotalsCache.has(userId)) {
    const cached = cartTotalsCache.get(userId);
    if (Date.now() - cached.timestamp < CACHE_TTL) {
      return cached.total; // Return cached result
    }
  }

  // Calculate total only if not cached
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

function clearCartCache(userId) {
  cartTotalsCache.delete(userId); // Clear cache when cart changes
}

// Database-backed cart persistence
router.post('/', cartRateLimit, authorizeRole(['customer','admin']), async (req, res) => {
  try {
    const userId = req.user.userId; // From JWT token - secure
    const { productId, quantity = 1 } = req.body;
    
    // Load cart from database
    let cart = await cartDB.getCart(userId);
    if (!cart) {
      cart = { items: [], total: 0, createdAt: new Date().toISOString() };
    }
    
    // Update cart logic...
    
    // Clear cache and recalculate
    clearCartCache(userId);
    cart.total = calculateCartTotal(userId, cart);
    
    // Save to database
    await cartDB.saveCart(userId, { items: cart.items }, cart.total);
    
    // Broadcast real-time update via WebSocket
    broadcastCartUpdate(userId, {
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
    });

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
```

### 🔄 Step 3: Real-Time Features

#### 3.1 WebSocket Implementation

**Problem**: No real-time updates for inventory or cart changes.
**Our Solution**: Authenticated WebSocket server with room-based broadcasting.

```javascript
// File: middleware/websocket.js
export const initializeWebSocket = (server) => {
  io = new Server(server, {
    cors: {
      origin: wsOrigins,
      methods: ["GET", "POST"]
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
    }

    // Handle inventory subscription
    socket.on('subscribe_inventory', (data) => {
      const { productIds } = data;
      if (Array.isArray(productIds)) {
        productIds.forEach(productId => {
          socket.join(`product:${productId}`);
        });
        socket.emit('inventory_subscribed', {
          productIds,
          message: 'Subscribed to inventory updates',
          timestamp: new Date().toISOString()
        });
      }
    });
  });
};

// Broadcast functions
export const broadcastInventoryUpdate = (productId, inventoryData) => {
  if (!io) return;
  
  io.to(`product:${productId}`).emit('inventory_update', {
    productId,
    ...inventoryData,
    timestamp: new Date().toISOString()
  });
};

export const broadcastCartUpdate = (userId, cartData) => {
  if (!io) return;
  
  io.to(`user:${userId}`).emit('cart_update', {
    ...cartData,
    timestamp: new Date().toISOString()
  });
};
```

#### 3.2 Metrics and Monitoring

**Problem**: No visibility into API performance and usage.
**Our Solution**: Comprehensive metrics collection with real-time monitoring.

```javascript
// File: middleware/metrics.js
const metricsStore = {
  requests: new Map(),      // endpoint -> count
  responseTimes: new Map(), // endpoint -> array of times
  errors: new Map(),        // endpoint -> error count
  activeConnections: 0,
  startTime: Date.now()
};

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
```

### 🎨 Step 4: User Interface Enhancement

**Problem**: Admin panel had hardcoded credentials and poor UX.
**Our Solution**: Secure, user-friendly admin interface.

```html
<!-- File: public/admin-panel.html - Secure Login Form -->
<div class="subsection">
    <h4><i class="fas fa-key"></i> Login</h4>
    <p class="help-text">Enter your credentials and click Login. Use the seeded accounts or your own.</p>
    <div class="form-group">
        <label for="identifier"><i class="fas fa-user"></i> Username or Email</label>
        <input type="text" id="identifier" placeholder="e.g., admin or admin@example.com">
        <small class="help-text">Default usernames: admin, customer, guest</small>
    </div>
    <div class="form-group">
        <label for="password"><i class="fas fa-lock"></i> Password</label>
        <input type="password" id="password" placeholder="Enter your password">
        <small class="help-text">Seeded passwords: Admin@123, Customer@123, Guest@123</small>
    </div>
    <div class="input-group">
        <button onclick="autoLogin()" class="btn btn-primary">
            <i class="fas fa-sign-in-alt"></i>
            Login
        </button>
    </div>
</div>
```

**Secure JavaScript Implementation:**
```javascript
// File: public/admin-panel.html - Secure Login Function
async function autoLogin() {
    try {
        updateAuthStatus('connecting', '<i class="fas fa-spinner fa-spin"></i> Connecting...');
        const idEl = document.getElementById('identifier');
        const pwEl = document.getElementById('password');
        const identifier = idEl ? idEl.value.trim() : '';
        const password = pwEl ? pwEl.value : '';

        if (!identifier || !password) {
            log('❌ Please enter identifier and password');
            updateAuthStatus('error', '<i class="fas fa-exclamation-triangle"></i> Missing credentials');
            return;
        }

        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                identifier: identifier,
                password: password
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            authToken = data.token;
            updateAuthStatus('connected', `<i class="fas fa-check-circle"></i> ${data.user.username} (${data.user.role})`);
            log(`✅ Authenticated as ${data.user.username} (${data.user.role})`);
            
            // Auto-connect to WebSocket after successful login
            setTimeout(() => connect(), 500);
        } else {
            throw new Error(data.error || 'Login failed');
        }
    } catch (error) {
        log(`❌ Login failed: ${error.message}`);
        updateAuthStatus('error', `<i class="fas fa-exclamation-triangle"></i> Auth failed`);
    }
}
```

### 📊 Step 5: Monitoring and Observability

Our solution includes comprehensive monitoring:

1. **Performance Metrics**: Response times, request counts, error rates
2. **Security Monitoring**: Rate limit violations, authentication failures
3. **Business Metrics**: Product views, cart operations, user activity
4. **Real-time Dashboards**: WebSocket connection stats, live event monitoring

### 🔧 Environment Configuration

```bash
# File: .env - Production-Ready Configuration
# Core Settings
PORT=3002
NODE_ENV=production
JWT_SECRET=your-super-secure-jwt-secret-here
JWT_EXPIRES_IN=24h

# Database Configuration
DB_PATH=./database/ecommerce.db

# Performance Tuning
SAMPLE_PRODUCTS_COUNT=1000
PRODUCTS_CACHE_TTL_MS=300000

# Rate Limiting (per IP)
RATE_LIMIT_WINDOW_MS=900000        # 15 minutes
RATE_LIMIT_MAX_REQUESTS=100        # 100 requests per window
AUTH_RATE_LIMIT_MAX_REQUESTS=10    # 10 auth attempts per window
ADMIN_RATE_LIMIT_MAX_REQUESTS=20   # 20 admin ops per 5 minutes

# CORS Security
DEV_ORIGINS=http://localhost:3000,http://localhost:3002
PRODUCTION_ORIGINS=https://yourdomain.com,https://www.yourdomain.com

# WebSocket Configuration
WS_DEV_ORIGINS=http://localhost:3000,http://localhost:3002
WS_PRODUCTION_ORIGINS=https://yourdomain.com,https://www.yourdomain.com

# Security Settings
BCRYPT_SALT_ROUNDS=12
```

### 🚀 Deployment and Testing

**Local Development:**
```bash
# Install dependencies
npm install

# Set up environment
cp env.example .env
# Edit .env with your values

# Start development server
npm run dev

# Server runs on http://localhost:3002
# Admin panel: http://localhost:3002/admin-panel.html
```

**Testing the Implementation:**
```bash
# Test authentication
curl -X POST http://localhost:3002/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"identifier":"admin","password":"Admin@123"}'

# Test protected endpoints
curl -H "Authorization: Bearer <JWT_TOKEN>" \
  "http://localhost:3002/api/products?search=electronics&limit=10"

# Test rate limiting
for i in {1..15}; do curl http://localhost:3002/api/auth/users; done

# Test WebSocket (using the admin panel)
# Open http://localhost:3002/admin-panel.html
# Login and test real-time features
```

This comprehensive solution transforms a vulnerable, slow API into a production-ready e-commerce backend with enterprise-grade security, performance, and monitoring capabilities.

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
time curl "http://localhost:3002/api/products"

# Test search performance with common terms
time curl "http://localhost:3002/api/products?search=product"

# Test large result sets
time curl "http://localhost:3002/api/products?limit=1000"
```

### Security Testing
```bash
# Test admin data exposure
curl "http://localhost:3002/api/products?admin=true"

# Test internal data access
curl "http://localhost:3002/api/products/1?internal=yes"

# Test malicious product ID
curl "http://localhost:3002/api/products/<script>alert('xss')</script>"

# Test secret endpoint access methods
curl -H "Authorization: Bearer secret-admin-token" \
     "http://localhost:3002/api/product_secret_endpoint"
```

### Cart Security Testing
```bash
# Test cross-user data access
curl -H "X-User-Id: victim" "http://localhost:3002/api/cart"
curl -H "X-User-Id: attacker" "http://localhost:3002/api/cart"
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


