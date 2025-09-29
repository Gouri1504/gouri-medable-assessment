import sqlite3 from 'sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Database setup
const dbPath = process.env.DB_PATH || path.join(__dirname, 'ecommerce.db');
const db = new sqlite3.Database(dbPath);

// Initialize database tables
export function initializeDatabase() {
  return new Promise((resolve, reject) => {
    db.serialize(() => {
      // Create carts table
      db.run(`
        CREATE TABLE IF NOT EXISTS carts (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id TEXT UNIQUE NOT NULL,
          cart_data TEXT NOT NULL,
          total REAL DEFAULT 0,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `, (err) => {
        if (err) {
          console.error('Error creating carts table:', err);
          reject(err);
          return;
        }
      });

      // Create products table for persistence
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
      `, (err) => {
        if (err) {
          console.error('Error creating products table:', err);
          reject(err);
          return;
        }
      });

      // Create rate_limits table for tracking API usage
      db.run(`
        CREATE TABLE IF NOT EXISTS rate_limits (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ip_address TEXT NOT NULL,
          endpoint TEXT NOT NULL,
          requests_count INTEGER DEFAULT 1,
          window_start DATETIME DEFAULT CURRENT_TIMESTAMP,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `, (err) => {
        if (err) {
          console.error('Error creating rate_limits table:', err);
          reject(err);
          return;
        }
      });

      // Create users table for authentication
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
      `, (err) => {
        if (err) {
          console.error('Error creating users table:', err);
          reject(err);
          return;
        }
        console.log('✅ Database initialized successfully');
        resolve();
      });
    });
  });
}

// Cart persistence functions
export const cartDB = {
  // Get user's cart
  getCart: (userId) => {
    return new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM carts WHERE user_id = ?',
        [userId],
        (err, row) => {
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
        }
      );
    });
  },

  // Save/update user's cart
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
  },

  // Delete user's cart
  deleteCart: (userId) => {
    return new Promise((resolve, reject) => {
      db.run(
        'DELETE FROM carts WHERE user_id = ?',
        [userId],
        function(err) {
          if (err) {
            reject(err);
            return;
          }
          resolve({ deleted: this.changes > 0 });
        }
      );
    });
  }
};

// Product persistence functions
export const productDB = {
  // Get all products with pagination and advanced search
  getProducts: (limit = 20, offset = 0, filters = {}) => {
    return new Promise((resolve, reject) => {
      let query = 'SELECT * FROM products WHERE 1=1';
      let countQuery = 'SELECT COUNT(*) as total FROM products WHERE 1=1';
      const params = [];
      
      // Advanced search with fuzzy matching
      if (filters.search) {
        // Split search terms for better matching
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
      
      if (filters.minRating) {
        query += ' AND rating >= ?';
        countQuery += ' AND rating >= ?';
        params.push(parseFloat(filters.minRating));
      }
      
      if (filters.inStock) {
        query += ' AND stock > 0';
        countQuery += ' AND stock > 0';
      }
      
      // Add sorting
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
      
      // Get total count first
      db.get(countQuery, params.slice(0, -2), (err, countRow) => {
        if (err) {
          reject(err);
          return;
        }
        
        // Get products
        db.all(query, params, (err, rows) => {
          if (err) {
            reject(err);
            return;
          }
          
          const products = rows.map(row => ({
            ...row,
            tags: row.tags ? JSON.parse(row.tags) : [],
            admin_only: Boolean(row.admin_only)
          }));
          
          resolve({
            products,
            total: countRow.total
          });
        });
      });
    });
  },

  // Get single product
  getProduct: (productId) => {
    return new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM products WHERE id = ?',
        [productId],
        (err, row) => {
          if (err) {
            reject(err);
            return;
          }
          
          if (!row) {
            resolve(null);
            return;
          }
          
          resolve({
            ...row,
            tags: row.tags ? JSON.parse(row.tags) : [],
            admin_only: Boolean(row.admin_only)
          });
        }
      );
    });
  },

  // Save product
  saveProduct: (product) => {
    return new Promise((resolve, reject) => {
      const {
        id, name, description, price, category, brand, stock, rating,
        tags, cost_price, supplier, internal_notes, admin_only
      } = product;
      
      db.run(
        `INSERT OR REPLACE INTO products 
         (id, name, description, price, category, brand, stock, rating, tags, 
          cost_price, supplier, internal_notes, admin_only, updated_at) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
        [
          id, name, description, price, category, brand, stock, rating,
          JSON.stringify(tags), cost_price, supplier, internal_notes, admin_only ? 1 : 0
        ],
        function(err) {
          if (err) {
            reject(err);
            return;
          }
          resolve({ id, rowsAffected: this.changes });
        }
      );
    });
  },

  // Delete product
  deleteProduct: (productId) => {
    return new Promise((resolve, reject) => {
      db.run(
        'DELETE FROM products WHERE id = ?',
        [productId],
        function(err) {
          if (err) {
            reject(err);
            return;
          }
          resolve({ deleted: this.changes > 0 });
        }
      );
    });
  },

  // Get faceted search data
  getFacets: () => {
    return new Promise((resolve, reject) => {
      const facets = {};
      
      // Get categories
      db.all('SELECT DISTINCT category FROM products WHERE category IS NOT NULL ORDER BY category', (err, categories) => {
        if (err) {
          reject(err);
          return;
        }
        facets.categories = categories.map(row => row.category);
        
        // Get brands
        db.all('SELECT DISTINCT brand FROM products WHERE brand IS NOT NULL ORDER BY brand', (err, brands) => {
          if (err) {
            reject(err);
            return;
          }
          facets.brands = brands.map(row => row.brand);
          
          // Get price ranges
          db.get('SELECT MIN(price) as minPrice, MAX(price) as maxPrice FROM products', (err, priceRange) => {
            if (err) {
              reject(err);
              return;
            }
            facets.priceRange = {
              min: Math.floor(priceRange.minPrice || 0),
              max: Math.ceil(priceRange.maxPrice || 1000)
            };
            
            // Get rating ranges
            db.get('SELECT MIN(rating) as minRating, MAX(rating) as maxRating FROM products', (err, ratingRange) => {
              if (err) {
                reject(err);
                return;
              }
              facets.ratingRange = {
                min: Math.floor(ratingRange.minRating || 0),
                max: Math.ceil(ratingRange.maxRating || 5)
              };
              
              resolve(facets);
            });
          });
        });
      });
    });
  },

  // Get product recommendations
  getRecommendations: (productId, limit = 5) => {
    return new Promise((resolve, reject) => {
      // First get the target product
      db.get('SELECT * FROM products WHERE id = ?', [productId], (err, targetProduct) => {
        if (err || !targetProduct) {
          reject(err || new Error('Product not found'));
          return;
        }

        // Content-based recommendations: similar category, brand, or price range
        const recommendations = [];
        const priceRange = targetProduct.price * 0.3; // 30% price tolerance
        
        // Similar products by category and brand (highest priority)
        db.all(
          `SELECT *, 
           (CASE 
             WHEN category = ? AND brand = ? AND id != ? THEN 5
             WHEN category = ? AND id != ? THEN 4  
             WHEN brand = ? AND id != ? THEN 3
             WHEN price BETWEEN ? AND ? AND id != ? THEN 2
             ELSE 1 
           END) as relevance_score
           FROM products 
           WHERE id != ? AND admin_only = 0
           ORDER BY relevance_score DESC, rating DESC, price ASC
           LIMIT ?`,
          [
            targetProduct.category, targetProduct.brand, productId,
            targetProduct.category, productId,
            targetProduct.brand, productId,
            targetProduct.price - priceRange, targetProduct.price + priceRange, productId,
            productId, limit
          ],
          (err, rows) => {
            if (err) {
              reject(err);
              return;
            }
            
            const recommendations = rows.map(row => ({
              ...row,
              tags: row.tags ? JSON.parse(row.tags) : [],
              admin_only: Boolean(row.admin_only),
              recommendation_reason: getRecommendationReason(row, targetProduct)
            }));
            
            resolve(recommendations);
          }
        );
      });
    });
  },

  // Get trending products (most viewed/popular)
  getTrendingProducts: (limit = 10) => {
    return new Promise((resolve, reject) => {
      db.all(
        `SELECT * FROM products 
         WHERE admin_only = 0 
         ORDER BY rating DESC, stock DESC, created_at DESC 
         LIMIT ?`,
        [limit],
        (err, rows) => {
          if (err) {
            reject(err);
            return;
          }
          
          const trending = rows.map(row => ({
            ...row,
            tags: row.tags ? JSON.parse(row.tags) : [],
            admin_only: Boolean(row.admin_only)
          }));
          
          resolve(trending);
        }
      );
    });
  }
};

// Rate limiting functions
export const rateLimitDB = {
  // Check and update rate limit
  checkRateLimit: (ipAddress, endpoint, maxRequests, windowMs) => {
    return new Promise((resolve, reject) => {
      const windowStart = new Date(Date.now() - windowMs);
      
      db.get(
        `SELECT requests_count, window_start FROM rate_limits 
         WHERE ip_address = ? AND endpoint = ? AND window_start > ?`,
        [ipAddress, endpoint, windowStart.toISOString()],
        (err, row) => {
          if (err) {
            reject(err);
            return;
          }
          
          if (!row) {
            // First request in window
            db.run(
              `INSERT INTO rate_limits (ip_address, endpoint, requests_count, window_start) 
               VALUES (?, ?, 1, CURRENT_TIMESTAMP)`,
              [ipAddress, endpoint],
              (insertErr) => {
                if (insertErr) {
                  reject(insertErr);
                  return;
                }
                resolve({ allowed: true, requests: 1, resetTime: Date.now() + windowMs });
              }
            );
          } else if (row.requests_count >= maxRequests) {
            // Rate limit exceeded
            resolve({ 
              allowed: false, 
              requests: row.requests_count, 
              resetTime: new Date(row.window_start).getTime() + windowMs 
            });
          } else {
            // Update existing record
            db.run(
              `UPDATE rate_limits SET requests_count = requests_count + 1 
               WHERE ip_address = ? AND endpoint = ? AND window_start = ?`,
              [ipAddress, endpoint, row.window_start],
              (updateErr) => {
                if (updateErr) {
                  reject(updateErr);
                  return;
                }
                resolve({ 
                  allowed: true, 
                  requests: row.requests_count + 1, 
                  resetTime: new Date(row.window_start).getTime() + windowMs 
                });
              }
            );
          }
        }
      );
    });
  },

  // Clean old rate limit records
  cleanOldRecords: () => {
    return new Promise((resolve, reject) => {
      const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
      
      db.run(
        'DELETE FROM rate_limits WHERE created_at < ?',
        [oneDayAgo.toISOString()],
        function(err) {
          if (err) {
            reject(err);
            return;
          }
          resolve({ deletedRows: this.changes });
        }
      );
    });
  }
};

// User authentication functions
export const userDB = {
  // Create a new user
  createUser: (userData) => {
    return new Promise((resolve, reject) => {
      const {
        user_id,
        username,
        email,
        password_hash,
        role = 'customer',
        first_name,
        last_name,
        phone,
        address,
        city,
        country,
        postal_code
      } = userData;

      db.run(`
        INSERT INTO users (
          user_id, username, email, password_hash, role,
          first_name, last_name, phone, address, city, country, postal_code
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [
        user_id, username, email, password_hash, role,
        first_name, last_name, phone, address, city, country, postal_code
      ], function(err) {
        if (err) {
          reject(err);
          return;
        }
        resolve({ id: this.lastID, user_id });
      });
    });
  },

  // Find user by username or email
  findUser: (identifier) => {
    return new Promise((resolve, reject) => {
      db.get(`
        SELECT * FROM users 
        WHERE username = ? OR email = ?
        AND is_active = 1
      `, [identifier, identifier], (err, row) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(row);
      });
    });
  },

  // Find user by user_id
  findUserById: (user_id) => {
    return new Promise((resolve, reject) => {
      db.get(`
        SELECT * FROM users 
        WHERE user_id = ? AND is_active = 1
      `, [user_id], (err, row) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(row);
      });
    });
  },

  // Update user's last login
  updateLastLogin: (user_id) => {
    return new Promise((resolve, reject) => {
      db.run(`
        UPDATE users 
        SET last_login = CURRENT_TIMESTAMP 
        WHERE user_id = ?
      `, [user_id], (err) => {
        if (err) {
          reject(err);
          return;
        }
        resolve();
      });
    });
  },

  // Get all users (admin only)
  getAllUsers: () => {
    return new Promise((resolve, reject) => {
      db.all(`
        SELECT user_id, username, email, role, first_name, last_name,
               phone, city, country, is_active, email_verified,
               last_login, created_at, updated_at
        FROM users 
        ORDER BY created_at DESC
      `, [], (err, rows) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(rows);
      });
    });
  },

  // Update user profile
  updateUser: (user_id, updateData) => {
    return new Promise((resolve, reject) => {
      const fields = [];
      const values = [];
      
      const allowedFields = ['first_name', 'last_name', 'phone', 'address', 'city', 'country', 'postal_code', 'email'];
      
      for (const [key, value] of Object.entries(updateData)) {
        if (allowedFields.includes(key) && value !== undefined) {
          fields.push(`${key} = ?`);
          values.push(value);
        }
      }
      
      if (fields.length === 0) {
        resolve({ message: 'No fields to update' });
        return;
      }
      
      values.push(user_id);
      
      db.run(`
        UPDATE users 
        SET ${fields.join(', ')}, updated_at = CURRENT_TIMESTAMP
        WHERE user_id = ?
      `, values, function(err) {
        if (err) {
          reject(err);
          return;
        }
        resolve({ changes: this.changes });
      });
    });
  },

  // Update user password
  updateUserPassword: (user_id, password_hash) => {
    return new Promise((resolve, reject) => {
      db.run(`
        UPDATE users 
        SET password_hash = ?, updated_at = CURRENT_TIMESTAMP
        WHERE user_id = ?
      `, [password_hash, user_id], function(err) {
        if (err) {
          reject(err);
          return;
        }
        resolve({ changes: this.changes });
      });
    });
  }
};

// Close database connection
export function closeDatabase() {
  return new Promise((resolve) => {
    db.close((err) => {
      if (err) {
        console.error('Error closing database:', err);
      } else {
        console.log('Database connection closed');
      }
      resolve();
    });
  });
}

// Helper function to determine recommendation reason
function getRecommendationReason(recommendedProduct, targetProduct) {
  if (recommendedProduct.category === targetProduct.category && recommendedProduct.brand === targetProduct.brand) {
    return 'Same category and brand';
  } else if (recommendedProduct.category === targetProduct.category) {
    return 'Similar category';
  } else if (recommendedProduct.brand === targetProduct.brand) {
    return 'Same brand';
  } else if (Math.abs(recommendedProduct.price - targetProduct.price) <= targetProduct.price * 0.3) {
    return 'Similar price range';
  } else {
    return 'Popular choice';
  }
}

export default db;
