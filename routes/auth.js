import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import validator from 'validator';
import { v4 as uuidv4 } from 'uuid';
import authenticateToken, { authorizeRole } from '../middleware/authenticate_token.js';
import { userDB } from '../database/db.js';
const router = express.Router();

// Initialize default users on startup for testing purpose 
const initializeDefaultUsers = async () => {
  try {
    const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12;
    
    const defaultUsers = [
      {
        user_id: 'admin-001',
        username: 'admin',
        email: 'admin@example.com',
        password: 'Admin@123',
        role: 'admin',
        first_name: 'Admin',
        last_name: 'User',
        phone: '+1234567890',
        city: 'New York',
        country: 'USA'
      },
      {
        user_id: 'customer-001',
        username: 'customer',
        email: 'customer@example.com',
        password: 'Customer@123',
        role: 'customer',
        first_name: 'John',
        last_name: 'Doe',
        phone: '+1234567891',
        city: 'Los Angeles',
        country: 'USA'
      },
      {
        user_id: 'guest-001',
        username: 'guest',
        email: 'guest@example.com',
        password: 'Guest@123',
        role: 'guest',
        first_name: 'Guest',
        last_name: 'User'
      }
    ];

    for (const userData of defaultUsers) {
      try {
        const existingUser = await userDB.findUser(userData.username);
        if (!existingUser) {
          const password_hash = await bcrypt.hash(userData.password, saltRounds);
          const { password, ...userDataWithoutPassword } = userData;
          
          await userDB.createUser({
            ...userDataWithoutPassword,
            password_hash
          });
          console.log(`✅ Default user created: ${userData.username}`);
        } else {
          // Update existing user with new password if needed
          const passwordMatch = await bcrypt.compare(userData.password, existingUser.password_hash);
          if (!passwordMatch) {
            const password_hash = await bcrypt.hash(userData.password, saltRounds);
            await userDB.updateUserPassword(existingUser.user_id, password_hash);
            console.log(`🔄 Updated password for user: ${userData.username}`);
          }
        }
      } catch (error) {
        if (error.code !== 'SQLITE_CONSTRAINT_UNIQUE') {
          console.error(`Error creating/updating default user ${userData.username}:`, error);
        }
      }
    }
  } catch (error) {
    console.error('Error initializing default users:', error);
  }
};

// Call initialization
setTimeout(initializeDefaultUsers, 1000);

// User Registration endpoint (public)
router.post('/register', async (req, res) => {
  try {
    const { username, email, password, role = 'customer', first_name, last_name, phone, address, city, country, postal_code } = req.body;

    // Validation
    if (!username || !validator.isLength(username, { min: 3, max: 30 })) {
      return res.status(400).json({ error: 'Username must be 3-30 characters long' });
    }

    if (!email || !validator.isEmail(email)) {
      return res.status(400).json({ error: 'Valid email is required' });
    }

    if (!password || !validator.isLength(password, { min: 6 })) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }

    if (!['admin', 'customer', 'guest'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role. Must be admin, customer, or guest' });
    }

    // Check if user already exists
    const existingUser = await userDB.findUser(username);
    if (existingUser) {
      return res.status(409).json({ error: 'Username or email already exists' });
    }

    // Hash password
    const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12;
    const password_hash = await bcrypt.hash(password, saltRounds);

    // Create user
    const user_id = uuidv4();
    const newUser = await userDB.createUser({
      user_id,
      username: validator.escape(username),
      email: validator.normalizeEmail(email),
      password_hash,
      role,
      first_name: first_name ? validator.escape(first_name) : null,
      last_name: last_name ? validator.escape(last_name) : null,
      phone: phone ? validator.escape(phone) : null,
      address: address ? validator.escape(address) : null,
      city: city ? validator.escape(city) : null,
      country: country ? validator.escape(country) : null,
      postal_code: postal_code ? validator.escape(postal_code) : null
    });

    res.status(201).json({
      message: 'User registered successfully',
      user: {
        user_id: newUser.user_id,
        username,
        email,
        role,
        first_name,
        last_name
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: 'Username or email already exists' });
    }
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login endpoint (public) - requires username/email and password
router.post('/login', async (req, res) => {
  try {
    const { identifier, password } = req.body;

    const JWT_SECRET = process.env.JWT_SECRET;
    if (!JWT_SECRET) {
      console.error('FATAL ERROR: JWT_SECRET environment variable is not set');
      return res.status(500).json({ error: 'Server configuration error' });
    }

    // Validate required fields
    if (!identifier && !password) {
      return res.status(400).json({ 
        error: 'Missing credentials',
        message: 'Both username/email and password are required'
      });
    }
    
    if (!identifier) {
      return res.status(400).json({ 
        error: 'Missing identifier',
        message: 'Username or email is required'
      });
    }
    
    if (!password) {
      return res.status(400).json({ 
        error: 'Missing password',
        message: 'Password is required'
      });
    }

    if (!validator.isLength(identifier, { min: 1, max: 100 })) {
      return res.status(400).json({ error: 'Valid username or email is required' });
    }

    if (!validator.isLength(password, { min: 1 })) {
      return res.status(400).json({ error: 'Password is required' });
    }

    // Find user in database
    const user = await userDB.findUser(identifier);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Verify password
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Update last login
    await userDB.updateLastLogin(user.user_id);

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: user.user_id, 
        username: user.username, 
        role: user.role, 
        email: user.email 
      },
      JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        userId: user.user_id,
        username: user.username,
        email: user.email,
        role: user.role,
        first_name: user.first_name,
        last_name: user.last_name,
        last_login: user.last_login
      },
      expiresIn: process.env.JWT_EXPIRES_IN || '24h'
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});


// List available users for testing (public)
router.get('/users', async (req, res) => {
  try {
    const users = await userDB.getAllUsers();
    res.json({
      message: 'Available test users for login',
      users: users.map(u => ({ 
        username: u.username, 
        email: u.email,
        role: u.role,
        first_name: u.first_name,
        last_name: u.last_name
      })),
      testAccounts: [
        { username: 'admin', email: 'admin@example.com', role: 'admin' },
        { username: 'customer', email: 'customer@example.com', role: 'customer' },
        { username: 'guest', email: 'guest@example.com', role: 'guest' }
      ],
      instructions: {
        login: 'POST /api/auth/login with { "identifier": "username_or_email", "password": "your_password" }',
        register: 'POST /api/auth/register with { "username": "newuser", "email": "user@example.com", "password": "password123" }',
        usage: 'Use the returned token in Authorization header: "Bearer <token>"',
        note: 'Contact administrator for test account passwords'
      }
    });
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Verify token (protected)
router.get('/verify', authenticateToken, async (req, res) => {
  try {
    const user = await userDB.findUserById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      message: 'Token is valid',
      user: {
        userId: user.user_id,
        username: user.username,
        email: user.email,
        role: user.role,
        first_name: user.first_name,
        last_name: user.last_name,
        phone: user.phone,
        city: user.city,
        country: user.country,
        last_login: user.last_login,
        created_at: user.created_at
      }
    });
  } catch (error) {
    console.error('Token verification error:', error);
    res.status(500).json({ error: 'Token verification failed' });
  }
});

// Get user profile (protected)
router.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await userDB.findUserById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const { password_hash, ...userProfile } = user;
    res.json({
      message: 'Profile retrieved successfully',
      user: userProfile
    });
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Update user profile (protected)
router.put('/profile', authenticateToken, async (req, res) => {
  try {
    const { first_name, last_name, phone, address, city, country, postal_code, email } = req.body;
    
    const updateData = {};
    if (first_name) updateData.first_name = validator.escape(first_name);
    if (last_name) updateData.last_name = validator.escape(last_name);
    if (phone) updateData.phone = validator.escape(phone);
    if (address) updateData.address = validator.escape(address);
    if (city) updateData.city = validator.escape(city);
    if (country) updateData.country = validator.escape(country);
    if (postal_code) updateData.postal_code = validator.escape(postal_code);
    if (email && validator.isEmail(email)) updateData.email = validator.normalizeEmail(email);

    const result = await userDB.updateUser(req.user.userId, updateData);
    
    if (result.changes === 0) {
      return res.status(404).json({ error: 'User not found or no changes made' });
    }

    const updatedUser = await userDB.findUserById(req.user.userId);
    const { password_hash, ...userProfile } = updatedUser;

    res.json({
      message: 'Profile updated successfully',
      user: userProfile
    });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Get all users (admin only)
router.get('/admin/users', authenticateToken, authorizeRole(['admin']), async (req, res) => {
  try {
    const users = await userDB.getAllUsers();
    res.json({
      message: 'Users retrieved successfully',
      users: users.map(user => {
        const { password_hash, ...userWithoutPassword } = user;
        return userWithoutPassword;
      }),
      total: users.length
    });
  } catch (error) {
    console.error('Admin users fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Example: admin-only route
router.get('/admin-data', authenticateToken, authorizeRole(['admin']), (req, res) => {
  res.json({ 
    message: `Hello ${req.user.username}, this is admin-only data.`,
    serverTime: new Date().toISOString(),
    adminFeatures: [
      'User Management',
      'Product Management',
      'Order Management',
      'Analytics Dashboard'
    ]
  });
});

export default router;