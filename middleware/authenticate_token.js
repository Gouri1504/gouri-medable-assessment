import jwt from 'jsonwebtoken';

// Middleware to verify token
const authenticateToken = (req, res, next) => {
  try {
    const JWT_SECRET = process.env.JWT_SECRET;
    
    if (!JWT_SECRET) {
      console.error('FATAL ERROR: JWT_SECRET environment variable is not set in authenticate_token middleware');
      return res.status(500).json({ error: 'Server configuration error' });
    }

    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Access token required' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) return res.status(403).json({ error: 'Invalid or expired token' });

      req.user = user; // attach decoded user info to request
      next();
    });
  } catch (error) {
    console.error('Token middleware error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// Middleware for role-based access
export const authorizeRole = (roles = []) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return res.status(403).json({ error: 'Forbidden: insufficient privileges' });
  }
  next();
};

export default authenticateToken;