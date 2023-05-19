const jwt = require('jsonwebtoken')
const jwtSecret = require('../config/jwtSecret')
const User = require('../models/user');

module.exports = (req, res, next) => {
    const authHeader = req.get('Authorization')
    if (!authHeader) {
        return res.status(401).json({ error: 'Missing Authorization header' })
    }

    try {
        const token = authHeader
        jwt.verify(token, jwtSecret)
        next()
    } catch (error) {
        return res.status(401).json(error)
    }

}

// Middleware to protect routes
exports.protect = async (req, res, next) => {
    try {
      let token;
  
      // Check if the token exists in the request headers
      if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
      }
  
      if (!token) {
        return res.status(401).json({ error: 'Unauthorized access' });
      }
  
      // Verify the token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
  
      // Check if the user still exists
      const user = await User.findById(decoded.id);
      if (!user) {
        return res.status(401).json({ error: 'User not found' });
      }
  
      // Attach the user object to the request
      req.user = user;
  
      next();
    } catch (error) {
      res.status(401).json({ error: 'Invalid token' });
    }
  };
  