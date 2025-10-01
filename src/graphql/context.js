const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../config/auth');
const User = require('../models/User');

const createContext = async ({ req }) => {
  let user = null;
  
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
    
    if (token) {
      const decoded = jwt.verify(token, JWT_SECRET);
      user = await User.findById(decoded.id).select('-password -passwordHistory');
      
      if (!user || !user.isActive) {
        user = null;
      }
    }
  } catch (error) {
    // Invalid token, continue without user
    user = null;
  }
  
  return {
    user,
    req
  };
};

module.exports = createContext;
