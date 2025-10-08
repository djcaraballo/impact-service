const jwt = require('jsonwebtoken');
const { JWT_SECRET, ROLE_PERMISSIONS, USER_ROLES } = require('../config/auth');
const User = require('../models/User');

// JWT Authentication Middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      return res.status(401).json({ 
        error: 'Access token required',
        code: 'TOKEN_MISSING'
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Check if user still exists and is active
    const user = await User.findById(decoded.id).select('-password -passwordHistory');
    if (!user || !user.isActive) {
      return res.status(401).json({ 
        error: 'Invalid or expired token',
        code: 'TOKEN_INVALID'
      });
    }

    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        error: 'Token expired',
        code: 'TOKEN_EXPIRED'
      });
    }
    
    return res.status(403).json({ 
      error: 'Invalid token',
      code: 'TOKEN_INVALID'
    });
  }
};

// Role-based Authorization Middleware
const requireRole = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ 
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ 
        error: 'Insufficient permissions',
        code: 'INSUFFICIENT_PERMISSIONS',
        required: roles,
        current: req.user.role
      });
    }

    next();
  };
};

// Permission-based Authorization Middleware
const requirePermission = (permission) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ 
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }

    const userPermissions = ROLE_PERMISSIONS[req.user.role] || [];
    
    if (!userPermissions.includes(permission)) {
      return res.status(403).json({ 
        error: 'Insufficient permissions',
        code: 'INSUFFICIENT_PERMISSIONS',
        required: permission,
        userPermissions
      });
    }

    next();
  };
};

// FERPA Compliance Middleware
const requireFerpaConsent = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ 
      error: 'Authentication required',
      code: 'AUTH_REQUIRED'
    });
  }

  // Check if user has provided FERPA consent
  if (!req.user.ferpaConsent) {
    return res.status(403).json({ 
      error: 'FERPA consent required',
      code: 'FERPA_CONSENT_REQUIRED',
      message: 'You must provide FERPA consent to access this resource'
    });
  }

  next();
};

// Resource Ownership Middleware
const requireOwnership = (resourceParam = 'id') => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ 
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }

    const resourceId = req.params[resourceParam];
    
    // Admin can access any resource
    if (req.user.role === USER_ROLES.ADMIN) {
      return next();
    }

    // Check if user owns the resource
    if (req.user._id.toString() !== resourceId) {
      return res.status(403).json({ 
        error: 'Access denied',
        code: 'ACCESS_DENIED',
        message: 'You can only access your own resources'
      });
    }

    next();
  };
};

// Student-Parent Relationship Middleware
const requireStudentAccess = async (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({ 
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }

    const studentId = req.params.studentId || req.body.studentId;
    
    if (!studentId) {
      return res.status(400).json({ 
        error: 'Student ID required',
        code: 'STUDENT_ID_REQUIRED'
      });
    }

    // Admin can access any student
    if (req.user.role === USER_ROLES.ADMIN) {
      return next();
    }

    // Teachers can access assigned students
    if (req.user.role === USER_ROLES.TEACHER) {
      // This would need to be implemented based on your class assignment logic
      // For now, we'll allow access (you'll need to add the actual check)
      return next();
    }

    // Service providers can access assigned students
    if (req.user.role === USER_ROLES.SERVICE_PROVIDER) {
      // This would need to be implemented based on your assignment logic
      return next();
    }

    // Parents can access their children
    if (req.user.role === USER_ROLES.PARENT) {
      // This would need to check parent-student relationships
      // For now, we'll allow access (you'll need to add the actual check)
      return next();
    }

    // Students can only access their own data
    if (req.user.role === USER_ROLES.STUDENT) {
      if (req.user._id.toString() !== studentId) {
        return res.status(403).json({ 
          error: 'Access denied',
          code: 'ACCESS_DENIED',
          message: 'You can only access your own student data'
        });
      }
    }

    next();
  } catch (error) {
    res.status(500).json({ 
      error: 'Internal server error',
      code: 'INTERNAL_ERROR'
    });
  }
};

// Optional Authentication (for public endpoints that can work with or without auth)
const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = await User.findById(decoded.id).select('-password -passwordHistory');
      
      if (user && user.isActive) {
        req.user = user;
      }
    }

    next();
  } catch (error) {
    // Continue without authentication if token is invalid
    next();
  }
};

module.exports = {
  authenticateToken,
  requireRole,
  requirePermission,
  requireFerpaConsent,
  requireOwnership,
  requireStudentAccess,
  optionalAuth
};
