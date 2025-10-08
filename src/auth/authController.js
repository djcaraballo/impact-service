const crypto = require('crypto');
const { validationResult } = require('express-validator');
const User = require('../models/User');
const { 
  generateTokens, 
  hashPassword, 
  verifyPassword, 
  validatePassword 
} = require('../config/auth');
const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'logs/auth.log' })
  ]
});

// Register new user
const register = async (req, res) => {
  try {
    // Check validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        code: 'VALIDATION_ERROR',
        details: errors.array()
      });
    }

    const { email, password, firstName, lastName, role, phone } = req.body;

    // Check if user already exists
    const existingUser = await User.findByEmail(email);
    if (existingUser) {
      return res.status(409).json({
        error: 'User already exists',
        code: 'USER_EXISTS'
      });
    }

    // Validate password
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.isValid) {
      return res.status(400).json({
        error: 'Password validation failed',
        code: 'PASSWORD_INVALID',
        details: passwordValidation.errors
      });
    }

    // Hash password
    const hashedPassword = await hashPassword(password);

    // Create user
    const user = new User({
      email,
      password: hashedPassword,
      firstName,
      lastName,
      role: role || 'student',
      phone,
      isEmailVerified: false
    });

    // Add password to history
    user.addPasswordToHistory(hashedPassword);

    // Generate email verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');
    user.emailVerificationToken = verificationToken;
    user.emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    await user.save();

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user);

    logger.info('User registered successfully', {
      userId: user._id,
      email: user.email,
      role: user.role,
      ip: req.ip
    });

    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        isEmailVerified: user.isEmailVerified
      },
      tokens: {
        accessToken,
        refreshToken
      },
      emailVerificationRequired: true
    });

  } catch (error) {
    logger.error('Registration error', {
      error: error.message,
      stack: error.stack,
      ip: req.ip
    });

    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR'
    });
  }
};

// Login user
const login = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        code: 'VALIDATION_ERROR',
        details: errors.array()
      });
    }

    const { email, password } = req.body;

    // Find user
    const user = await User.findByEmail(email);
    if (!user) {
      return res.status(401).json({
        error: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS'
      });
    }

    // Check if account is locked
    if (user.isLocked) {
      return res.status(423).json({
        error: 'Account is temporarily locked due to too many failed login attempts',
        code: 'ACCOUNT_LOCKED',
        lockedUntil: user.accountLockedUntil
      });
    }

    // Check if account is active
    if (!user.isActive) {
      return res.status(401).json({
        error: 'Account is deactivated',
        code: 'ACCOUNT_DEACTIVATED'
      });
    }

    // Verify password
    const isValidPassword = await verifyPassword(password, user.password);
    if (!isValidPassword) {
      // Increment failed login attempts
      await user.incrementLoginAttempts();
      
      logger.warn('Failed login attempt', {
        userId: user._id,
        email: user.email,
        ip: req.ip
      });

      return res.status(401).json({
        error: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS'
      });
    }

    // Reset login attempts on successful login
    await user.resetLoginAttempts();

    // Update last login info
    user.lastLoginAt = new Date();
    user.lastLoginIP = req.ip;
    await user.save();

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user);

    logger.info('User logged in successfully', {
      userId: user._id,
      email: user.email,
      role: user.role,
      ip: req.ip
    });

    res.json({
      message: 'Login successful',
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        isEmailVerified: user.isEmailVerified
      },
      tokens: {
        accessToken,
        refreshToken
      }
    });

  } catch (error) {
    logger.error('Login error', {
      error: error.message,
      stack: error.stack,
      ip: req.ip
    });

    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR'
    });
  }
};

// Refresh access token
const refreshToken = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(401).json({
        error: 'Refresh token required',
        code: 'REFRESH_TOKEN_MISSING'
      });
    }

    // Verify refresh token
    const decoded = jwt.verify(refreshToken, JWT_SECRET);
    
    if (decoded.type !== 'refresh') {
      return res.status(401).json({
        error: 'Invalid refresh token',
        code: 'INVALID_REFRESH_TOKEN'
      });
    }

    // Find user
    const user = await User.findById(decoded.id);
    if (!user || !user.isActive) {
      return res.status(401).json({
        error: 'Invalid refresh token',
        code: 'INVALID_REFRESH_TOKEN'
      });
    }

    // Generate new tokens
    const tokens = generateTokens(user);

    logger.info('Token refreshed successfully', {
      userId: user._id,
      email: user.email,
      ip: req.ip
    });

    res.json({
      message: 'Token refreshed successfully',
      tokens
    });

  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Refresh token expired',
        code: 'REFRESH_TOKEN_EXPIRED'
      });
    }

    logger.error('Token refresh error', {
      error: error.message,
      stack: error.stack,
      ip: req.ip
    });

    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR'
    });
  }
};

// Logout user
const logout = async (req, res) => {
  try {
    // In a more sophisticated implementation, you might want to:
    // 1. Add the token to a blacklist
    // 2. Store refresh tokens in database and revoke them
    // 3. Clear any server-side sessions

    logger.info('User logged out', {
      userId: req.user._id,
      email: req.user.email,
      ip: req.ip
    });

    res.json({
      message: 'Logout successful'
    });

  } catch (error) {
    logger.error('Logout error', {
      error: error.message,
      stack: error.stack,
      ip: req.ip
    });

    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR'
    });
  }
};

// Request password reset
const requestPasswordReset = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        code: 'VALIDATION_ERROR',
        details: errors.array()
      });
    }

    const { email } = req.body;

    const user = await User.findByEmail(email);
    if (!user) {
      // Don't reveal if user exists or not
      return res.json({
        message: 'If an account with that email exists, a password reset link has been sent'
      });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    user.passwordResetToken = resetToken;
    user.passwordResetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
    await user.save();

    // In a real implementation, you would send an email here
    logger.info('Password reset requested', {
      userId: user._id,
      email: user.email,
      ip: req.ip
    });

    res.json({
      message: 'If an account with that email exists, a password reset link has been sent'
    });

  } catch (error) {
    logger.error('Password reset request error', {
      error: error.message,
      stack: error.stack,
      ip: req.ip
    });

    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR'
    });
  }
};

// Reset password
const resetPassword = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        code: 'VALIDATION_ERROR',
        details: errors.array()
      });
    }

    const { token, newPassword } = req.body;

    // Find user with valid reset token
    const user = await User.findOne({
      passwordResetToken: token,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({
        error: 'Invalid or expired reset token',
        code: 'INVALID_RESET_TOKEN'
      });
    }

    // Validate new password
    const passwordValidation = validatePassword(newPassword, user.passwordHistory);
    if (!passwordValidation.isValid) {
      return res.status(400).json({
        error: 'Password validation failed',
        code: 'PASSWORD_INVALID',
        details: passwordValidation.errors
      });
    }

    // Hash new password
    const hashedPassword = await hashPassword(newPassword);

    // Update user
    user.password = hashedPassword;
    user.addPasswordToHistory(hashedPassword);
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    logger.info('Password reset successfully', {
      userId: user._id,
      email: user.email,
      ip: req.ip
    });

    res.json({
      message: 'Password reset successfully'
    });

  } catch (error) {
    logger.error('Password reset error', {
      error: error.message,
      stack: error.stack,
      ip: req.ip
    });

    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR'
    });
  }
};

// Change password
const changePassword = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        code: 'VALIDATION_ERROR',
        details: errors.array()
      });
    }

    const { currentPassword, newPassword } = req.body;
    const user = req.user;

    // Verify current password
    const isValidPassword = await verifyPassword(currentPassword, user.password);
    if (!isValidPassword) {
      return res.status(400).json({
        error: 'Current password is incorrect',
        code: 'INVALID_CURRENT_PASSWORD'
      });
    }

    // Validate new password
    const passwordValidation = validatePassword(newPassword, user.passwordHistory);
    if (!passwordValidation.isValid) {
      return res.status(400).json({
        error: 'Password validation failed',
        code: 'PASSWORD_INVALID',
        details: passwordValidation.errors
      });
    }

    // Hash new password
    const hashedPassword = await hashPassword(newPassword);

    // Update user
    user.password = hashedPassword;
    user.addPasswordToHistory(hashedPassword);
    await user.save();

    logger.info('Password changed successfully', {
      userId: user._id,
      email: user.email,
      ip: req.ip
    });

    res.json({
      message: 'Password changed successfully'
    });

  } catch (error) {
    logger.error('Password change error', {
      error: error.message,
      stack: error.stack,
      ip: req.ip
    });

    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR'
    });
  }
};

module.exports = {
  register,
  login,
  refreshToken,
  logout,
  requestPasswordReset,
  resetPassword,
  changePassword
};
