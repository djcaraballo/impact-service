const express = require('express');
const { body } = require('express-validator');
const {
  register,
  login,
  refreshToken,
  logout,
  requestPasswordReset,
  resetPassword,
  changePassword
} = require('./authController');
const {
  loginLimiter,
  passwordResetLimiter,
  tokenRefreshLimiter,
  registrationLimiter
} = require('../middleware/rateLimiting');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

// Validation rules
const emailValidation = body('email')
  .isEmail()
  .normalizeEmail()
  .withMessage('Please provide a valid email address');

const passwordValidation = body('password')
  .isLength({ min: 12 })
  .withMessage('Password must be at least 12 characters long')
  .matches(/[A-Z]/)
  .withMessage('Password must contain at least one uppercase letter')
  .matches(/[a-z]/)
  .withMessage('Password must contain at least one lowercase letter')
  .matches(/\d/)
  .withMessage('Password must contain at least one number')
  .matches(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/)
  .withMessage('Password must contain at least one special character');

const nameValidation = body('firstName')
  .trim()
  .isLength({ min: 1, max: 50 })
  .withMessage('First name must be between 1 and 50 characters');

const lastNameValidation = body('lastName')
  .trim()
  .isLength({ min: 1, max: 50 })
  .withMessage('Last name must be between 1 and 50 characters');

const roleValidation = body('role')
  .optional()
  .isIn(['admin', 'teacher', 'service_provider', 'parent', 'student'])
  .withMessage('Invalid role specified');

const phoneValidation = body('phone')
  .optional()
  .isMobilePhone()
  .withMessage('Please provide a valid phone number');

// Public routes
router.post('/register',
  registrationLimiter,
  [
    emailValidation,
    passwordValidation,
    nameValidation,
    lastNameValidation,
    roleValidation,
    phoneValidation
  ],
  register
);

router.post('/login',
  loginLimiter,
  [
    emailValidation,
    body('password').notEmpty().withMessage('Password is required')
  ],
  login
);

router.post('/refresh-token',
  tokenRefreshLimiter,
  [
    body('refreshToken').notEmpty().withMessage('Refresh token is required')
  ],
  refreshToken
);

router.post('/request-password-reset',
  passwordResetLimiter,
  [emailValidation],
  requestPasswordReset
);

router.post('/reset-password',
  passwordResetLimiter,
  [
    body('token').notEmpty().withMessage('Reset token is required'),
    passwordValidation
  ],
  resetPassword
);

// Protected routes
router.post('/logout',
  authenticateToken,
  logout
);

router.post('/change-password',
  authenticateToken,
  [
    body('currentPassword').notEmpty().withMessage('Current password is required'),
    passwordValidation
  ],
  changePassword
);

module.exports = router;
