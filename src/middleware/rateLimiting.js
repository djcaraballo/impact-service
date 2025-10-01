const rateLimit = require('express-rate-limit');
const { RATE_LIMITS } = require('../config/auth');

// Login rate limiting
const loginLimiter = rateLimit({
  windowMs: RATE_LIMITS.login.windowMs,
  max: RATE_LIMITS.login.max,
  message: {
    error: RATE_LIMITS.login.message,
    code: 'RATE_LIMIT_EXCEEDED',
    retryAfter: Math.ceil(RATE_LIMITS.login.windowMs / 1000)
  },
  standardHeaders: true,
  legacyHeaders: false,
  // Skip successful requests
  skipSuccessfulRequests: true,
  // Custom key generator to use IP + email for more granular limiting
  keyGenerator: (req) => {
    const email = req.body?.email || req.query?.email || 'unknown';
    return `${req.ip}:${email}`;
  }
});

// Password reset rate limiting
const passwordResetLimiter = rateLimit({
  windowMs: RATE_LIMITS.passwordReset.windowMs,
  max: RATE_LIMITS.passwordReset.max,
  message: {
    error: RATE_LIMITS.passwordReset.message,
    code: 'RATE_LIMIT_EXCEEDED',
    retryAfter: Math.ceil(RATE_LIMITS.passwordReset.windowMs / 1000)
  },
  standardHeaders: true,
  legacyHeaders: false,
  // Custom key generator to use email
  keyGenerator: (req) => {
    const email = req.body?.email || req.query?.email || req.ip;
    return `password-reset:${email}`;
  }
});

// Token refresh rate limiting
const tokenRefreshLimiter = rateLimit({
  windowMs: RATE_LIMITS.tokenRefresh.windowMs,
  max: RATE_LIMITS.tokenRefresh.max,
  message: {
    error: RATE_LIMITS.tokenRefresh.message,
    code: 'RATE_LIMIT_EXCEEDED',
    retryAfter: Math.ceil(RATE_LIMITS.tokenRefresh.windowMs / 1000)
  },
  standardHeaders: true,
  legacyHeaders: false,
  // Custom key generator to use user ID if available
  keyGenerator: (req) => {
    const userId = req.user?.id || req.body?.userId || req.ip;
    return `token-refresh:${userId}`;
  }
});

// General API rate limiting
const generalLimiter = rateLimit({
  windowMs: RATE_LIMITS.general.windowMs,
  max: RATE_LIMITS.general.max,
  message: {
    error: RATE_LIMITS.general.message,
    code: 'RATE_LIMIT_EXCEEDED',
    retryAfter: Math.ceil(RATE_LIMITS.general.windowMs / 1000)
  },
  standardHeaders: true,
  legacyHeaders: false,
  // Custom key generator to use user ID if authenticated, otherwise IP
  keyGenerator: (req) => {
    return req.user?.id || req.ip;
  }
});

// Strict rate limiting for sensitive operations
const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3, // 3 attempts per 15 minutes
  message: {
    error: 'Too many attempts for this sensitive operation',
    code: 'STRICT_RATE_LIMIT_EXCEEDED',
    retryAfter: 900
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true
});

// Registration rate limiting
const registrationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 registrations per hour per IP
  message: {
    error: 'Too many registration attempts',
    code: 'REGISTRATION_RATE_LIMIT_EXCEEDED',
    retryAfter: 3600
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return `registration:${req.ip}`;
  }
});

// Email verification rate limiting
const emailVerificationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // 10 verification attempts per hour
  message: {
    error: 'Too many email verification attempts',
    code: 'EMAIL_VERIFICATION_RATE_LIMIT_EXCEEDED',
    retryAfter: 3600
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    const email = req.body?.email || req.query?.email || req.ip;
    return `email-verification:${email}`;
  }
});

module.exports = {
  loginLimiter,
  passwordResetLimiter,
  tokenRefreshLimiter,
  generalLimiter,
  strictLimiter,
  registrationLimiter,
  emailVerificationLimiter
};
