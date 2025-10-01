const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_ACCESS_EXPIRES_IN = process.env.JWT_ACCESS_EXPIRES_IN || '15m';
const JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || '7d';
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS) || 12;

// Password validation rules
const PASSWORD_RULES = {
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true,
  preventReuse: 5, // Prevent reusing last 5 passwords
  maxAge: 90 // days
};

// Rate limiting configuration
const RATE_LIMITS = {
  login: {
    windowMs: 60 * 1000, // 1 minute
    max: 5, // 5 attempts per minute per IP
    message: 'Too many login attempts, please try again later.'
  },
  passwordReset: {
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 attempts per hour per email
    message: 'Too many password reset attempts, please try again later.'
  },
  tokenRefresh: {
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 100, // 100 refreshes per hour per user
    message: 'Too many token refresh attempts, please try again later.'
  },
  general: {
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 1000, // 1000 requests per hour per user
    message: 'Too many requests, please try again later.'
  }
};

// User roles and permissions
const USER_ROLES = {
  ADMIN: 'admin',
  TEACHER: 'teacher',
  SERVICE_PROVIDER: 'service_provider',
  PARENT: 'parent',
  STUDENT: 'student'
};

const ROLE_PERMISSIONS = {
  [USER_ROLES.ADMIN]: [
    'read:all_users',
    'write:all_users',
    'read:all_students',
    'write:all_students',
    'manage:roles',
    'manage:system'
  ],
  [USER_ROLES.TEACHER]: [
    'read:assigned_students',
    'write:assigned_students',
    'read:student_progress',
    'write:student_progress',
    'read:iep_documents'
  ],
  [USER_ROLES.SERVICE_PROVIDER]: [
    'read:assigned_students',
    'write:assigned_students',
    'read:iep_documents',
    'write:iep_documents',
    'read:disability_classifications'
  ],
  [USER_ROLES.PARENT]: [
    'read:own_children',
    'read:child_progress',
    'read:child_iep',
    'write:parent_contact_info'
  ],
  [USER_ROLES.STUDENT]: [
    'read:own_data',
    'read:own_progress',
    'write:own_preferences'
  ]
};

// FERPA compliance - directory information vs educational records
const FERPA_DATA_TYPES = {
  DIRECTORY_INFO: [
    'name',
    'email',
    'grade_level',
    'school_id',
    'current_classes'
  ],
  EDUCATIONAL_RECORDS: [
    'iep_documents',
    'disability_classification',
    'evaluations',
    'progress_monitoring_results',
    'parent_contact_info'
  ]
};

// JWT token generation
const generateTokens = (user) => {
  const payload = {
    id: user._id,
    email: user.email,
    role: user.role
  };

  const accessToken = jwt.sign(payload, JWT_SECRET, {
    expiresIn: JWT_ACCESS_EXPIRES_IN,
    issuer: 'impact-service',
    audience: 'impact-clients'
  });

  const refreshToken = jwt.sign(
    { id: user._id, type: 'refresh' },
    JWT_SECRET,
    {
      expiresIn: JWT_REFRESH_EXPIRES_IN,
      issuer: 'impact-service',
      audience: 'impact-clients'
    }
  );

  return { accessToken, refreshToken };
};

// Password hashing
const hashPassword = async (password) => {
  return await bcrypt.hash(password, BCRYPT_ROUNDS);
};

// Password verification
const verifyPassword = async (password, hashedPassword) => {
  return await bcrypt.compare(password, hashedPassword);
};

// Password validation
const validatePassword = (password, passwordHistory = []) => {
  const errors = [];

  if (password.length < PASSWORD_RULES.minLength) {
    errors.push(`Password must be at least ${PASSWORD_RULES.minLength} characters long`);
  }

  if (PASSWORD_RULES.requireUppercase && !/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }

  if (PASSWORD_RULES.requireLowercase && !/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }

  if (PASSWORD_RULES.requireNumbers && !/\d/.test(password)) {
    errors.push('Password must contain at least one number');
  }

  if (PASSWORD_RULES.requireSpecialChars && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }

  // Check password history
  for (const oldPassword of passwordHistory) {
    if (bcrypt.compareSync(password, oldPassword)) {
      errors.push('Password cannot be the same as any of your last 5 passwords');
      break;
    }
  }

  return {
    isValid: errors.length === 0,
    errors
  };
};

module.exports = {
  JWT_SECRET,
  JWT_ACCESS_EXPIRES_IN,
  JWT_REFRESH_EXPIRES_IN,
  PASSWORD_RULES,
  RATE_LIMITS,
  USER_ROLES,
  ROLE_PERMISSIONS,
  FERPA_DATA_TYPES,
  generateTokens,
  hashPassword,
  verifyPassword,
  validatePassword
};
