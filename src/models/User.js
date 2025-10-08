const mongoose = require('mongoose');
const { USER_ROLES } = require('../config/auth');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: function() {
      return !this.ssoProvider; // Password required only if not SSO user
    }
  },
  role: {
    type: String,
    enum: Object.values(USER_ROLES),
    required: true,
    default: USER_ROLES.STUDENT
  },
  isActive: {
    type: Boolean,
    default: true
  },
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  emailVerificationToken: String,
  emailVerificationExpires: Date,
  
  // SSO Information
  ssoProvider: {
    type: String,
    enum: ['google', 'saml'],
    required: false
  },
  ssoId: String, // External SSO user ID
  
  // Password Management
  passwordHistory: [{
    password: String,
    createdAt: { type: Date, default: Date.now }
  }],
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  
  // Account Security
  failedLoginAttempts: {
    type: Number,
    default: 0
  },
  accountLockedUntil: Date,
  lastLoginAt: Date,
  lastLoginIP: String,
  
  // Profile Information
  firstName: {
    type: String,
    required: true,
    trim: true
  },
  lastName: {
    type: String,
    required: true,
    trim: true
  },
  phone: {
    type: String,
    trim: true
  },
  
  // FERPA Compliance
  ferpaConsent: {
    type: Boolean,
    default: false
  },
  ferpaConsentDate: Date,
  ferpaConsentIP: String,
  
  // Audit Trail
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  updatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for performance
userSchema.index({ email: 1 });
userSchema.index({ ssoProvider: 1, ssoId: 1 });
userSchema.index({ role: 1 });
userSchema.index({ isActive: 1 });

// Virtual for full name
userSchema.virtual('fullName').get(function() {
  return `${this.firstName} ${this.lastName}`;
});

// Virtual for account lock status
userSchema.virtual('isLocked').get(function() {
  return !!(this.accountLockedUntil && this.accountLockedUntil > Date.now());
});

// Pre-save middleware
userSchema.pre('save', function(next) {
  // Update password changed timestamp
  if (this.isModified('password') && !this.isNew) {
    this.passwordChangedAt = new Date();
  }
  next();
});

// Instance methods
userSchema.methods.incrementLoginAttempts = function() {
  // If we have a previous lock that has expired, restart at 1
  if (this.accountLockedUntil && this.accountLockedUntil < Date.now()) {
    return this.updateOne({
      $unset: { accountLockedUntil: 1 },
      $set: { failedLoginAttempts: 1 }
    });
  }
  
  const updates = { $inc: { failedLoginAttempts: 1 } };
  
  // Lock account after 5 failed attempts for 15 minutes
  if (this.failedLoginAttempts + 1 >= 5 && !this.isLocked) {
    updates.$set = { accountLockedUntil: Date.now() + 15 * 60 * 1000 }; // 15 minutes
  }
  
  return this.updateOne(updates);
};

userSchema.methods.resetLoginAttempts = function() {
  return this.updateOne({
    $unset: { failedLoginAttempts: 1, accountLockedUntil: 1 }
  });
};

userSchema.methods.addPasswordToHistory = function(newPassword) {
  // Keep only last 5 passwords
  const passwordHistory = [...this.passwordHistory];
  passwordHistory.push({
    password: newPassword,
    createdAt: new Date()
  });
  
  if (passwordHistory.length > 5) {
    passwordHistory.shift();
  }
  
  this.passwordHistory = passwordHistory;
};

// Static methods
userSchema.statics.findByEmail = function(email) {
  return this.findOne({ email: email.toLowerCase() });
};

userSchema.statics.findBySSO = function(provider, ssoId) {
  return this.findOne({ ssoProvider: provider, ssoId });
};

module.exports = mongoose.model('User', userSchema);
