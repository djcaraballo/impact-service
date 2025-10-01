const User = require('../models/User');
const Student = require('../models/Student');
const { 
  generateTokens, 
  hashPassword, 
  verifyPassword, 
  validatePassword,
  USER_ROLES,
  ROLE_PERMISSIONS,
  FERPA_DATA_TYPES
} = require('../config/auth');
const { AuthenticationError, ForbiddenError, UserInputError } = require('apollo-server-express');
const crypto = require('crypto');

// Helper function to check permissions
const hasPermission = (user, permission) => {
  const userPermissions = ROLE_PERMISSIONS[user.role] || [];
  return userPermissions.includes(permission);
};

// Helper function to check if user can access student data
const canAccessStudent = async (user, studentId) => {
  if (user.role === USER_ROLES.ADMIN) return true;
  
  if (user.role === USER_ROLES.STUDENT) {
    const student = await Student.findById(studentId);
    return student && student.user.toString() === user._id.toString();
  }
  
  if (user.role === USER_ROLES.PARENT) {
    const student = await Student.findOne({
      _id: studentId,
      'parentContacts.parentId': user._id
    });
    return !!student;
  }
  
  if (user.role === USER_ROLES.TEACHER || user.role === USER_ROLES.SERVICE_PROVIDER) {
    const student = await Student.findOne({
      _id: studentId,
      'currentClasses.teacherId': user._id
    });
    return !!student;
  }
  
  return false;
};

const resolvers = {
  Query: {
    // User queries
    me: async (parent, args, { user }) => {
      if (!user) throw new AuthenticationError('Authentication required');
      return user;
    },

    user: async (parent, { id }, { user }) => {
      if (!user) throw new AuthenticationError('Authentication required');
      
      if (user.role !== USER_ROLES.ADMIN && user._id.toString() !== id) {
        throw new ForbiddenError('Insufficient permissions');
      }
      
      return await User.findById(id).select('-password -passwordHistory');
    },

    users: async (parent, { role, limit = 50, offset = 0 }, { user }) => {
      if (!user) throw new AuthenticationError('Authentication required');
      if (!hasPermission(user, 'read:all_users')) {
        throw new ForbiddenError('Insufficient permissions');
      }
      
      const filter = role ? { role } : {};
      return await User.find(filter)
        .select('-password -passwordHistory')
        .limit(limit)
        .skip(offset)
        .sort({ createdAt: -1 });
    },

    // Student queries
    student: async (parent, { id }, { user }) => {
      if (!user) throw new AuthenticationError('Authentication required');
      
      if (!(await canAccessStudent(user, id))) {
        throw new ForbiddenError('Insufficient permissions to access this student');
      }
      
      return await Student.findById(id).populate('user');
    },

    students: async (parent, { gradeLevel, limit = 50, offset = 0 }, { user }) => {
      if (!user) throw new AuthenticationError('Authentication required');
      
      if (user.role === USER_ROLES.STUDENT) {
        // Students can only see their own data
        const student = await Student.findOne({ user: user._id });
        return student ? [student] : [];
      }
      
      if (user.role === USER_ROLES.PARENT) {
        // Parents can see their children
        return await Student.find({ 'parentContacts.parentId': user._id })
          .populate('user')
          .limit(limit)
          .skip(offset);
      }
      
      if (user.role === USER_ROLES.TEACHER) {
        // Teachers can see their assigned students
        return await Student.find({ 'currentClasses.teacherId': user._id })
          .populate('user')
          .limit(limit)
          .skip(offset);
      }
      
      if (user.role === USER_ROLES.SERVICE_PROVIDER) {
        // Service providers can see their assigned students
        return await Student.find({ 'currentClasses.teacherId': user._id })
          .populate('user')
          .limit(limit)
          .skip(offset);
      }
      
      // Admin can see all students
      const filter = gradeLevel ? { gradeLevel } : {};
      return await Student.find(filter)
        .populate('user')
        .limit(limit)
        .skip(offset)
        .sort({ createdAt: -1 });
    },

    myStudents: async (parent, args, { user }) => {
      if (!user) throw new AuthenticationError('Authentication required');
      
      if (user.role === USER_ROLES.PARENT) {
        return await Student.find({ 'parentContacts.parentId': user._id }).populate('user');
      }
      
      if (user.role === USER_ROLES.TEACHER || user.role === USER_ROLES.SERVICE_PROVIDER) {
        return await Student.find({ 'currentClasses.teacherId': user._id }).populate('user');
      }
      
      throw new ForbiddenError('Insufficient permissions');
    },

    studentBySchoolId: async (parent, { schoolId }, { user }) => {
      if (!user) throw new AuthenticationError('Authentication required');
      
      const student = await Student.findOne({ schoolId }).populate('user');
      if (!student) return null;
      
      if (!(await canAccessStudent(user, student._id))) {
        throw new ForbiddenError('Insufficient permissions to access this student');
      }
      
      return student;
    },

    // SSO queries
    ssoProviders: async () => {
      const providers = [];
      
      if (process.env.GOOGLE_CLIENT_ID) {
        providers.push({
          name: 'GOOGLE',
          displayName: 'Google',
          authUrl: '/auth/google'
        });
      }
      
      if (process.env.SAML_ENTRY_POINT) {
        providers.push({
          name: 'SAML',
          displayName: 'School Login',
          authUrl: '/auth/saml'
        });
      }
      
      return providers;
    }
  },

  Mutation: {
    // Authentication mutations
    register: async (parent, { input }, { req }) => {
      const { email, password, firstName, lastName, role, phone } = input;
      
      // Check if user already exists
      const existingUser = await User.findByEmail(email);
      if (existingUser) {
        throw new UserInputError('User already exists');
      }
      
      // Validate password
      const passwordValidation = validatePassword(password);
      if (!passwordValidation.isValid) {
        throw new UserInputError(`Password validation failed: ${passwordValidation.errors.join(', ')}`);
      }
      
      // Hash password
      const hashedPassword = await hashPassword(password);
      
      // Create user
      const user = new User({
        email,
        password: hashedPassword,
        firstName,
        lastName,
        role: role || USER_ROLES.STUDENT,
        phone,
        isEmailVerified: false
      });
      
      // Add password to history
      user.addPasswordToHistory(hashedPassword);
      
      // Generate email verification token
      const verificationToken = crypto.randomBytes(32).toString('hex');
      user.emailVerificationToken = verificationToken;
      user.emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);
      
      await user.save();
      
      // Generate tokens
      const tokens = generateTokens(user);
      
      return {
        user: {
          id: user._id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
          isEmailVerified: user.isEmailVerified
        },
        tokens,
        message: 'User registered successfully'
      };
    },

    login: async (parent, { input }, { req }) => {
      const { email, password } = input;
      
      // Find user
      const user = await User.findByEmail(email);
      if (!user) {
        throw new UserInputError('Invalid credentials');
      }
      
      // Check if account is locked
      if (user.isLocked) {
        throw new ForbiddenError('Account is temporarily locked');
      }
      
      // Check if account is active
      if (!user.isActive) {
        throw new ForbiddenError('Account is deactivated');
      }
      
      // Verify password
      const isValidPassword = await verifyPassword(password, user.password);
      if (!isValidPassword) {
        await user.incrementLoginAttempts();
        throw new UserInputError('Invalid credentials');
      }
      
      // Reset login attempts
      await user.resetLoginAttempts();
      
      // Update last login info
      user.lastLoginAt = new Date();
      user.lastLoginIP = req.ip;
      await user.save();
      
      // Generate tokens
      const tokens = generateTokens(user);
      
      return {
        user: {
          id: user._id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
          isEmailVerified: user.isEmailVerified
        },
        tokens,
        message: 'Login successful'
      };
    },

    refreshToken: async (parent, { refreshToken }, { req }) => {
      const jwt = require('jsonwebtoken');
      const { JWT_SECRET } = require('../config/auth');
      
      try {
        const decoded = jwt.verify(refreshToken, JWT_SECRET);
        
        if (decoded.type !== 'refresh') {
          throw new AuthenticationError('Invalid refresh token');
        }
        
        const user = await User.findById(decoded.id);
        if (!user || !user.isActive) {
          throw new AuthenticationError('Invalid refresh token');
        }
        
        return generateTokens(user);
      } catch (error) {
        throw new AuthenticationError('Invalid or expired refresh token');
      }
    },

    logout: async (parent, args, { user }) => {
      if (!user) throw new AuthenticationError('Authentication required');
      return 'Logout successful';
    },

    changePassword: async (parent, { input }, { user }) => {
      if (!user) throw new AuthenticationError('Authentication required');
      
      const { currentPassword, newPassword } = input;
      
      // Verify current password
      const isValidPassword = await verifyPassword(currentPassword, user.password);
      if (!isValidPassword) {
        throw new UserInputError('Current password is incorrect');
      }
      
      // Validate new password
      const passwordValidation = validatePassword(newPassword, user.passwordHistory);
      if (!passwordValidation.isValid) {
        throw new UserInputError(`Password validation failed: ${passwordValidation.errors.join(', ')}`);
      }
      
      // Hash new password
      const hashedPassword = await hashPassword(newPassword);
      
      // Update user
      user.password = hashedPassword;
      user.addPasswordToHistory(hashedPassword);
      await user.save();
      
      return 'Password changed successfully';
    },

    requestPasswordReset: async (parent, { email }) => {
      const user = await User.findByEmail(email);
      if (!user) {
        // Don't reveal if user exists
        return 'If an account with that email exists, a password reset link has been sent';
      }
      
      // Generate reset token
      const resetToken = crypto.randomBytes(32).toString('hex');
      user.passwordResetToken = resetToken;
      user.passwordResetExpires = new Date(Date.now() + 60 * 60 * 1000);
      await user.save();
      
      // In a real implementation, send email here
      return 'If an account with that email exists, a password reset link has been sent';
    },

    resetPassword: async (parent, { token, newPassword }) => {
      const user = await User.findOne({
        passwordResetToken: token,
        passwordResetExpires: { $gt: Date.now() }
      });
      
      if (!user) {
        throw new UserInputError('Invalid or expired reset token');
      }
      
      // Validate new password
      const passwordValidation = validatePassword(newPassword, user.passwordHistory);
      if (!passwordValidation.isValid) {
        throw new UserInputError(`Password validation failed: ${passwordValidation.errors.join(', ')}`);
      }
      
      // Hash new password
      const hashedPassword = await hashPassword(newPassword);
      
      // Update user
      user.password = hashedPassword;
      user.addPasswordToHistory(hashedPassword);
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save();
      
      return 'Password reset successfully';
    },

    // Profile mutations
    updateProfile: async (parent, { input }, { user }) => {
      if (!user) throw new AuthenticationError('Authentication required');
      
      const { firstName, lastName, phone } = input;
      
      if (firstName) user.firstName = firstName;
      if (lastName) user.lastName = lastName;
      if (phone !== undefined) user.phone = phone;
      
      await user.save();
      
      return user;
    },

    provideFerpaConsent: async (parent, args, { user, req }) => {
      if (!user) throw new AuthenticationError('Authentication required');
      
      user.ferpaConsent = true;
      user.ferpaConsentDate = new Date();
      user.ferpaConsentIP = req.ip;
      await user.save();
      
      return user;
    },

    // Student mutations
    createStudent: async (parent, { input }, { user }) => {
      if (!user) throw new AuthenticationError('Authentication required');
      if (!hasPermission(user, 'write:all_students')) {
        throw new ForbiddenError('Insufficient permissions');
      }
      
      const { userId, schoolId, gradeLevel } = input;
      
      // Check if student already exists
      const existingStudent = await Student.findOne({ 
        $or: [{ user: userId }, { schoolId }] 
      });
      if (existingStudent) {
        throw new UserInputError('Student already exists');
      }
      
      const student = new Student({
        user: userId,
        schoolId,
        gradeLevel,
        createdBy: user._id
      });
      
      await student.save();
      return await Student.findById(student._id).populate('user');
    },

    updateStudent: async (parent, { id, input }, { user }) => {
      if (!user) throw new AuthenticationError('Authentication required');
      
      if (!(await canAccessStudent(user, id))) {
        throw new ForbiddenError('Insufficient permissions to update this student');
      }
      
      const student = await Student.findById(id);
      if (!student) {
        throw new UserInputError('Student not found');
      }
      
      const { schoolId, gradeLevel } = input;
      
      if (schoolId) student.schoolId = schoolId;
      if (gradeLevel) student.gradeLevel = gradeLevel;
      
      student.updatedBy = user._id;
      await student.save();
      
      return await Student.findById(student._id).populate('user');
    },

    addProgressEntry: async (parent, { input }, { user }) => {
      if (!user) throw new AuthenticationError('Authentication required');
      
      const { studentId, area, goal, currentLevel, targetLevel, progress, notes } = input;
      
      if (!(await canAccessStudent(user, studentId))) {
        throw new ForbiddenError('Insufficient permissions to add progress entry');
      }
      
      const student = await Student.findById(studentId);
      if (!student) {
        throw new UserInputError('Student not found');
      }
      
      const progressEntry = {
        date: new Date(),
        area,
        goal,
        currentLevel,
        targetLevel,
        progress,
        notes,
        recordedBy: user._id
      };
      
      student.progressMonitoring.push(progressEntry);
      await student.save();
      
      return progressEntry;
    },

    // User management (admin only)
    updateUserRole: async (parent, { userId, role }, { user }) => {
      if (!user) throw new AuthenticationError('Authentication required');
      if (user.role !== USER_ROLES.ADMIN) {
        throw new ForbiddenError('Admin access required');
      }
      
      const targetUser = await User.findById(userId);
      if (!targetUser) {
        throw new UserInputError('User not found');
      }
      
      targetUser.role = role;
      targetUser.updatedBy = user._id;
      await targetUser.save();
      
      return targetUser;
    },

    deactivateUser: async (parent, { userId }, { user }) => {
      if (!user) throw new AuthenticationError('Authentication required');
      if (user.role !== USER_ROLES.ADMIN) {
        throw new ForbiddenError('Admin access required');
      }
      
      const targetUser = await User.findById(userId);
      if (!targetUser) {
        throw new UserInputError('User not found');
      }
      
      targetUser.isActive = false;
      targetUser.updatedBy = user._id;
      await targetUser.save();
      
      return targetUser;
    },

    activateUser: async (parent, { userId }, { user }) => {
      if (!user) throw new AuthenticationError('Authentication required');
      if (user.role !== USER_ROLES.ADMIN) {
        throw new ForbiddenError('Admin access required');
      }
      
      const targetUser = await User.findById(userId);
      if (!targetUser) {
        throw new UserInputError('User not found');
      }
      
      targetUser.isActive = true;
      targetUser.updatedBy = user._id;
      await targetUser.save();
      
      return targetUser;
    }
  },

  // Field resolvers
  User: {
    fullName: (user) => `${user.firstName} ${user.lastName}`
  },

  Student: {
    activeIEP: (student) => {
      return student.iepDocuments.find(doc => 
        doc.documentType === 'IEP' && doc.isActive
      );
    },
    
    primaryParent: (student) => {
      return student.parentContacts.find(contact => contact.isPrimary);
    }
  }
};

module.exports = resolvers;
