const passport = require('passport');
const User = require('../models/User');
const { generateTokens } = require('../config/auth');
const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'logs/sso.log' })
  ]
});

// Google OAuth callback
const googleCallback = async (req, res) => {
  try {
    const { id, emails, name } = req.user;

    // Check if user exists with this Google ID
    let user = await User.findBySSO('google', id);

    if (user) {
      // Update last login
      user.lastLoginAt = new Date();
      user.lastLoginIP = req.ip;
      await user.save();

      logger.info('Google SSO login - existing user', {
        userId: user._id,
        email: user.email,
        ip: req.ip
      });
    } else {
      // Check if user exists with this email
      const email = emails[0].value;
      user = await User.findByEmail(email);

      if (user) {
        // Link Google account to existing user
        user.ssoProvider = 'google';
        user.ssoId = id;
        user.isEmailVerified = true;
        user.lastLoginAt = new Date();
        user.lastLoginIP = req.ip;
        await user.save();

        logger.info('Google SSO linked to existing user', {
          userId: user._id,
          email: user.email,
          ip: req.ip
        });
      } else {
        // Create new user
        user = new User({
          email: email,
          firstName: name.givenName,
          lastName: name.familyName,
          ssoProvider: 'google',
          ssoId: id,
          isEmailVerified: true,
          role: 'student', // Default role, can be changed by admin
          lastLoginAt: new Date(),
          lastLoginIP: req.ip
        });

        await user.save();

        logger.info('Google SSO - new user created', {
          userId: user._id,
          email: user.email,
          ip: req.ip
        });
      }
    }

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user);

    // Redirect to frontend with tokens
    const redirectUrl = `${process.env.FRONTEND_URL}/auth/callback?token=${accessToken}&refreshToken=${refreshToken}`;
    res.redirect(redirectUrl);

  } catch (error) {
    logger.error('Google SSO callback error', {
      error: error.message,
      stack: error.stack,
      ip: req.ip
    });

    const errorUrl = `${process.env.FRONTEND_URL}/auth/error?message=${encodeURIComponent('Authentication failed')}`;
    res.redirect(errorUrl);
  }
};

// SAML callback
const samlCallback = async (req, res) => {
  try {
    const { nameID, attributes } = req.user;

    // Extract user information from SAML attributes
    const email = attributes.email || attributes.mail || nameID;
    const firstName = attributes.firstName || attributes.givenName || attributes.first_name;
    const lastName = attributes.lastName || attributes.surname || attributes.last_name;
    const role = attributes.role || 'student';

    if (!email) {
      throw new Error('Email not provided in SAML response');
    }

    // Check if user exists with this SAML ID
    let user = await User.findBySSO('saml', nameID);

    if (user) {
      // Update last login
      user.lastLoginAt = new Date();
      user.lastLoginIP = req.ip;
      await user.save();

      logger.info('SAML SSO login - existing user', {
        userId: user._id,
        email: user.email,
        ip: req.ip
      });
    } else {
      // Check if user exists with this email
      user = await User.findByEmail(email);

      if (user) {
        // Link SAML account to existing user
        user.ssoProvider = 'saml';
        user.ssoId = nameID;
        user.isEmailVerified = true;
        user.lastLoginAt = new Date();
        user.lastLoginIP = req.ip;
        await user.save();

        logger.info('SAML SSO linked to existing user', {
          userId: user._id,
          email: user.email,
          ip: req.ip
        });
      } else {
        // Create new user
        user = new User({
          email: email,
          firstName: firstName || 'Unknown',
          lastName: lastName || 'User',
          ssoProvider: 'saml',
          ssoId: nameID,
          isEmailVerified: true,
          role: role,
          lastLoginAt: new Date(),
          lastLoginIP: req.ip
        });

        await user.save();

        logger.info('SAML SSO - new user created', {
          userId: user._id,
          email: user.email,
          ip: req.ip
        });
      }
    }

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user);

    // Redirect to frontend with tokens
    const redirectUrl = `${process.env.FRONTEND_URL}/auth/callback?token=${accessToken}&refreshToken=${refreshToken}`;
    res.redirect(redirectUrl);

  } catch (error) {
    logger.error('SAML SSO callback error', {
      error: error.message,
      stack: error.stack,
      ip: req.ip
    });

    const errorUrl = `${process.env.FRONTEND_URL}/auth/error?message=${encodeURIComponent('Authentication failed')}`;
    res.redirect(errorUrl);
  }
};

// Get SSO providers
const getSSOProviders = (req, res) => {
  const providers = [];

  if (process.env.GOOGLE_CLIENT_ID) {
    providers.push({
      name: 'google',
      displayName: 'Google',
      authUrl: '/auth/google'
    });
  }

  if (process.env.SAML_ENTRY_POINT) {
    providers.push({
      name: 'saml',
      displayName: 'School Login',
      authUrl: '/auth/saml'
    });
  }

  res.json({
    providers
  });
};

module.exports = {
  googleCallback,
  samlCallback,
  getSSOProviders
};
