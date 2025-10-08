const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const SamlStrategy = require('passport-saml').Strategy;

// Google OAuth Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/auth/google/callback"
}, (accessToken, refreshToken, profile, done) => {
  // This callback is handled in the route, not here
  return done(null, profile);
}));

// SAML Strategy
if (process.env.SAML_ENTRY_POINT) {
  passport.use(new SamlStrategy({
    entryPoint: process.env.SAML_ENTRY_POINT,
    issuer: process.env.SAML_ISSUER,
    cert: process.env.SAML_CERT,
    callbackUrl: `${process.env.BASE_URL}/auth/saml/callback`,
    identifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    // Additional SAML configuration options
    acceptedClockSkewMs: 5000,
    disableRequestedAuthnContext: true,
    // Attribute mapping
    attributeMap: {
      'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'email',
      'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname': 'firstName',
      'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname': 'lastName',
      'http://schemas.microsoft.com/identity/claims/role': 'role'
    }
  }, (profile, done) => {
    // This callback is handled in the route, not here
    return done(null, profile);
  }));
}

// Serialize user for session (not used in JWT auth, but required by passport)
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

module.exports = passport;
