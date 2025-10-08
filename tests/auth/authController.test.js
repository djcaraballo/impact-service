const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../../src/server');
const User = require('../../src/models/User');
const { hashPassword } = require('../../src/config/auth');

describe('Auth Controller', () => {
  beforeAll(async () => {
    // Connect to test database
    const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/impact-service-test';
    await mongoose.connect(mongoUri);
  });

  afterAll(async () => {
    // Clean up and close connection
    await mongoose.connection.dropDatabase();
    await mongoose.connection.close();
  });

  beforeEach(async () => {
    // Clean up before each test
    await User.deleteMany({});
  });

  describe('POST /auth/register', () => {
    it('should register a new user successfully', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'TestPassword123!',
        firstName: 'John',
        lastName: 'Doe',
        role: 'student'
      };

      const response = await request(app)
        .post('/auth/register')
        .send(userData)
        .expect(201);

      expect(response.body.message).toBe('User registered successfully');
      expect(response.body.user.email).toBe(userData.email);
      expect(response.body.user.firstName).toBe(userData.firstName);
      expect(response.body.user.lastName).toBe(userData.lastName);
      expect(response.body.user.role).toBe(userData.role);
      expect(response.body.tokens.accessToken).toBeDefined();
      expect(response.body.tokens.refreshToken).toBeDefined();
      expect(response.body.emailVerificationRequired).toBe(true);
    });

    it('should reject registration with invalid email', async () => {
      const userData = {
        email: 'invalid-email',
        password: 'TestPassword123!',
        firstName: 'John',
        lastName: 'Doe'
      };

      const response = await request(app)
        .post('/auth/register')
        .send(userData)
        .expect(400);

      expect(response.body.error).toBe('Validation failed');
      expect(response.body.code).toBe('VALIDATION_ERROR');
    });

    it('should reject registration with weak password', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'weak',
        firstName: 'John',
        lastName: 'Doe'
      };

      const response = await request(app)
        .post('/auth/register')
        .send(userData)
        .expect(400);

      expect(response.body.error).toBe('Validation failed');
      expect(response.body.code).toBe('VALIDATION_ERROR');
    });

    it('should reject registration with existing email', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'TestPassword123!',
        firstName: 'John',
        lastName: 'Doe'
      };

      // Create user first
      await request(app)
        .post('/auth/register')
        .send(userData)
        .expect(201);

      // Try to register again with same email
      const response = await request(app)
        .post('/auth/register')
        .send(userData)
        .expect(409);

      expect(response.body.error).toBe('User already exists');
      expect(response.body.code).toBe('USER_EXISTS');
    });
  });

  describe('POST /auth/login', () => {
    beforeEach(async () => {
      // Create a test user
      const hashedPassword = await hashPassword('TestPassword123!');
      await User.create({
        email: 'test@example.com',
        password: hashedPassword,
        firstName: 'John',
        lastName: 'Doe',
        role: 'student',
        isEmailVerified: true
      });
    });

    it('should login user successfully', async () => {
      const loginData = {
        email: 'test@example.com',
        password: 'TestPassword123!'
      };

      const response = await request(app)
        .post('/auth/login')
        .send(loginData)
        .expect(200);

      expect(response.body.message).toBe('Login successful');
      expect(response.body.user.email).toBe(loginData.email);
      expect(response.body.tokens.accessToken).toBeDefined();
      expect(response.body.tokens.refreshToken).toBeDefined();
    });

    it('should reject login with invalid credentials', async () => {
      const loginData = {
        email: 'test@example.com',
        password: 'WrongPassword123!'
      };

      const response = await request(app)
        .post('/auth/login')
        .send(loginData)
        .expect(401);

      expect(response.body.error).toBe('Invalid credentials');
      expect(response.body.code).toBe('INVALID_CREDENTIALS');
    });

    it('should reject login with non-existent user', async () => {
      const loginData = {
        email: 'nonexistent@example.com',
        password: 'TestPassword123!'
      };

      const response = await request(app)
        .post('/auth/login')
        .send(loginData)
        .expect(401);

      expect(response.body.error).toBe('Invalid credentials');
      expect(response.body.code).toBe('INVALID_CREDENTIALS');
    });
  });

  describe('POST /auth/refresh-token', () => {
    let refreshToken;

    beforeEach(async () => {
      // Create a test user and get refresh token
      const hashedPassword = await hashPassword('TestPassword123!');
      const user = await User.create({
        email: 'test@example.com',
        password: hashedPassword,
        firstName: 'John',
        lastName: 'Doe',
        role: 'student',
        isEmailVerified: true
      });

      const loginResponse = await request(app)
        .post('/auth/login')
        .send({
          email: 'test@example.com',
          password: 'TestPassword123!'
        });

      refreshToken = loginResponse.body.tokens.refreshToken;
    });

    it('should refresh token successfully', async () => {
      const response = await request(app)
        .post('/auth/refresh-token')
        .send({ refreshToken })
        .expect(200);

      expect(response.body.message).toBe('Token refreshed successfully');
      expect(response.body.tokens.accessToken).toBeDefined();
      expect(response.body.tokens.refreshToken).toBeDefined();
    });

    it('should reject invalid refresh token', async () => {
      const response = await request(app)
        .post('/auth/refresh-token')
        .send({ refreshToken: 'invalid-token' })
        .expect(401);

      expect(response.body.error).toBe('Invalid refresh token');
      expect(response.body.code).toBe('INVALID_REFRESH_TOKEN');
    });
  });

  describe('POST /auth/change-password', () => {
    let accessToken;

    beforeEach(async () => {
      // Create a test user and get access token
      const hashedPassword = await hashPassword('TestPassword123!');
      await User.create({
        email: 'test@example.com',
        password: hashedPassword,
        firstName: 'John',
        lastName: 'Doe',
        role: 'student',
        isEmailVerified: true
      });

      const loginResponse = await request(app)
        .post('/auth/login')
        .send({
          email: 'test@example.com',
          password: 'TestPassword123!'
        });

      accessToken = loginResponse.body.tokens.accessToken;
    });

    it('should change password successfully', async () => {
      const response = await request(app)
        .post('/auth/change-password')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          currentPassword: 'TestPassword123!',
          newPassword: 'NewPassword123!'
        })
        .expect(200);

      expect(response.body.message).toBe('Password changed successfully');
    });

    it('should reject change password with wrong current password', async () => {
      const response = await request(app)
        .post('/auth/change-password')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          currentPassword: 'WrongPassword123!',
          newPassword: 'NewPassword123!'
        })
        .expect(400);

      expect(response.body.error).toBe('Current password is incorrect');
      expect(response.body.code).toBe('INVALID_CURRENT_PASSWORD');
    });

    it('should reject change password without authentication', async () => {
      const response = await request(app)
        .post('/auth/change-password')
        .send({
          currentPassword: 'TestPassword123!',
          newPassword: 'NewPassword123!'
        })
        .expect(401);

      expect(response.body.error).toBe('Access token required');
      expect(response.body.code).toBe('TOKEN_MISSING');
    });
  });
});
