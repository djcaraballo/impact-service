# IMPACT Service

A FERPA-compliant authentication and user management system for educational platforms, built with Node.js, Express, GraphQL, and MongoDB.

## Features

### Authentication & Authorization
- **Email/Password Authentication** with strong password policies
- **Single Sign-On (SSO)** support for Google OAuth and SAML
- **JWT-based token management** with access and refresh tokens
- **Role-based access control** (Admin, Teacher, Service Provider, Parent, Student)
- **FERPA-compliant data handling** with proper consent management

### Security Features
- **Rate limiting** on all authentication endpoints
- **Account lockout** after failed login attempts
- **Password history** to prevent reuse
- **HTTPS enforcement** with HSTS headers
- **CSRF protection** and input validation
- **Audit logging** for security events

### User Management
- **Multi-role user system** with granular permissions
- **Student data management** with FERPA compliance
- **Parent-student relationships** with proper access controls
- **Profile management** and account settings

### API Design
- **REST API** for traditional HTTP operations
- **GraphQL API** for flexible data querying
- **Unified authentication** across both APIs
- **Real-time subscriptions** (GraphQL)

## Quick Start

### Prerequisites
- Node.js 16+ 
- MongoDB 4.4+
- npm or yarn

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd impact-service
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Environment setup**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` with your configuration:
   ```env
   # Server Configuration
   PORT=3000
   NODE_ENV=development
   
   # Database
   MONGODB_URI=mongodb://localhost:27017/impact-service
   
   # JWT Configuration
   JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
   JWT_ACCESS_EXPIRES_IN=15m
   JWT_REFRESH_EXPIRES_IN=7d
   
   # Google OAuth (optional)
   GOOGLE_CLIENT_ID=your-google-client-id
   GOOGLE_CLIENT_SECRET=your-google-client-secret
   
   # SAML Configuration (optional)
   SAML_ENTRY_POINT=your-saml-entry-point
   SAML_ISSUER=your-saml-issuer
   SAML_CERT=your-saml-certificate
   
   # Security
   BCRYPT_ROUNDS=12
   SESSION_SECRET=your-session-secret-change-this-in-production
   
   # CORS
   CORS_ORIGIN=http://localhost:3000
   FRONTEND_URL=http://localhost:3000
   BASE_URL=http://localhost:3000
   ```

4. **Start the server**
   ```bash
   # Development
   npm run dev
   
   # Production
   npm start
   ```

5. **Access the APIs**
   - REST API: `http://localhost:3000/auth/*`
   - GraphQL Playground: `http://localhost:3000/graphql`
   - Health Check: `http://localhost:3000/health`

## API Documentation

### REST Endpoints

#### Authentication
- `POST /auth/register` - Register new user
- `POST /auth/login` - User login
- `POST /auth/refresh-token` - Refresh access token
- `POST /auth/logout` - User logout
- `POST /auth/change-password` - Change password
- `POST /auth/request-password-reset` - Request password reset
- `POST /auth/reset-password` - Reset password with token

#### SSO
- `GET /auth/providers` - Get available SSO providers
- `GET /auth/google` - Google OAuth login
- `GET /auth/google/callback` - Google OAuth callback
- `GET /auth/saml` - SAML login
- `POST /auth/saml/callback` - SAML callback
- `GET /auth/saml/metadata` - SAML metadata

### GraphQL Schema

The GraphQL API provides a comprehensive schema for user and student management:

```graphql
type User {
  id: ID!
  email: String!
  firstName: String!
  lastName: String!
  role: UserRole!
  isActive: Boolean!
  isEmailVerified: Boolean!
  # ... more fields
}

type Student {
  id: ID!
  user: User!
  schoolId: String!
  gradeLevel: String!
  currentClasses: [Class!]!
  iepDocuments: [IEPDocument!]!
  # ... more fields
}
```

### Example GraphQL Queries

```graphql
# Get current user
query GetMe {
  me {
    id
    email
    firstName
    lastName
    role
  }
}

# Get students (role-based access)
query GetStudents {
  students {
    id
    schoolId
    gradeLevel
    user {
      firstName
      lastName
    }
  }
}

# Login mutation
mutation Login($input: LoginInput!) {
  login(input: $input) {
    user {
      id
      email
      role
    }
    tokens {
      accessToken
      refreshToken
    }
  }
}
```

## User Roles & Permissions

### Admin
- Full system access
- User management
- Role assignment
- System configuration

### Teacher
- Access assigned students
- View student progress
- Update student records
- Access IEP documents

### Service Provider
- Access assigned students
- Manage IEP documents
- Update disability classifications
- Progress monitoring

### Parent
- View own children's data
- Access child progress
- Update contact information
- View IEP documents (with consent)

### Student
- View own data
- Access own progress
- Update preferences
- Limited profile access

## FERPA Compliance

The system implements FERPA compliance through:

### Data Classification
- **Directory Information**: Name, email, grade level, school ID, current classes
- **Educational Records**: IEPs, evaluations, progress monitoring, parent contacts

### Access Controls
- Role-based data access
- Parent-student relationship validation
- Consent management
- Audit logging

### Security Measures
- Encrypted data transmission
- Secure password storage
- Session management
- Rate limiting

## Security Features

### Password Policy
- Minimum 12 characters
- Uppercase, lowercase, number, special character
- Password history (prevents reuse of last 5)
- Account lockout after 5 failed attempts

### Token Management
- Access tokens: 15-minute expiration
- Refresh tokens: 7-day expiration
- Automatic token rotation
- Secure token storage

### Rate Limiting
- Login attempts: 5 per minute per IP
- Password reset: 3 per hour per email
- Token refresh: 100 per hour per user
- General API: 1000 requests per hour per user

## Testing

Run the test suite:

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run with coverage
npm test -- --coverage
```

## Deployment

### Environment Variables
Ensure all required environment variables are set in production:

```bash
NODE_ENV=production
MONGODB_URI=mongodb://your-production-db
JWT_SECRET=your-production-jwt-secret
SESSION_SECRET=your-production-session-secret
```

### Security Checklist
- [ ] Change all default secrets
- [ ] Enable HTTPS
- [ ] Configure CORS properly
- [ ] Set up proper logging
- [ ] Configure rate limiting
- [ ] Enable security headers
- [ ] Set up monitoring

## Architecture

### Project Structure
```
src/
├── auth/                 # Authentication logic
│   ├── authController.js
│   ├── authRoutes.js
│   ├── ssoController.js
│   ├── ssoRoutes.js
│   └── passportConfig.js
├── config/              # Configuration files
│   ├── auth.js
│   └── database.js
├── graphql/             # GraphQL schema and resolvers
│   ├── schema.js
│   ├── resolvers.js
│   └── context.js
├── middleware/          # Express middleware
│   ├── auth.js
│   └── rateLimiting.js
├── models/              # MongoDB models
│   ├── User.js
│   └── Student.js
└── server.js           # Main server file
```

### Database Design
- **Users Collection**: Core user data and authentication
- **Students Collection**: Student-specific educational data
- **Proper indexing** for performance
- **Data validation** at schema level

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

For support and questions:
- Create an issue in the repository
- Contact the development team
- Check the documentation

---

**Note**: This system is designed for educational use and FERPA compliance. Ensure proper security measures are in place before production deployment.