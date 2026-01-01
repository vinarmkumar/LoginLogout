// ========================================
// Production Deployment Configuration
// ========================================

const config = {
  // JWT Configuration
  jwt: {
    expiry: process.env.JWT_EXPIRY || '1h',
    secret: process.env.JWT_SECRET,
    refreshExpiry: process.env.JWT_REFRESH_EXPIRY || '7d'
  },

  // Password Configuration
  password: {
    minLength: 8,
    bcryptRounds: 12,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: false
  },

  // Email Configuration
  email: {
    verificationExpiry: 5 * 60 * 1000, // 5 minutes
    resendCooldown: 30 * 1000, // 30 seconds
    maxAttempts: 3
  },

  // Account Lockout Configuration
  security: {
    maxLoginAttempts: 3,
    lockoutDuration: 15 * 60 * 1000, // 15 minutes
    passwordResetExpiry: 30 * 60 * 1000 // 30 minutes
  },

  // Rate Limiting Configuration
  rateLimit: {
    general: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100 // requests per window
    },
    auth: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 5 // requests per window
    },
    email: {
      windowMs: 60 * 1000, // 1 minute
      max: 3 // requests per window
    }
  },

  // CORS Configuration
  cors: {
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 3600
  },

  // Server Configuration
  server: {
    port: process.env.PORT || 3000,
    env: process.env.NODE_ENV || 'development',
    isProduction: process.env.NODE_ENV === 'production'
  },

  // Database Configuration
  database: {
    mongoUri: process.env.DB_CONNECT_KEY,
    useNewUrlParser: true,
    useUnifiedTopology: true,
    maxPoolSize: 10,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000
  },

  // Cookie Configuration
  cookies: {
    token: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 60 * 60 * 1000, // 1 hour
      signed: true
    },
    tempUser: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 5 * 60 * 1000, // 5 minutes
      signed: true
    }
  },

  // API Configuration
  api: {
    maxRequestSize: '10kb',
    defaultTimeout: 30000 // 30 seconds
  },

  // Logging Configuration
  logging: {
    level: process.env.LOG_LEVEL || 'info',
    format: 'combined'
  }
};

module.exports = config;
