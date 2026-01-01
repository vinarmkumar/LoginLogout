// ==========================================
// Global Error Handler Middleware
// ==========================================

const errorHandler = (err, req, res, next) => {
  const isDevelopment = process.env.NODE_ENV === 'development';

  // Default error values
  let status = err.status || 500;
  let message = err.message || 'Internal Server Error';
  let data = null;

  // Handle specific error types
  if (err.name === 'CastError') {
    status = 400;
    message = 'Invalid ID format';
  } else if (err.name === 'ValidationError') {
    status = 400;
    message = 'Validation error';
    data = Object.values(err.errors).map(e => e.message);
  } else if (err.code === 11000) {
    // MongoDB duplicate key error
    status = 409;
    const field = Object.keys(err.keyPattern)[0];
    message = `${field} already exists`;
  } else if (err.name === 'JsonWebTokenError') {
    status = 401;
    message = 'Invalid token';
  } else if (err.name === 'TokenExpiredError') {
    status = 401;
    message = 'Token expired';
  }

  // Log error details (for debugging)
  if (isDevelopment) {
    console.error('❌ Error:', {
      status,
      message,
      stack: err.stack
    });
  } else {
    // In production, log only important details
    console.error(`[${new Date().toISOString()}] Error: ${status} - ${message}`);
  }

  // Send response
  res.status(status).json({
    message,
    ...(isDevelopment && { error: err, data })
  });
};

// 404 Handler - Must be last middleware
const notFoundHandler = (req, res) => {
  res.status(404).json({
    message: `Route not found: ${req.method} ${req.path}`
  });
};

// Async error wrapper for route handlers
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

module.exports = {
  errorHandler,
  notFoundHandler,
  asyncHandler
};
