// ==========================================
// Health Check Endpoint
// Add this near the top of index.js after middleware setup
// ==========================================

// Health check endpoint (no auth required)
app.get('/health', async (req, res) => {
  try {
    // Check database connection
    const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
    
    res.status(200).json({
      message: 'Server is healthy',
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development',
      database: dbStatus,
      uptime: process.uptime(),
      version: '1.0.0'
    });
  } catch (err) {
    res.status(503).json({
      message: 'Server health check failed',
      error: err.message
    });
  }
});

// ==========================================
// Status endpoint (for monitoring)
// ==========================================
app.get('/status', async (req, res) => {
  try {
    const status = {
      status: 'ok',
      timestamp: new Date().toISOString(),
      service: 'LoginLogout API',
      version: '1.0.0',
      environment: process.env.NODE_ENV,
      checks: {
        database: mongoose.connection.readyState === 1 ? '✓' : '✗',
        api: '✓',
        brevo: process.env.BREVO_API_KEY ? '✓' : '✗'
      },
      uptime: Math.floor(process.uptime()),
      memory: {
        used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + 'MB',
        total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024) + 'MB'
      }
    };

    res.status(200).json(status);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});
