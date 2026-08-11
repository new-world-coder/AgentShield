const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');
const winston = require('winston');

// Import routes
const authRoutes = require('./routes/auth');
const testRoutes = require('./routes/tests');
const resultRoutes = require('./routes/results');
const configRoutes = require('./routes/config');
const cloudflareRoutes = require('./routes/cloudflare');
const agentAdapterRoutes = require('./routes/agentAdapters');

// Import middleware
const { authMiddleware } = require('./middleware/auth');
const { errorHandler } = require('./middleware/errorHandler');
const {
  cloudflareAIGatewayAuth,
  aiAgentInputValidation,
  dataLossPrevention,
  zeroTrustSecurity,
  encryptionMiddleware
} = require('./middleware/cloudflareSecurity');

// Import test execution engine
const TestExecutor = require('./services/TestExecutor');

const app = express();
const PORT = process.env.PORT || 5000;

// Configure logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:3000',
  credentials: true
}));

// Cloudflare AI Agent Security Middleware
app.use(encryptionMiddleware);
app.use(zeroTrustSecurity);
app.use(aiAgentInputValidation);
app.use(dataLossPrevention);

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Initialize test executor
const testExecutor = new TestExecutor();

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/tests', cloudflareAIGatewayAuth, authMiddleware, testRoutes);
app.use('/api/results', cloudflareAIGatewayAuth, authMiddleware, resultRoutes);
app.use('/api/config', cloudflareAIGatewayAuth, authMiddleware, configRoutes);
app.use('/api/cloudflare', cloudflareAIGatewayAuth, authMiddleware, cloudflareRoutes);
app.use('/api/agents', cloudflareAIGatewayAuth, authMiddleware, agentAdapterRoutes);

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// Error handling middleware
app.use(errorHandler);

// Database connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/agentshield', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  logger.info('Connected to MongoDB');
})
.catch((error) => {
  logger.error('MongoDB connection error:', error);
  process.exit(1);
});

// Start server
app.listen(PORT, () => {
  logger.info(`AgentShield server running on port ${PORT}`);
  console.log(`🚀 AgentShield server running on port ${PORT}`);
});

module.exports = app;
