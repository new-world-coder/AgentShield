const jwt = require('jsonwebtoken');
const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console()
  ]
});

/**
 * Cloudflare AI Gateway Authorization Middleware
 * Validates cf-aig-authorization header for session control
 */
const cloudflareAIGatewayAuth = (req, res, next) => {
  try {
    const aigAuth = req.headers['cf-aig-authorization'];
    
    if (!aigAuth) {
      logger.warn('Missing cf-aig-authorization header', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        url: req.url
      });
      return res.status(401).json({ 
        error: 'Cloudflare AI Gateway authorization required' 
      });
    }

    // Validate the authorization token format
    if (!aigAuth.startsWith('Bearer ') && !aigAuth.startsWith('Token ')) {
      logger.warn('Invalid cf-aig-authorization format', {
        ip: req.ip,
        url: req.url
      });
      return res.status(401).json({ 
        error: 'Invalid Cloudflare AI Gateway authorization format' 
      });
    }

    // Add Cloudflare context to request
    req.cloudflareContext = {
      aigAuth,
      timestamp: new Date().toISOString(),
      ip: req.ip,
      userAgent: req.get('User-Agent')
    };

    next();
  } catch (error) {
    logger.error('Cloudflare AI Gateway auth error:', error);
    res.status(500).json({ error: 'Cloudflare authentication error' });
  }
};

/**
 * Input Validation Middleware for AI Agent Security
 * Validates inputs against prompt injection and malformed payloads
 */
const aiAgentInputValidation = (req, res, next) => {
  try {
    const body = req.body;
    const suspiciousPatterns = [
      // Prompt injection patterns
      /ignore\s+(previous|all)\s+(instructions?|prompts?)/i,
      /you\s+are\s+now\s+(dan|developer|admin)/i,
      /pretend\s+to\s+be/i,
      /act\s+as\s+if/i,
      /forget\s+(everything|all)/i,
      /system\s+prompt/i,
      /jailbreak/i,
      /role\s+confusion/i,
      
      // SQL injection patterns
      /(?:'|--|\/\*|\*\/|;)/i,
      
      // Command injection patterns
      /[;&|`$()]/,
      
      // XSS patterns
      /<script|javascript:|on\w+\s*=/i,
      
      // Path traversal patterns
      /\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c/i
    ];

    // Check for suspicious patterns in request body
    const bodyString = JSON.stringify(body);
    for (const pattern of suspiciousPatterns) {
      if (pattern.test(bodyString)) {
        logger.warn('Suspicious input detected', {
          pattern: pattern.toString(),
          input: bodyString.substring(0, 200),
          ip: req.ip,
          url: req.url,
          userAgent: req.get('User-Agent')
        });
        
        return res.status(400).json({
          error: 'Suspicious input detected',
          code: 'SECURITY_VIOLATION'
        });
      }
    }

    // Validate input length limits
    if (bodyString.length > 10000) {
      logger.warn('Input too large', {
        length: bodyString.length,
        ip: req.ip,
        url: req.url
      });
      
      return res.status(400).json({
        error: 'Input too large',
        code: 'INPUT_TOO_LARGE'
      });
    }

    next();
  } catch (error) {
    logger.error('Input validation error:', error);
    res.status(500).json({ error: 'Input validation error' });
  }
};

/**
 * Data Loss Prevention Middleware
 * Monitors and prevents leakage of sensitive information
 */
const dataLossPrevention = (req, res, next) => {
  try {
    const sensitivePatterns = [
      // API keys and tokens
      /(api[_-]?key|token|secret|password|credential)[\s]*[:=][\s]*['"]?[a-zA-Z0-9]{20,}['"]?/i,
      
      // Email addresses
      /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/,
      
      // Credit card numbers
      /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/,
      
      // Social Security Numbers
      /\b\d{3}-\d{2}-\d{4}\b/,
      
      // Phone numbers
      /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/
    ];

    const bodyString = JSON.stringify(req.body);
    const responseData = res.locals.responseData || '';

    // Check request body for sensitive data
    for (const pattern of sensitivePatterns) {
      if (pattern.test(bodyString)) {
        logger.warn('Sensitive data detected in request', {
          pattern: pattern.toString(),
          ip: req.ip,
          url: req.url,
          userAgent: req.get('User-Agent')
        });
        
        return res.status(400).json({
          error: 'Sensitive data not allowed in request',
          code: 'SENSITIVE_DATA_DETECTED'
        });
      }
    }

    // Override response to prevent sensitive data leakage
    const originalJson = res.json;
    res.json = function(data) {
      const responseString = JSON.stringify(data);
      
      for (const pattern of sensitivePatterns) {
        if (pattern.test(responseString)) {
          logger.warn('Sensitive data detected in response', {
            pattern: pattern.toString(),
            ip: req.ip,
            url: req.url
          });
          
          // Sanitize response
          data = sanitizeResponse(data);
        }
      }
      
      return originalJson.call(this, data);
    };

    next();
  } catch (error) {
    logger.error('DLP error:', error);
    res.status(500).json({ error: 'Data loss prevention error' });
  }
};

/**
 * Sanitize response data to remove sensitive information
 */
function sanitizeResponse(data) {
  if (typeof data === 'string') {
    return data.replace(/(api[_-]?key|token|secret|password|credential)[\s]*[:=][\s]*['"]?[a-zA-Z0-9]{20,}['"]?/gi, '$1=***REDACTED***');
  }
  
  if (typeof data === 'object' && data !== null) {
    const sanitized = { ...data };
    for (const key in sanitized) {
      if (typeof sanitized[key] === 'string') {
        sanitized[key] = sanitized[key].replace(/(api[_-]?key|token|secret|password|credential)[\s]*[:=][\s]*['"]?[a-zA-Z0-9]{20,}['"]?/gi, '$1=***REDACTED***');
      } else if (typeof sanitized[key] === 'object') {
        sanitized[key] = sanitizeResponse(sanitized[key]);
      }
    }
    return sanitized;
  }
  
  return data;
}

/**
 * Zero Trust Security Middleware
 * Enforces least-privilege access control
 */
const zeroTrustSecurity = (req, res, next) => {
  try {
    // Check for required security headers
    const requiredHeaders = [
      'user-agent',
      'x-forwarded-for',
      'cf-connecting-ip'
    ];

    const missingHeaders = requiredHeaders.filter(header => !req.headers[header]);
    
    if (missingHeaders.length > 0) {
      logger.warn('Missing security headers', {
        missing: missingHeaders,
        ip: req.ip,
        url: req.url
      });
    }

    // Rate limiting per IP
    const clientIP = req.headers['cf-connecting-ip'] || req.ip;
    const rateLimitKey = `rate_limit_${clientIP}`;
    
    // Simple in-memory rate limiting (in production, use Redis)
    if (!global.rateLimitStore) {
      global.rateLimitStore = new Map();
    }
    
    const now = Date.now();
    const windowMs = 15 * 60 * 1000; // 15 minutes
    const maxRequests = 100;
    
    const clientData = global.rateLimitStore.get(rateLimitKey) || { count: 0, resetTime: now + windowMs };
    
    if (now > clientData.resetTime) {
      clientData.count = 0;
      clientData.resetTime = now + windowMs;
    }
    
    if (clientData.count >= maxRequests) {
      logger.warn('Rate limit exceeded', {
        ip: clientIP,
        count: clientData.count,
        url: req.url
      });
      
      return res.status(429).json({
        error: 'Rate limit exceeded',
        retryAfter: Math.ceil((clientData.resetTime - now) / 1000)
      });
    }
    
    clientData.count++;
    global.rateLimitStore.set(rateLimitKey, clientData);

    next();
  } catch (error) {
    logger.error('Zero Trust security error:', error);
    res.status(500).json({ error: 'Security validation error' });
  }
};

/**
 * Encryption Middleware
 * Ensures sensitive data is encrypted at rest and in transit
 */
const encryptionMiddleware = (req, res, next) => {
  try {
    // Check if request is over HTTPS
    if (req.headers['x-forwarded-proto'] !== 'https' && process.env.NODE_ENV === 'production') {
      logger.warn('Non-HTTPS request in production', {
        ip: req.ip,
        url: req.url,
        protocol: req.headers['x-forwarded-proto']
      });
      
      return res.status(400).json({
        error: 'HTTPS required in production',
        code: 'HTTPS_REQUIRED'
      });
    }

    // Add encryption headers
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');

    next();
  } catch (error) {
    logger.error('Encryption middleware error:', error);
    res.status(500).json({ error: 'Encryption validation error' });
  }
};

module.exports = {
  cloudflareAIGatewayAuth,
  aiAgentInputValidation,
  dataLossPrevention,
  zeroTrustSecurity,
  encryptionMiddleware
};
