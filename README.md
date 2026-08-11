# AgentShield

A comprehensive developer tool for detecting and testing loopholes in agentic AI applications. AgentShield provides a web-based UI for creating, managing, and executing security tests against AI systems.

NOTE-Cloning and reuse are allowed only by approved contributors under CLA.
## 🚀 Features

- **Dynamic Test Case Creation**: Define and customize tests for user input validation, API endpoint fuzzing, and agentic workflow analysis
- **Test Categories**: 
  - **Input Injection Testing**: SQL injection, XSS, command injection, path traversal
  - **API Fuzzing**: Authentication bypass, rate limiting, input validation, CORS testing
  - **Agentic Workflow Testing**: Prompt injection, role confusion, data exfiltration, jailbreaking
- **Configuration UI**: Add/edit/remove test cases, set payloads, authentication, and rate limits
- **Execution Controls**: Run tests sequentially or in parallel with abort/clear options
- **Result Dashboard**: Real-time logs, summary tables, detailed results, and vulnerability visualization
- **Export Capabilities**: Download test results as CSV/JSON
- **Template Library**: Pre-built test templates for common security scenarios
- **Real-time Monitoring**: Live test execution monitoring with progress tracking
- **Agent Plugin API**: Test any HTTP or OpenAI-compatible agent with structured risk reports
- **Risk Scoring Engine**: CVSS-style risk assessment with severity buckets and trend analysis
- **Automated Remediation**: AI-powered suggestions for fixing identified vulnerabilities
- **Benchmark Suite**: Pre-built test agents demonstrating security vulnerabilities and controls
- **Threat Model**: Comprehensive security framework covering all agentic AI attack vectors

## 🛠 Tech Stack

- **Backend**: Node.js with Express
- **Frontend**: Next.js with React and TypeScript
- **UI Components**: Material-UI (MUI)
- **Database**: MongoDB with Mongoose
- **Authentication**: JWT-based with bcrypt
- **Testing**: Jest for backend, React Testing Library for frontend
- **Charts**: Recharts for data visualization
- **Python SDK** (`python/agentshield`): MCP firewall (pin/scan/audit/policy), AgentBOM, action oracles, mutational packs, SARIF (Phase 0 + Phase 1)
- **MCP Security Gate**: Schema pins, rug-pull drift detection, poisoning scan, allowlist policy, GitHub Action CI gate — see [`docs/MCP_SECURITY.md`](docs/MCP_SECURITY.md)

## Strategy

AgentShield is evolving into an **Open Agent Security Fabric** (Assure + Enforce + Govern). See [`docs/STRATEGY.md`](docs/STRATEGY.md) and the refreshed [`docs/threat-model.md`](docs/threat-model.md) (OWASP LLM + Agentic + MCP Top 10).

**Priority:** MCP firewall first (Python-first runtime primitives), then adaptive Assure expansion. Phase 1 MCP audit/API/CI is documented in [`docs/MCP_SECURITY.md`](docs/MCP_SECURITY.md).

## 🚀 Quick Start

1. **Clone the repository:**
```bash
git clone https://github.com/your-org/agentshield.git
cd agentshield
```

2. **Install dependencies:**
```bash
npm install
```

3. **Set up environment variables:**
```bash
cp env.example .env
# Edit .env with your configuration
```

4. **Start MongoDB:**
```bash
# On macOS with Homebrew
brew services start mongodb-community

# On Ubuntu/Debian
sudo systemctl start mongod

# On Windows
net start MongoDB
```

5. **Start the development servers:**
```bash
npm run dev
```

6. **Open your browser:**
Navigate to `http://localhost:3000`

## 📁 Project Structure

```
agentshield/
├── client/                 # Next.js frontend application
│   ├── src/
│   │   ├── components/     # Reusable UI components
│   │   ├── contexts/       # React contexts for state management
│   │   ├── pages/          # Next.js pages and routing
│   │   └── utils/          # Utility functions
├── server/                 # Express backend API
│   ├── models/             # MongoDB models
│   ├── routes/             # API route handlers
│   ├── services/           # Business logic services
│   └── middleware/         # Express middleware
├── docs/                   # Documentation
├── examples/               # Sample test suites and configurations
└── tests/                  # Test files and fixtures
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the root directory:

```env
# Server Configuration
PORT=5000
NODE_ENV=development

# Database
MONGODB_URI=mongodb://localhost:27017/agentshield

# JWT Secret (change this in production)
JWT_SECRET=your-super-secret-jwt-key

# Client URL (for CORS)
CLIENT_URL=http://localhost:3000

# API URL (for client)
API_URL=http://localhost:5000/api
```

## 📖 Usage

### Creating Your First Test Suite

1. **Register/Login** to the application
2. **Navigate to Test Suites** in the sidebar
3. **Click "Create Test Suite"**
4. **Fill in basic information:**
   - Name: "My AI API Security Tests"
   - Description: "Comprehensive security testing for my AI API"
   - Tags: "api", "security", "production"

5. **Add test categories:**
   - Choose from Input Injection, API Fuzzing, or Agentic Workflow
   - Configure test cases with target URLs and payloads
   - Set expected responses and validation rules

6. **Run your tests:**
   - Click "Run" on your test suite
   - Monitor real-time execution progress
   - Review detailed results and vulnerabilities

### Using Templates

1. **Navigate to Templates** in the sidebar
2. **Browse available templates** by category
3. **Click "Use Template"** on a template you want to use
4. **Customize the configuration** (target URL, headers, etc.)
5. **Click "Create Test Suite"** to add it to your test suites

### Analyzing Results

1. **Navigate to Results** to see all test executions
2. **Click on a result** to see detailed information
3. **Review vulnerabilities** by severity level (Critical, High, Medium, Low)
4. **Export results** as CSV or JSON for further analysis

## 🔒 Security Features

- **JWT Authentication**: Secure user authentication and session management
- **Input Validation**: Comprehensive input validation using Joi
- **Rate Limiting**: API rate limiting to prevent abuse
- **CORS Protection**: Configurable CORS settings
- **Helmet Security**: Security headers and protection middleware
- **Password Hashing**: bcrypt for secure password storage

## 🧪 Test Categories

### Input Injection Testing
- **SQL Injection**: Test for SQL injection vulnerabilities
- **XSS**: Test for cross-site scripting vulnerabilities  
- **Command Injection**: Test for command injection vulnerabilities
- **Path Traversal**: Test for directory traversal vulnerabilities
- **LDAP Injection**: Test for LDAP injection vulnerabilities
- **NoSQL Injection**: Test for NoSQL injection vulnerabilities

### API Fuzzing
- **Authentication Bypass**: Test for authentication vulnerabilities
- **Authorization Issues**: Test for authorization bypass
- **Rate Limit Testing**: Test API rate limiting mechanisms
- **Input Validation**: Test API input validation
- **Error Handling**: Test error handling and information disclosure
- **CORS Testing**: Test CORS configuration

### Agentic Workflow Testing
- **Prompt Injection**: Test for prompt injection vulnerabilities
- **Role Confusion**: Test for role confusion attacks
- **Data Exfiltration**: Test for data exfiltration vulnerabilities
- **Jailbreaking**: Test for AI model jailbreaking
- **Context Manipulation**: Test for context manipulation attacks
- **System Prompt Extraction**: Test for system prompt extraction

## 📊 Dashboard Features

- **Real-time Statistics**: Test execution counts, success rates, vulnerability counts
- **Visual Charts**: Pie charts for vulnerability distribution, bar charts for test performance
- **Recent Results**: Quick access to recent test executions
- **Coverage Metrics**: Test coverage and execution statistics
- **Export Options**: Download results in multiple formats

## 🔧 API Documentation

The AgentShield API provides comprehensive endpoints for:

- **Authentication**: User registration, login, profile management
- **Test Suites**: CRUD operations for test suites
- **Test Execution**: Running tests and monitoring execution
- **Results**: Retrieving and exporting test results
- **Configuration**: Templates, payloads, and settings

See [API Documentation](docs/API.md) for detailed endpoint information.

## 🤖 Agent Testing

AgentShield provides comprehensive security testing for AI agents through multiple adapters and test suites.

### Supported Agent Types

- **HTTP Agents**: Test any agent accessible via HTTP endpoints
- **OpenAI Compatible**: Test OpenAI, Anthropic, and other compatible language models
- **Mock Agents**: Development and testing with simulated responses

### Security Test Suite

- **Prompt Injection**: Detect attempts to override system instructions
- **System Prompt Extraction**: Identify system prompt leakage
- **Data Exfiltration**: Prevent sensitive data exposure
- **Role Confusion**: Detect unauthorized role changes
- **Jailbreaking**: Identify safety constraint bypass attempts
- **Tool Abuse**: Prevent unauthorized command execution
- **Context Manipulation**: Protect conversation history integrity
- **API Abuse**: Detect rate limiting and quota violations
- **Privilege Escalation**: Prevent unauthorized access escalation
- **Input Validation**: Test input sanitization and validation
- **Output Sanitization**: Verify response filtering and content safety
- **Performance Impact**: Measure security control overhead

### Risk Assessment

- **CVSS-style Scoring**: 0-100 risk score with severity buckets
- **Trend Analysis**: Track security improvements over time
- **Automated Remediation**: AI-powered fix suggestions with code examples
- **Executive Reports**: Business impact assessment and recommendations

### Example Usage

```bash
# Test an HTTP agent
curl -X POST http://localhost:5000/api/agents/run \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "name": "my-agent",
    "adapter": "http",
    "config": {
      "url": "https://my-agent.com/api/respond",
      "method": "POST",
      "headers": {"Authorization": "Bearer API_KEY"}
    },
    "tests": ["prompt-injection", "data-exfiltration", "role-confusion"]
  }'

# Get results
curl http://localhost:5000/api/agents/results/EXECUTION_ID \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## 🧪 Running Agent Benchmarks

AgentShield includes pre-built benchmark agents to demonstrate security testing:

1. **Start the vulnerable agent:**
```bash
npm run example:vulnerable-agent
# Runs on http://localhost:6001
```

2. **Start the secure agent:**
```bash
npm run example:secure-agent
# Runs on http://localhost:6002
```

3. **Run the benchmark suite:**
```bash
npm run test:benchmarks
# Tests both agents and generates reports
```

4. **Run specific agentic tests:**
```bash
npm run test:agentic
# Runs comprehensive agentic workflow tests
```

## 🔌 Chrome Extension

AgentShield includes a Chrome extension for real-time security testing directly in your browser.

### Building the Extension

1. **Build the extension:**
```bash
npm run extension:build
# Creates dist/ folder with extension files
```

2. **Load in Chrome:**
- Open Chrome and go to `chrome://extensions/`
- Enable "Developer mode"
- Click "Load unpacked" and select `client/extension/dist`

3. **Use the extension:**
- Visit ChatGPT, Claude, or Bard
- Click the AgentShield extension icon
- Click "Scan Current Tab" to test the agent
- View results with risk scores and remediation suggestions

### Extension Features

- **Real-time Scanning**: Test AI agents directly from supported websites
- **Multiple Test Types**: Prompt injection, data exfiltration, role confusion, jailbreaking
- **Risk Assessment**: CVSS-style scoring with severity buckets
- **Offline & Online Modes**: Works with local tests or remote API
- **Scan History**: Track and export results over time
- **Supported Platforms**: ChatGPT, Claude, Bard, and other LLM interfaces

See [Extension Documentation](docs/extension.md) for detailed usage instructions.

## 🚀 Deployment

### Production Deployment

1. **Set production environment variables**
2. **Configure MongoDB for production**
3. **Set up reverse proxy (nginx)**
4. **Configure SSL certificates**
5. **Set up monitoring and logging**

### Docker Deployment

```bash
# Build the application
docker-compose build

# Start the services
docker-compose up -d
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔒 Security

If you discover a security vulnerability, please report it to security@agentshield.dev.

## 📞 Support

- **Documentation**: [docs.agentshield.dev](https://docs.agentshield.dev)
- **Issues**: [GitHub Issues](https://github.com/your-org/agentshield/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/agentshield/discussions)
- **Getting Started**: [Getting Started Guide](docs/GETTING_STARTED.md)

## 🙏 Acknowledgments

- Built with ❤️ for the AI security community
- Inspired by OWASP testing methodologies
- Powered by the open-source community
