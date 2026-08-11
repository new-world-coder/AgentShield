const express = require('express');
const router = express.Router();
const TestResult = require('../models/TestResult');
const TestSuite = require('../models/TestSuite');
const { findingsToSarif } = require('../services/assure/sarif');

/**
 * POST /api/results/sarif
 * Convert oracle/finding payloads to SARIF 2.1.0 (CI-friendly)
 */
router.post('/sarif', async (req, res) => {
  try {
    const body = req.body || {};
    const findings = body.findings || body.oracles || body.tests || [];
    const sarif = findingsToSarif(findings, {
      toolName: body.toolName || 'agentshield',
      toolVersion: body.toolVersion
    });
    res.setHeader('Content-Type', 'application/sarif+json');
    res.json(sarif);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * GET /api/results
 * Get test results with filtering and pagination
 */
router.get('/', async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 10, 
      status, 
      testSuiteId, 
      severity,
      startDate,
      endDate,
      sortBy = 'startTime',
      sortOrder = 'desc'
    } = req.query;

    const query = { executedBy: req.user.id };

    // Add filters
    if (status) {
      query.status = status;
    }

    if (testSuiteId) {
      query.testSuiteId = testSuiteId;
    }

    if (severity) {
      query['summary.vulnerabilities.severity'] = severity;
    }

    if (startDate || endDate) {
      query.startTime = {};
      if (startDate) {
        query.startTime.$gte = new Date(startDate);
      }
      if (endDate) {
        query.startTime.$lte = new Date(endDate);
      }
    }

    // Build sort object
    const sort = {};
    sort[sortBy] = sortOrder === 'desc' ? -1 : 1;

    const results = await TestResult.find(query)
      .populate('testSuiteId', 'name description')
      .sort(sort)
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await TestResult.countDocuments(query);

    res.json({
      results,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * GET /api/results/:id
 * Get a specific test result
 */
router.get('/:id', async (req, res) => {
  try {
    const result = await TestResult.findOne({
      _id: req.params.id,
      executedBy: req.user.id
    }).populate('testSuiteId', 'name description categories');

    if (!result) {
      return res.status(404).json({ error: 'Test result not found' });
    }

    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * DELETE /api/results/:id
 * Delete a test result
 */
router.delete('/:id', async (req, res) => {
  try {
    const result = await TestResult.findOneAndDelete({
      _id: req.params.id,
      executedBy: req.user.id
    });

    if (!result) {
      return res.status(404).json({ error: 'Test result not found' });
    }

    res.json({ message: 'Test result deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * GET /api/results/export/:id
 * Export test result as CSV or JSON
 */
router.get('/export/:id', async (req, res) => {
  try {
    const { format = 'json' } = req.query;
    const result = await TestResult.findOne({
      _id: req.params.id,
      executedBy: req.user.id
    }).populate('testSuiteId', 'name description');

    if (!result) {
      return res.status(404).json({ error: 'Test result not found' });
    }

    if (format === 'csv') {
      // Convert to CSV format
      const csv = convertToCSV(result);
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="test-result-${result.executionId}.csv"`);
      res.send(csv);
    } else if (format === 'sarif') {
      const findings = [];
      const cases = result.results || result.testCases || [];
      for (const tc of cases) {
        if (Array.isArray(tc.oracles)) {
          findings.push(...tc.oracles);
        } else if (tc.passed === false) {
          findings.push({
            rule_id: tc.name || tc.testName || 'test_failure',
            message: tc.evidence || tc.message || 'Test failed',
            severity: tc.severity || 'Medium',
            impact: tc.impact || 'hygiene',
            confidence: tc.confidence != null ? tc.confidence : 0.4,
            taxonomy: tc.taxonomy || [],
            evidence: tc.evidence || '',
            passed: false
          });
        }
      }
      const sarif = findingsToSarif(findings);
      res.setHeader('Content-Type', 'application/sarif+json');
      res.setHeader('Content-Disposition', `attachment; filename="test-result-${result.executionId}.sarif.json"`);
      res.json(sarif);
    } else {
      // Return as JSON
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="test-result-${result.executionId}.json"`);
      res.json(result);
    }

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * GET /api/results/dashboard/stats
 * Get dashboard statistics
 */
router.get('/dashboard/stats', async (req, res) => {
  try {
    const { period = '30d' } = req.query;
    
    // Calculate date range
    const now = new Date();
    let startDate;
    
    switch (period) {
      case '7d':
        startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        break;
      case '30d':
        startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
        break;
      case '90d':
        startDate = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
        break;
      default:
        startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    }

    const query = {
      executedBy: req.user.id,
      startTime: { $gte: startDate }
    };

    // Get basic stats
    const totalExecutions = await TestResult.countDocuments(query);
    const completedExecutions = await TestResult.countDocuments({
      ...query,
      status: 'completed'
    });
    const failedExecutions = await TestResult.countDocuments({
      ...query,
      status: 'failed'
    });

    // Get vulnerability stats
    const vulnerabilityStats = await TestResult.aggregate([
      { $match: query },
      { $unwind: '$summary.vulnerabilities' },
      {
        $group: {
          _id: '$summary.vulnerabilities.severity',
          count: { $sum: 1 }
        }
      }
    ]);

    // Get test category stats
    const categoryStats = await TestResult.aggregate([
      { $match: query },
      { $unwind: '$tests' },
      {
        $group: {
          _id: '$tests.category',
          total: { $sum: 1 },
          passed: {
            $sum: { $cond: [{ $eq: ['$tests.status', 'passed'] }, 1, 0] }
          },
          failed: {
            $sum: { $cond: [{ $eq: ['$tests.status', 'failed'] }, 1, 0] }
          }
        }
      }
    ]);

    // Get execution trends (daily)
    const trendData = await TestResult.aggregate([
      { $match: query },
      {
        $group: {
          _id: {
            year: { $year: '$startTime' },
            month: { $month: '$startTime' },
            day: { $dayOfMonth: '$startTime' }
          },
          count: { $sum: 1 },
          vulnerabilities: {
            $sum: { $size: '$summary.vulnerabilities' }
          }
        }
      },
      { $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1 } }
    ]);

    res.json({
      period,
      totalExecutions,
      completedExecutions,
      failedExecutions,
      successRate: totalExecutions > 0 ? (completedExecutions / totalExecutions) * 100 : 0,
      vulnerabilityStats: vulnerabilityStats.reduce((acc, stat) => {
        acc[stat._id] = stat.count;
        return acc;
      }, {}),
      categoryStats,
      trendData
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * GET /api/results/dashboard/coverage
 * Get test coverage information
 */
router.get('/dashboard/coverage', async (req, res) => {
  try {
    const testSuites = await TestSuite.find({ createdBy: req.user.id });
    const testResults = await TestResult.find({
      executedBy: req.user.id,
      status: 'completed'
    }).populate('testSuiteId', 'name categories');

    // Calculate coverage metrics
    const coverage = {
      totalTestSuites: testSuites.length,
      executedTestSuites: new Set(testResults.map(r => r.testSuiteId._id.toString())).size,
      totalTests: testSuites.reduce((sum, suite) => 
        sum + suite.categories.reduce((catSum, cat) => catSum + cat.tests.length, 0), 0
      ),
      executedTests: testResults.reduce((sum, result) => sum + result.summary.total, 0),
      vulnerabilities: testResults.reduce((sum, result) => 
        sum + result.summary.vulnerabilities.length, 0
      )
    };

    coverage.coveragePercentage = coverage.totalTests > 0 
      ? (coverage.executedTests / coverage.totalTests) * 100 
      : 0;

    res.json(coverage);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Convert test result to CSV format
 */
function convertToCSV(result) {
  const headers = [
    'Execution ID',
    'Test Suite',
    'Test Name',
    'Category',
    'Status',
    'Duration (ms)',
    'Vulnerability Type',
    'Severity',
    'Description',
    'Start Time',
    'End Time'
  ];

  const rows = [headers.join(',')];

  result.tests.forEach(test => {
    if (test.vulnerability && test.vulnerability.detected) {
      rows.push([
        result.executionId,
        `"${result.testSuiteId.name}"`,
        `"${test.name}"`,
        test.category,
        test.status,
        test.duration || 0,
        `"${test.vulnerability.type}"`,
        test.vulnerability.severity,
        `"${test.vulnerability.description}"`,
        test.startTime,
        test.endTime
      ].join(','));
    } else {
      rows.push([
        result.executionId,
        `"${result.testSuiteId.name}"`,
        `"${test.name}"`,
        test.category,
        test.status,
        test.duration || 0,
        '',
        '',
        '',
        test.startTime,
        test.endTime
      ].join(','));
    }
  });

  return rows.join('\n');
}

module.exports = router;
