/** Jest config for pure unit tests (no MongoDB). */
module.exports = {
  testEnvironment: 'node',
  testMatch: ['**/tests/assurePrimitives.test.js'],
  collectCoverage: false,
  testTimeout: 10000,
  verbose: true
};
