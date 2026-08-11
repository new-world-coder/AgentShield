'use strict';

module.exports = {
  ...require('./runAudit'),
  pin: require('./pin'),
  scan: require('./scan'),
  firewall: require('./firewall'),
  pinRegistry: require('./pinRegistry')
};
