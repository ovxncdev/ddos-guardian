/**
 * Logging Index
 * 
 * Usage:
 *   const logger = require('./logging');
 *   logger.info('Hello', { key: 'value' });
 */

const logger = require('./logger');

module.exports = logger;
module.exports.Logger = logger.Logger;
module.exports.generateRequestId = logger.generateRequestId;
