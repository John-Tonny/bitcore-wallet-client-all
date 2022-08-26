#!/usr/bin/env node

var config = require('../config');
const MasternodeService = require('../lib/masternodeservice');
import logger from '../lib/logger';

const masternodeService = new MasternodeService();
masternodeService.init(config, err => {
  if (err) throw err;
  masternodeService.startCron(config, err => {
    if (err) throw err;

    logger.info('masternode service started');
  });
});
