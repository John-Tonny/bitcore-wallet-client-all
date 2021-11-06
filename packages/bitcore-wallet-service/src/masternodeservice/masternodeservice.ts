#!/usr/bin/env node

var config = require('../config');
const MasternodeService = require('../lib/masternodeservice');
// const log = require('npmlog');
// log.debug = log.verbose;

const masternodeService = new MasternodeService();
masternodeService.init(config, err => {
  if (err) throw err;
  masternodeService.startCron(config, err => {
    if (err) throw err;

    console.log('masternode service started');
  });
});
