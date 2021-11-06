import * as async from 'async';
import * as _ from 'lodash';
import 'source-map-support/register';

import { BlockChainExplorer } from './blockchainexplorer';
import { Lock } from './lock';
import { MessageBroker } from './messagebroker';
import { Notification } from './model';
import { IMasternode, Masternodes } from './model/masternodes';
import { WalletService } from './server';
import { Storage } from './storage';

const $ = require('preconditions').singleton();
const Mustache = require('mustache');
const fs = require('fs');
const path = require('path');
const Common = require('./common');
const Constants = Common.Constants;
const Utils = require('./common/utils');
const Defaults = require('./common/defaults');

let log = require('npmlog');
log.debug = log.verbose;

export class MasternodeService {
  explorers: any;
  storage: Storage;
  messageBroker: MessageBroker;
  lock: Lock;

  init(opts, cb) {
    opts = opts || {};

    async.parallel(
      [
        done => {
          this.explorers = {
            vcl: {}
          };

          const coinNetworkPairs = [];
          _.each(_.values(Constants.COINS), coin => {
            _.each(_.values(Constants.NETWORKS), network => {
              coinNetworkPairs.push({
                coin,
                network
              });
            });
          });
          _.each(coinNetworkPairs, pair => {
            if (pair.coin == 'vcl') {
              let explorer;
              if (
                opts.blockchainExplorers &&
                opts.blockchainExplorers[pair.coin] &&
                opts.blockchainExplorers[pair.coin][pair.network]
              ) {
                explorer = opts.blockchainExplorers[pair.coin][pair.network];
              } else {
                let config: { url?: string; provider?: any } = {};
                if (
                  opts.blockchainExplorerOpts &&
                  opts.blockchainExplorerOpts[pair.coin] &&
                  opts.blockchainExplorerOpts[pair.coin][pair.network]
                ) {
                  config = opts.blockchainExplorerOpts[pair.coin][pair.network];
                } else {
                  return;
                }

                explorer = BlockChainExplorer({
                  provider: config.provider,
                  coin: pair.coin,
                  network: pair.network,
                  url: config.url,
                  userAgent: WalletService.getServiceVersion()
                });
              }
              $.checkState(explorer);

              this.explorers[pair.coin][pair.network] = explorer;
            }
          });
          done();
        },
        done => {
          if (opts.storage) {
            this.storage = opts.storage;
            done();
          } else {
            this.storage = new Storage();
            this.storage.connect(
              {
                ...opts.storageOpts,
                secondaryPreferred: true
              },
              done
            );
          }
        },
        done => {
          this.messageBroker = opts.messageBroker || new MessageBroker(opts.messageBrokerOpts);
          done();
        },
        done => {
          this.lock = opts.lock || new Lock(opts.lockOpts);
          done();
        }
      ],
      err => {
        if (err) {
          log.error(err);
        }
        return cb(err);
      }
    );
  }

  startCron(opts, cb) {
    opts = opts || {};

    const interval = opts.fetchInterval || Defaults.MASTERNODE_STATUS_FETCH_INTERVAL;
    if (interval) {
      this._fetch();
      setInterval(() => {
        this._fetch();
      }, interval * 60 * 1000);
    }

    return cb();
  }

  _fetch(cb?) {
    cb = cb || function() {};
    const coins = ['vcl'];

    async.each(
      coins,
      (coin, next2) => {
        let explorer = this.explorers[coin]['livenet'];
        let network = 'livenet';
        let opts = {
          coin,
          network
        };
        explorer.getMasternodeStatus(opts, (err, res) => {
          if (err) {
            log.warn('Error retrieving masternode status for ' + coin, err);
            return next2();
          }
          this.updateMasternodes(coin, network, res, err => {
            if (err) {
              log.warn('Error storing masternode status for ' + coin, err);
            }
            return next2();
          });
        });
      },
      //        next),
      cb
    );
  }

  updateMasternodes(coin, network, masternodes, cb) {
    let imasternodes: Array<any> = [];
    _.forEach(_.keys(masternodes), function(key) {
      let masternodeStatus: {
        txid?: string;
        coin?: string;
        network?: string;
        address?: string;
        payee?: string;
        status?: string;
        protocol?: number;
        daemonversion?: string;
        sentinelversion?: string;
        sentinelstate?: string;
        lastseen?: number;
        activeseconds?: number;
        lastpaidtime?: number;
        lastpaidblock?: number;
        pingretries?: number;
      } = {};

      masternodeStatus.coin = coin;
      masternodeStatus.network = network;
      masternodeStatus.txid = key;
      masternodeStatus.address = masternodes[key].address;
      masternodeStatus.payee = masternodes[key].payee;
      masternodeStatus.status = masternodes[key].status;
      masternodeStatus.protocol = masternodes[key].protocol;
      masternodeStatus.daemonversion = masternodes[key].daemonversion;
      masternodeStatus.sentinelversion = masternodes[key].sentinelversion;
      masternodeStatus.sentinelstate = masternodes[key].sentinelstate;
      masternodeStatus.lastseen = masternodes[key].lastseen;
      masternodeStatus.activeseconds = masternodes[key].activeseconds;
      masternodeStatus.lastpaidtime = masternodes[key].lastpaidtime;
      masternodeStatus.lastpaidblock = masternodes[key].lastpaidblock;
      masternodeStatus.pingretries = masternodes[key].pingretries;
      let imasternode = Masternodes.create(masternodeStatus);
      imasternodes.push(imasternode);
    });
    for (const imasternode of imasternodes) {
      this.storage.fetchMasternodesFromTxId(imasternode.txid, (err, res) => {
        if (err) {
          log.warn('Error fetch masternode status for ' + coin + '-' + imasternode.txid, err);
        } else {
          if (res) {
            let oldStatus = res.status;
            this.storage.updateMasternode(imasternode, err => {
              if (err) {
                log.warn('Error update masternode status for ' + coin + '-' + imasternode.txid, err);
              } else {
                if (oldStatus != imasternode.status) {
                  const args = {
                    createdOn: imasternode.createdOn,
                    txid: imasternode.txid,
                    masternodeKey: res.masternodeKey,
                    coin: res.coin,
                    network: res.network,
                    address: imasternode.address,
                    payee: res.payee,
                    status: imasternode.status,
                    protocol: imasternode.protocol,
                    daemonversion: imasternode.daemonversion,
                    sentinelversion: imasternode.sentinelversion,
                    sentinelstate: imasternode.sentinelstate,
                    lastseen: imasternode.lastseen,
                    activeseconds: imasternode.activeseconds,
                    lastpaidtime: imasternode.lastpaidtime,
                    lastpaidblock: imasternode.lastpaidblock,
                    pingretries: imasternode.pingretries
                  };
                  const notification = Notification.create({
                    type: 'UpdateMasternode',
                    data: args,
                    walletId: res.walletId
                  });
                  this._storeAndBroadcastNotification(notification);
                }
              }
            });
          }
        }
      });
    }
    return cb();
  }

  _storeAndBroadcastNotification(notification, cb?: () => void) {
    this.storage.storeNotification(notification.walletId, notification, () => {
      this.messageBroker.send(notification);
      if (cb) return cb();
    });
  }
}

module.exports = MasternodeService;
