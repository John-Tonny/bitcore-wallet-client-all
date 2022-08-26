import { constant } from 'async';
import * as async from 'async';
import * as _ from 'lodash';
import 'source-map-support/register';
import logger from './logger';

import { BlockChainExplorer } from './blockchainexplorer';
import { V8 } from './blockchainexplorers/v8';
import { ChainService } from './chain/index';
import { ClientError } from './errors/clienterror';
import { FiatRateService } from './fiatrateservice';
import { Lock } from './lock';
import { MessageBroker } from './messagebroker';
import {
  Advertisement,
  Copayer,
  IMasternode,
  INotification,
  ITxProposal,
  IWallet,
  Masternodes,
  Notification,
  Preferences,
  PushNotificationSub,
  Session,
  TxConfirmationSub,
  TxNote,
  TxProposal,
  Wallet
} from './model';
import { Storage } from './storage';

const config = require('../config');
const Uuid = require('uuid');
const $ = require('preconditions').singleton();
const deprecatedServerMessage = require('../deprecated-serverMessages');
const serverMessages = require('../serverMessages');
const BCHAddressTranslator = require('./bchaddresstranslator');

const EmailValidator = require('email-validator');

import { Deriver, Validation, Web3 } from 'crypto-wallet-core';
const Bitcore = require('bitcore-lib');
const Bitcore_ = {
  btc: require('bitcore-lib'),
  bch: require('bitcore-lib-cash'),
  eth: require('bitcore-lib'),
  xrp: require('bitcore-lib'),
  doge: require('bitcore-lib-doge'),
  ltc: require('bitcore-lib-ltc'),
  vcl: require('bitcore-lib-vcl')
};

const Common = require('./common');
const Utils = Common.Utils;
const Constants = Common.Constants;
const Defaults = Common.Defaults;
const Services = Common.Services;

const Errors = require('./errors/errordefinitions');

let request = require('request');

// john 20220709
const sjs = require('syscoinjs-lib');
const stxjs = require('syscointx-js');
const syscoinjs = new sjs.SyscoinJSLib(null, config.blockbookUrl);
const bitcoinProof = require('bitcoin-proof');
const web3 = new Web3(config.web3Url);

let initialized = false;
let doNotCheckV8 = false;

let lock;
let storage;
let blockchainExplorer;
let blockchainExplorerOpts;
let messageBroker;
let fiatRateService;
let serviceVersion;

interface IAddress {
  coin: string;
  network: string;
  address: string;
  hasActivity: boolean;
  isChange?: boolean;
}

export interface IWalletService {
  lock: any;
  storage: Storage;
  blockchainExplorer: any;
  blockchainExplorerOpts: any;
  messageBroker: any;
  fiatRateService: any;
  notifyTicker: number;
  userAgent: string;
  walletId: string;
  copayerId: string;
  appName: string;
  appVersion: string;
  parsedClientVersion: { agent: number; major: number; minor: number };
  clientVersion: string;
  copayerIsSupportStaff: boolean;
  copayerIsMarketingStaff: boolean;
}
function boolToNum(x: boolean) {
  return x ? 1 : 0;
}
/**
 * Creates an instance of the Bitcore Wallet Service.
 * @constructor
 */
export class WalletService {
  lock: any;
  storage: Storage;
  blockchainExplorer: V8;
  blockchainExplorerOpts: any;
  messageBroker: any;
  fiatRateService: any;
  notifyTicker: number;
  userAgent: string;
  walletId: string;
  copayerId: string;
  appName: string;
  appVersion: string;
  parsedClientVersion: { agent: string; major: number; minor: number };
  clientVersion: string;
  copayerIsSupportStaff: boolean;
  copayerIsMarketingStaff: boolean;
  request;

  constructor() {
    if (!initialized) {
      throw new Error('Server not initialized');
    }

    this.lock = lock;
    this.storage = storage;
    this.blockchainExplorer = blockchainExplorer;
    this.blockchainExplorerOpts = blockchainExplorerOpts;
    this.messageBroker = messageBroker;
    this.fiatRateService = fiatRateService;
    this.notifyTicker = 0;
    // for testing
    //
    this.request = request;
  }
  /**
   * Gets the current version of BWS
   */
  static getServiceVersion() {
    if (!serviceVersion) {
      serviceVersion = 'bws-' + require('../../package').version;
    }

    return serviceVersion;
  }

  /**
   * Initializes global settings for all instances.
   * @param {Object} opts
   * @param {Storage} [opts.storage] - The storage provider.
   * @param {Storage} [opts.blockchainExplorer] - The blockchainExporer provider.
   * @param {Storage} [opts.doNotCheckV8] - only for testing
   * @param {Callback} cb
   */
  static initialize(opts, cb) {
    $.shouldBeFunction(cb, '');

    opts = opts || {};
    blockchainExplorer = opts.blockchainExplorer;
    blockchainExplorerOpts = opts.blockchainExplorerOpts;

    doNotCheckV8 = opts.doNotCheckV8;

    if (opts.request) {
      request = opts.request;
    }

    const initStorage = cb => {
      if (opts.storage) {
        storage = opts.storage;
        return cb();
      } else {
        const newStorage = new Storage();
        newStorage.connect(opts.storageOpts, err => {
          if (err) {
            return cb(err);
          }
          storage = newStorage;
          return cb();
        });
      }
    };

    const initMessageBroker = cb => {
      messageBroker = opts.messageBroker || new MessageBroker(opts.messageBrokerOpts);
      if (messageBroker) {
        messageBroker.onMessage(WalletService.handleIncomingNotifications);
      }

      return cb();
    };

    const initFiatRateService = cb => {
      if (opts.fiatRateService) {
        fiatRateService = opts.fiatRateService;
        return cb();
      } else {
        const newFiatRateService = new FiatRateService();
        const opts2 = opts.fiatRateServiceOpts || {};
        opts2.storage = storage;
        newFiatRateService.init(opts2, err => {
          if (err) {
            return cb(err);
          }

          fiatRateService = newFiatRateService;
          return cb();
        });
      }
    };

    async.series(
      [
        next => {
          initStorage(next);
        },
        next => {
          initMessageBroker(next);
        },
        next => {
          initFiatRateService(next);
        }
      ],
      err => {
        lock = opts.lock || new Lock(storage);

        if (err) {
          logger.error('Could not initialize', err);
          throw err;
        }
        initialized = true;
        return cb();
      }
    );
  }

  static handleIncomingNotifications(notification, cb) {
    cb = cb || function() {};

    // do nothing here....
    // bc height cache is cleared on bcmonitor
    return cb();
  }

  static shutDown(cb) {
    if (!initialized) {
      return cb();
    }

    storage.disconnect(err => {
      if (err) {
        return cb(err);
      }

      initialized = false;
      return cb();
    });
  }

  /**
   * Gets an instance of the server without authentication.
   * @param {Object} opts
   * @param {string} opts.clientVersion - A string that identifies the client issuing the request
   */
  static getInstance(opts): WalletService {
    opts = opts || {};

    const version = Utils.parseVersion(opts.clientVersion);
    if (version && version.agent === 'bwc') {
      if (version.major === 0 || (version.major === 1 && version.minor < 2)) {
        throw new ClientError(Errors.codes.UPGRADE_NEEDED, 'BWC clients < 1.2 are no longer supported.');
      }
    }

    const server = new WalletService();
    server._setClientVersion(opts.clientVersion);
    server._setAppVersion(opts.userAgent);
    server.userAgent = opts.userAgent;
    return server;
  }

  /**
   * Gets an instance of the server after authenticating the copayer.
   * @param {Object} opts
   * @param {string} opts.copayerId - The copayer id making the request.
   * @param {string} opts.message - (Optional) The contents of the request to be signed.
   *  Only needed if no session token is provided.
   * @param {string} opts.signature - (Optional) Signature of message to be verified using
   * one of the copayer's requestPubKeys.
   * Only needed if no session token is provided.
   * @param {string} opts.session - (Optional) A valid session token previously obtained using
   * the #login method
   * @param {string} opts.clientVersion - A string that identifies the client issuing the request
   * @param {string} [opts.walletId] - The wallet id to use as current wallet
   * for this request (only when copayer is support staff).
   */
  static getInstanceWithAuth(opts, cb) {
    const withSignature = cb => {
      if (!checkRequired(opts, ['copayerId', 'message', 'signature'], cb)) {
        return;
      }

      let server: WalletService;
      try {
        server = WalletService.getInstance(opts);
      } catch (ex) {
        return cb(ex);
      }

      server.storage.fetchCopayerLookup(opts.copayerId, (err, copayer) => {
        if (err) {
          return cb(err);
        }
        if (!copayer) {
          return cb(new ClientError(Errors.codes.NOT_AUTHORIZED, 'Copayer not found'));
        }

        const isValid = !!server._getSigningKey(opts.message, opts.signature, copayer.requestPubKeys);
        if (!isValid) {
          return cb(new ClientError(Errors.codes.NOT_AUTHORIZED, 'Invalid signature'));
        }

        server.walletId = copayer.walletId;

        // allow overwrite walletid if the copayer is from the support team
        if (copayer.isSupportStaff) {
          server.walletId = opts.walletId || copayer.walletId;
          server.copayerIsSupportStaff = true;
        }
        if (copayer.isMarketingStaff) {
          server.copayerIsMarketingStaff = true;
        }

        server.copayerId = opts.copayerId;
        return cb(null, server);
      });
    };

    const withSession = cb => {
      if (!checkRequired(opts, ['copayerId', 'session'], cb)) {
        return;
      }

      let server;
      try {
        server = WalletService.getInstance(opts);
      } catch (ex) {
        return cb(ex);
      }

      server.storage.getSession(opts.copayerId, (err, s) => {
        if (err) {
          return cb(err);
        }

        const isValid = s && s.id === opts.session && s.isValid();
        if (!isValid) {
          return cb(new ClientError(Errors.codes.NOT_AUTHORIZED, 'Session expired'));
        }

        server.storage.fetchCopayerLookup(opts.copayerId, (err, copayer) => {
          if (err) {
            return cb(err);
          }
          if (!copayer) {
            return cb(new ClientError(Errors.codes.NOT_AUTHORIZED, 'Copayer not found'));
          }

          server.copayerId = opts.copayerId;
          server.walletId = copayer.walletId;
          return cb(null, server);
        });
      });
    };

    const authFn = opts.session ? withSession : withSignature;
    return authFn(cb);
  }

  _runLocked(cb, task, waitTime?: number) {
    $.checkState(this.walletId, 'Failed state: this.walletId undefined at <_runLocked()>');

    this.lock.runLocked(this.walletId, { waitTime }, cb, task);
  }
  logi(message, ...args) {
    if (!this || !this.walletId) {
      return logger.warn(message, ...args);
    }

    message = '<' + this.walletId + '>' + message;
    return logger.info(message, ...args);
  }

  logw(message, ...args) {
    if (!this || !this.walletId) {
      return logger.warn(message, ...args);
    }

    message = '<' + this.walletId + '>' + message;
    return logger.warn(message, ...args);
  }

  logd(message, ...args) {
    if (!this || !this.walletId) {
      return logger.verbose(message, ...args);
    }

    message = '<' + this.walletId + '>' + message;
    return logger.verbose(message, ...args);
  }

  login(opts, cb) {
    let session;
    async.series(
      [
        next => {
          this.storage.getSession(this.copayerId, (err, s) => {
            if (err) {
              return next(err);
            }
            session = s;
            next();
          });
        },
        next => {
          if (!session || !session.isValid()) {
            session = Session.create({
              copayerId: this.copayerId,
              walletId: this.walletId
            });
          } else {
            session.touch();
          }
          next();
        },
        next => {
          this.storage.storeSession(session, next);
        }
      ],
      err => {
        if (err) {
          return cb(err);
        }
        if (!session) {
          return cb(new Error('Could not get current session for this copayer'));
        }

        return cb(null, session.id);
      }
    );
  }

  logout(opts, cb) {
    // this.storage.removeSession(this.copayerId, cb);
  }

  /**
   * Creates a new wallet.
   * @param {Object} opts
   * @param {string} opts.id - The wallet id.
   * @param {string} opts.name - The wallet name.
   * @param {number} opts.m - Required copayers.
   * @param {number} opts.n - Total copayers.
   * @param {string} opts.pubKey - Public key to verify copayers joining have access to the wallet secret.
   * @param {string} opts.singleAddress[=false] - The wallet will only ever have one address.
   * @param {string} opts.coin[='vcl'] - The coin for this wallet (btc, bch, eth, doge, ltc, vcl).
   * @param {string} opts.network[='livenet'] - The Bitcoin network for this wallet.
   * @param {string} opts.account[=0] - BIP44 account number
   * @param {string} opts.usePurpose48 - for Multisig wallet, use purpose=48
   * @param {string} opts.useNativeSegwit - for Segwit address, set addressType to P2WPKH or P2WSH
   */
  createWallet(opts, cb) {
    let pubKey;

    if (opts.coin === 'bch' && opts.n > 1) {
      const version = Utils.parseVersion(this.clientVersion);
      if (version && version.agent === 'bwc') {
        if (version.major < 8 || (version.major === 8 && version.minor < 3)) {
          return cb(
            new ClientError(
              Errors.codes.UPGRADE_NEEDED,
              'BWC clients < 8.3 are no longer supported for multisig BCH wallets.'
            )
          );
        }
      }
    }

    if (!checkRequired(opts, ['name', 'm', 'n', 'pubKey'], cb)) {
      return;
    }

    if (_.isEmpty(opts.name)) {
      return cb(new ClientError('Invalid wallet name'));
    }

    if (!Wallet.verifyCopayerLimits(opts.m, opts.n)) {
      return cb(new ClientError('Invalid combination of required copayers / total copayers'));
    }

    opts.coin = opts.coin || Defaults.COIN;
    if (!Utils.checkValueInCollection(opts.coin, Constants.COINS)) {
      return cb(new ClientError('Invalid coin'));
    }

    opts.network = opts.network || 'livenet';
    if (!Utils.checkValueInCollection(opts.network, Constants.NETWORKS)) {
      return cb(new ClientError('Invalid network'));
    }

    const derivationStrategy = Constants.DERIVATION_STRATEGIES.BIP44;
    let addressType = opts.n === 1 ? Constants.SCRIPT_TYPES.P2PKH : Constants.SCRIPT_TYPES.P2SH;

    if (opts.useNativeSegwit) {
      addressType = opts.n === 1 ? Constants.SCRIPT_TYPES.P2WPKH : Constants.SCRIPT_TYPES.P2WSH;
    }

    try {
      pubKey = new Bitcore_[opts.coin].PublicKey.fromString(opts.pubKey);
    } catch (ex) {
      return cb(new ClientError('Invalid public key'));
    }

    if (opts.n > 1 && !ChainService.supportsMultisig(opts.coin)) {
      return cb(new ClientError('Multisig wallets are not supported for this coin'));
    }

    if (ChainService.isSingleAddress(opts.coin)) {
      opts.singleAddress = true;
    }

    let newWallet;
    async.series(
      [
        acb => {
          if (!opts.id) {
            return acb();
          }

          this.storage.fetchWallet(opts.id, (err, wallet) => {
            if (wallet) {
              return acb(Errors.WALLET_ALREADY_EXISTS);
            }
            return acb(err);
          });
        },
        acb => {
          const wallet = Wallet.create({
            id: opts.id,
            name: opts.name,
            m: opts.m,
            n: opts.n,
            coin: opts.coin,
            network: opts.network,
            pubKey: pubKey.toString(),
            singleAddress: !!opts.singleAddress,
            derivationStrategy,
            addressType,
            nativeCashAddr: opts.nativeCashAddr,
            usePurpose48: opts.n > 1 && !!opts.usePurpose48
          });
          this.storage.storeWallet(wallet, err => {
            this.logd('Wallet created', wallet.id, opts.network);
            newWallet = wallet;
            return acb(err);
          });
        }
      ],
      err => {
        return cb(err, newWallet ? newWallet.id : null);
      }
    );
  }

  /**
   * Retrieves a wallet from storage.
   * @param {Object} opts
   * @returns {Object} wallet
   */
  getWallet(opts, cb) {
    this.storage.fetchWallet(this.walletId, (err, wallet) => {
      if (err) return cb(err);
      if (!wallet) return cb(Errors.WALLET_NOT_FOUND);

      // cashAddress migration
      if (wallet.coin != 'bch' || wallet.nativeCashAddr) return cb(null, wallet);

      // only for testing
      if (opts.doNotMigrate) return cb(null, wallet);

      // remove someday...
      logger.info(`Migrating wallet ${wallet.id} to cashAddr`);
      this.storage.migrateToCashAddr(this.walletId, e => {
        if (e) return cb(e);
        wallet.nativeCashAddr = true;
        return this.storage.storeWallet(wallet, e => {
          if (e) return cb(e);
          return cb(e, wallet);
        });
      });
    });
  }

  /**
   * Retrieves a wallet from storage.
   * @param {Object} opts
   * @param {string} opts.identifier - The identifier associated with the wallet (one of: walletId, address, txid).
   * @param {string} opts.walletCheck - Check v8 wallet sync
   * @returns {Object} wallet
   */
  getWalletFromIdentifier(opts, cb) {
    if (!opts.identifier) return cb();

    const end = (err, ret) => {
      if (opts.walletCheck && !err && ret) {
        return this.syncWallet(ret, cb);
      } else {
        return cb(err, ret);
      }
    };

    let walletId;
    async.parallel(
      [
        done => {
          this.storage.fetchWallet(opts.identifier, (err, wallet) => {
            if (wallet) walletId = wallet.id;
            return done(err);
          });
        },
        done => {
          this.storage.fetchAddressByCoin(Defaults.COIN, opts.identifier, (err, address) => {
            if (address) walletId = address.walletId;
            return done(err);
          });
        },
        done => {
          // sent txs
          this.storage.fetchTxByHash(opts.identifier, (err, tx) => {
            if (tx) walletId = tx.walletId;
            return done(err);
          });
        }
      ],
      err => {
        if (err) return cb(err);
        if (walletId) {
          return this.storage.fetchWallet(walletId, end);
        }

        return cb();
      }
    );
  }

  /**
   * Retrieves wallet status.
   * @param {Object} opts
   * @param {Object} opts.includeExtendedInfo - Include PKR info & address managers for wallet & copayers
   * @param {Object} opts.includeServerMessages - Include server messages array
   * @param {Object} opts.tokenAddress - (Optional) Token contract address to pass in getBalance
   * @param {Object} opts.multisigContractAddress - (Optional) Multisig ETH contract address to pass in getBalance
   * @param {Object} opts.network - (Optional ETH MULTISIG) Multisig ETH contract address network
   * @returns {Object} status
   */
  getStatus(opts, cb) {
    opts = opts || {};

    const status: {
      wallet?: IWallet;
      serverMessage?: {
        title: string;
        body: string;
        link: string;
        id: string;
        dismissible: boolean;
        category: string;
        app: string;
      };
      serverMessages?: Array<{
        title: string;
        body: string;
        link: string;
        id: string;
        dismissible: boolean;
        category: string;
        app: string;
        priority: number;
      }>;
      balance?: string;
      pendingTxps?: ITxProposal[];
      pendingAtomicSwapTxps?: ITxProposal[];
      preferences?: boolean;
      tokensAsset?: [];
    } = {};
    async.parallel(
      [
        next => {
          this.getWallet({}, (err, wallet) => {
            if (err) return next(err);

            const walletExtendedKeys = ['publicKeyRing', 'pubKey', 'addressManager'];
            const copayerExtendedKeys = ['xPubKey', 'requestPubKey', 'signature', 'addressManager', 'customData'];

            wallet.copayers = _.map(wallet.copayers, copayer => {
              if (copayer.id == this.copayerId) return copayer;
              return _.omit(copayer, 'customData');
            });
            if (!opts.includeExtendedInfo) {
              wallet = _.omit(wallet, walletExtendedKeys);
              wallet.copayers = _.map(wallet.copayers, copayer => {
                return _.omit(copayer, copayerExtendedKeys);
              });
            }
            status.wallet = wallet;

            if (opts.includeServerMessages) {
              status.serverMessages = serverMessages(wallet, this.appName, this.appVersion);
            } else {
              status.serverMessage = deprecatedServerMessage(wallet, this.appName, this.appVersion);
            }

            const zpub = this.xPubTozPub(wallet);
            sjs.utils
              .fetchBackendAccount(config.blockbookUrl, zpub, null, true)
              .then(ret => {
                _.each(ret.tokensAsset, tokenAsset => {
                  tokenAsset.symbol = new Buffer(tokenAsset.symbol, 'base64').toString();
                });
                status.tokensAsset = ret.tokensAsset;
                next();
              })
              .catch(err => {
                next();
              });
          });
        },
        next => {
          opts.wallet = status.wallet;
          this.getBalance(opts, (err, balance) => {
            // ignore WALLET_NEED_SCAN err is includeExtendedInfo is given
            // (to allow `importWallet` to import a wallet, while scan has
            // failed)
            if (opts.includeExtendedInfo) {
              if (err && err.code != 'WALLET_NEED_SCAN') {
                return next(err);
              }
            } else if (err) {
              return next(err);
            }

            status.balance = balance;
            next();
          });
        },
        next => {
          this.getPendingTxs(opts, (err, pendingTxps) => {
            if (err) return next(err);
            status.pendingTxps = pendingTxps;
            next();
          });
        },
        next => {
          this.getPendingAtomicSwapTxs(opts, (err, pendingAtomicSwapTxps) => {
            if (err) return next(err);
            status.pendingAtomicSwapTxps = pendingAtomicSwapTxps;
            next();
          });
        },
        next => {
          this.getPreferences({}, (err, preferences) => {
            if (err) return next(err);
            status.preferences = preferences;
            next();
          });
        }
      ],
      err => {
        if (err) return cb(err);
        return cb(null, status);
      }
    );
  }

  /*
   * Verifies a signature
   * @param text
   * @param signature
   * @param pubKeys
   */
  _verifySignature(text, signature, pubkey) {
    return Utils.verifyMessage(text, signature, pubkey);
  }

  /*
   * Verifies a request public key
   * @param requestPubKey
   * @param signature
   * @param xPubKey
   */
  _verifyRequestPubKey(requestPubKey, signature, xPubKey, coin) {
    const pub = new Bitcore_[coin].HDPublicKey(xPubKey).deriveChild(Constants.PATHS.REQUEST_KEY_AUTH).publicKey;
    return Utils.verifyMessage(requestPubKey, signature, pub.toString(), coin);
  }

  /*
   * Verifies signature againt a collection of pubkeys
   * @param text
   * @param signature
   * @param pubKeys
   */
  _getSigningKey(text, signature, pubKeys) {
    return _.find(pubKeys, item => {
      return this._verifySignature(text, signature, item.key);
    });
  }

  /**
   * _notify
   *
   * @param {String} type
   * @param {Object} data
   * @param {Object} opts
   * @param {Boolean} opts.isGlobal - If true, the notification is not issued on behalf of any particular copayer (defaults to false)
   */
  _notify(type, data, opts, cb?: (err?: any, data?: any) => void) {
    if (_.isFunction(opts)) {
      cb = opts;
      opts = {};
    }
    opts = opts || {};

    // this.logi('Notification', type);

    cb = cb || function() {};

    const walletId = this.walletId || data.walletId;
    const copayerId = this.copayerId || data.copayerId;

    $.checkState(walletId, 'Failed state: walletId undefined at <_notify()>');

    const notification = Notification.create({
      type,
      data,
      ticker: this.notifyTicker++,
      creatorId: opts.isGlobal ? null : copayerId,
      walletId
    });

    this.storage.storeNotification(walletId, notification, () => {
      this.messageBroker.send(notification);
      return cb();
    });
  }

  _notifyTxProposalAction(type, txp, extraArgs, cb?: (err?: any, data?: any) => void) {
    if (_.isFunction(extraArgs)) {
      cb = extraArgs;
      extraArgs = {};
    }

    const data = _.assign(
      {
        txProposalId: txp.id,
        creatorId: txp.creatorId,
        amount: txp.getTotalAmount(),
        message: txp.message,
        tokenAddress: txp.tokenAddress,
        multisigContractAddress: txp.multisigContractAddress
      },
      extraArgs
    );
    this._notify(type, data, {}, cb);
  }

  // john
  _notifyRedeemTxProposalAction(type, txp, extraArgs, cb?: (err?: any, data?: any) => void) {
    if (_.isFunction(extraArgs)) {
      cb = extraArgs;
      extraArgs = {};
    }

    var data;
    // john 20211026
    if (txp.atomicswap && txp.atomicswap.secret) {
      const data = _.assign(
        {
          txProposalId: txp.id,
          creatorId: txp.creatorId,
          amount: txp.getTotalAmount(),
          secret: txp.atomicswap.secret
        },
        extraArgs
      );
    } else {
      const data = _.assign(
        {
          txProposalId: txp.id,
          creatorId: txp.creatorId,
          amount: txp.getTotalAmount()
        },
        extraArgs
      );
    }
    this._notify(type, data, {}, cb);
  }

  // john 20220219
  _notifyMasternodeAction(type, masternode, extraArgs, cb?: (err?: any, data?: any) => void) {
    if (_.isFunction(extraArgs)) {
      cb = extraArgs;
      extraArgs = {};
    }

    const data = _.assign(
      {
        coin: masternode.coin,
        network: masternode.network,
        txid: masternode.txid || masternode.proTxHash
      },
      extraArgs
    );
    this._notify(type, data, {}, cb);
  }

  _addCopayerToWallet(wallet, opts, cb) {
    const copayer = Copayer.create({
      coin: wallet.coin,
      name: opts.name,
      copayerIndex: wallet.copayers.length,
      xPubKey: opts.xPubKey,
      requestPubKey: opts.requestPubKey,
      signature: opts.copayerSignature,
      customData: opts.customData,
      derivationStrategy: wallet.derivationStrategy
    });

    this.storage.fetchCopayerLookup(copayer.id, (err, res) => {
      if (err) return cb(err);
      if (res) return cb(Errors.COPAYER_REGISTERED);

      if (opts.dryRun)
        return cb(null, {
          copayerId: null,
          wallet
        });

      wallet.addCopayer(copayer);
      this.storage.storeWalletAndUpdateCopayersLookup(wallet, err => {
        if (err) return cb(err);

        async.series(
          [
            next => {
              this._notify(
                'NewCopayer',
                {
                  walletId: opts.walletId,
                  copayerId: copayer.id,
                  copayerName: copayer.name
                },
                {},
                next
              );
            },
            next => {
              if (wallet.isComplete() && wallet.isShared()) {
                this._notify(
                  'WalletComplete',
                  {
                    walletId: opts.walletId
                  },
                  {
                    isGlobal: true
                  },
                  next
                );
              } else {
                next();
              }
            }
          ],
          () => {
            return cb(null, {
              copayerId: copayer.id,
              wallet
            });
          }
        );
      });
    });
  }

  _addKeyToCopayer(wallet, copayer, opts, cb) {
    wallet.addCopayerRequestKey(copayer.copayerId, opts.requestPubKey, opts.signature, opts.restrictions, opts.name);
    this.storage.storeWalletAndUpdateCopayersLookup(wallet, err => {
      if (err) return cb(err);

      return cb(null, {
        copayerId: copayer.id,
        wallet
      });
    });
  }

  /**
   * Adds access to a given copayer
   *
   * @param {Object} opts
   * @param {string} opts.copayerId - The copayer id
   * @param {string} opts.requestPubKey - Public Key used to check requests from this copayer.
   * @param {string} opts.copayerSignature - S(requestPubKey). Used by other copayers to verify the that the copayer is himself (signed with REQUEST_KEY_AUTH)
   * @param {string} opts.restrictions
   *    - cannotProposeTXs
   *    - cannotXXX TODO
   * @param {string} opts.name  (name for the new access)
   */
  addAccess(opts, cb) {
    if (!checkRequired(opts, ['copayerId', 'requestPubKey', 'signature'], cb)) return;

    opts.coin = opts.coin || Defaults.COIN;
    this.storage.fetchCopayerLookup(opts.copayerId, (err, copayer) => {
      if (err) return cb(err);
      if (!copayer) return cb(Errors.NOT_AUTHORIZED);
      this.storage.fetchWallet(copayer.walletId, (err, wallet) => {
        if (err) return cb(err);
        if (!wallet) return cb(Errors.NOT_AUTHORIZED);

        const xPubKey = wallet.copayers.find(c => c.id === opts.copayerId).xPubKey;

        if (!this._verifyRequestPubKey(opts.requestPubKey, opts.signature, xPubKey, opts.coin)) {
          return cb(Errors.NOT_AUTHORIZED);
        }

        if (copayer.requestPubKeys.length > Defaults.MAX_KEYS) return cb(Errors.TOO_MANY_KEYS);

        this._addKeyToCopayer(wallet, copayer, opts, cb);
      });
    });
  }

  _setClientVersion(version) {
    delete this.parsedClientVersion;
    this.clientVersion = version;
  }

  _setAppVersion(userAgent) {
    const parsed = Utils.parseAppVersion(userAgent);
    if (!parsed) {
      this.appName = this.appVersion = null;
    } else {
      this.appName = parsed.app;
      this.appVersion = parsed;
    }
  }

  _parseClientVersion() {
    if (_.isUndefined(this.parsedClientVersion)) {
      this.parsedClientVersion = Utils.parseVersion(this.clientVersion);
    }
    return this.parsedClientVersion;
  }

  _clientSupportsPayProRefund() {
    const version = this._parseClientVersion();
    if (!version) return false;
    if (version.agent != 'bwc') return true;
    if (version.major < 1 || (version.major == 1 && version.minor < 2)) return false;
    return true;
  }

  static _getCopayerHash(name, xPubKey, requestPubKey) {
    return [name, xPubKey, requestPubKey].join('|');
  }

  /**
   * Joins a wallet in creation.
   * @param {Object} opts
   * @param {string} opts.walletId - The wallet id.
   * @param {string} opts.coin[='vcl'] - The expected coin for this wallet (btc, bch, eth, doge, ltc, vcl).
   * @param {string} opts.name - The copayer name.
   * @param {string} opts.xPubKey - Extended Public Key for this copayer.
   * @param {string} opts.requestPubKey - Public Key used to check requests from this copayer.
   * @param {string} opts.copayerSignature - S(name|xPubKey|requestPubKey). Used by other copayers to verify that the copayer joining knows the wallet secret.
   * @param {string} opts.customData - (optional) Custom data for this copayer.
   * @param {string} opts.dryRun[=false] - (optional) Simulate the action but do not change server state.
   */
  joinWallet(opts, cb) {
    if (!checkRequired(opts, ['walletId', 'name', 'xPubKey', 'requestPubKey', 'copayerSignature'], cb)) return;

    if (_.isEmpty(opts.name)) return cb(new ClientError('Invalid copayer name'));

    opts.coin = opts.coin || Defaults.COIN;
    if (!Utils.checkValueInCollection(opts.coin, Constants.COINS)) return cb(new ClientError('Invalid coin'));

    let xPubKey;
    try {
      xPubKey = Bitcore_[opts.coin].HDPublicKey(opts.xPubKey);
    } catch (ex) {
      return cb(new ClientError('Invalid extended public key'));
    }
    if (_.isUndefined(xPubKey.network)) {
      return cb(new ClientError('Invalid extended public key'));
    }

    this.walletId = opts.walletId;
    this._runLocked(cb, cb => {
      this.storage.fetchWallet(opts.walletId, (err, wallet) => {
        if (err) return cb(err);
        if (!wallet) return cb(Errors.WALLET_NOT_FOUND);

        if (opts.coin === 'bch' && wallet.n > 1) {
          const version = Utils.parseVersion(this.clientVersion);
          if (version && version.agent === 'bwc') {
            if (version.major < 8 || (version.major === 8 && version.minor < 3)) {
              return cb(
                new ClientError(
                  Errors.codes.UPGRADE_NEEDED,
                  'BWC clients < 8.3 are no longer supported for multisig BCH wallets.'
                )
              );
            }
          }
        }

        if (wallet.n > 1 && wallet.usePurpose48) {
          const version = Utils.parseVersion(this.clientVersion);
          if (version && version.agent === 'bwc') {
            if (version.major < 8 || (version.major === 8 && version.minor < 4)) {
              return cb(
                new ClientError(Errors.codes.UPGRADE_NEEDED, 'Please upgrade your client to join this multisig wallet')
              );
            }
          }
        }

        if (wallet.n > 1 && wallet.addressType === 'P2WSH') {
          const version = Utils.parseVersion(this.clientVersion);
          if (version && version.agent === 'bwc') {
            if (version.major < 8 || (version.major === 8 && version.minor < 17)) {
              return cb(
                new ClientError(Errors.codes.UPGRADE_NEEDED, 'Please upgrade your client to join this multisig wallet')
              );
            }
          }
        }

        if (opts.coin != wallet.coin) {
          return cb(new ClientError('The wallet you are trying to join was created for a different coin'));
        }

        if (wallet.network != xPubKey.network.name) {
          return cb(new ClientError('The wallet you are trying to join was created for a different network'));
        }

        // New client trying to join legacy wallet
        if (wallet.derivationStrategy == Constants.DERIVATION_STRATEGIES.BIP45) {
          return cb(
            new ClientError('The wallet you are trying to join was created with an older version of the client app.')
          );
        }

        const hash = WalletService._getCopayerHash(opts.name, opts.xPubKey, opts.requestPubKey);
        if (!this._verifySignature(hash, opts.copayerSignature, wallet.pubKey)) {
          return cb(new ClientError());
        }

        if (
          _.find(wallet.copayers, {
            xPubKey: opts.xPubKey
          })
        )
          return cb(Errors.COPAYER_IN_WALLET);

        if (wallet.copayers.length == wallet.n) return cb(Errors.WALLET_FULL);

        this._addCopayerToWallet(wallet, opts, cb);
      });
    });
  }

  /**
   * Save copayer preferences for the current wallet/copayer pair.
   * @param {Object} opts
   * @param {string} opts.email - Email address for notifications.
   * @param {string} opts.language - Language used for notifications.
   * @param {string} opts.unit - Bitcoin unit used to format amounts in notifications.
   * @param {string} opts.tokenAddresses - Linked token addresses
   * @param {string} opts.multisigEthInfo - Linked multisig eth wallet info
   *
   */
  savePreferences(opts, cb) {
    opts = opts || {};

    const preferences = [
      {
        name: 'email',
        isValid(value) {
          return EmailValidator.validate(value);
        }
      },
      {
        name: 'language',
        isValid(value) {
          return _.isString(value) && value.length == 2;
        }
      },
      {
        name: 'unit',
        isValid(value) {
          return _.isString(value) && _.includes(['btc', 'bit'], value.toLowerCase());
        }
      },
      {
        name: 'tokenAddresses',
        isValid(value) {
          return _.isArray(value) && value.every(x => Validation.validateAddress('eth', 'mainnet', x));
        }
      },
      {
        name: 'multisigEthInfo',
        isValid(value) {
          return (
            _.isArray(value) &&
            value.every(x => Validation.validateAddress('eth', 'mainnet', x.multisigContractAddress))
          );
        }
      }
    ];

    opts = _.pick(opts, _.map(preferences, 'name'));
    try {
      _.each(preferences, preference => {
        const value = opts[preference.name];
        if (!value) return;
        if (!preference.isValid(value)) {
          throw new Error('Invalid ' + preference.name);
        }
      });
    } catch (ex) {
      return cb(new ClientError(ex));
    }

    this.getWallet({}, (err, wallet) => {
      if (err) return cb(err);

      if (wallet.coin != 'eth') {
        opts.tokenAddresses = null;
        opts.multisigEthInfo = null;
      }

      this._runLocked(cb, cb => {
        this.storage.fetchPreferences(this.walletId, this.copayerId, (err, oldPref) => {
          if (err) return cb(err);

          const newPref = Preferences.create({
            walletId: this.walletId,
            copayerId: this.copayerId
          });
          const preferences = Preferences.fromObj(_.defaults(newPref, opts, oldPref));

          // merge tokenAddresses
          if (opts.tokenAddresses) {
            oldPref = oldPref || {};
            oldPref.tokenAddresses = oldPref.tokenAddresses || [];
            preferences.tokenAddresses = _.uniq(oldPref.tokenAddresses.concat(opts.tokenAddresses));
          }

          // merge multisigEthInfo
          if (opts.multisigEthInfo) {
            oldPref = oldPref || {};
            oldPref.multisigEthInfo = oldPref.multisigEthInfo || [];

            preferences.multisigEthInfo = _.uniq(
              oldPref.multisigEthInfo.concat(opts.multisigEthInfo).reduce((x, y) => {
                let exists = false;
                x.forEach(e => {
                  // add new token addresses linked to the multisig wallet
                  if (e.multisigContractAddress === y.multisigContractAddress) {
                    e.tokenAddresses = e.tokenAddresses || [];
                    y.tokenAddresses = _.uniq(e.tokenAddresses.concat(y.tokenAddresses));
                    e = Object.assign(e, y);
                    exists = true;
                  }
                });
                return exists ? x : [...x, y];
              }, [])
            );
          }

          this.storage.storePreferences(preferences, err => {
            return cb(err);
          });
        });
      });
    });
  }

  /**
   * Retrieves a preferences for the current wallet/copayer pair.
   * @param {Object} opts
   * @returns {Object} preferences
   */
  getPreferences(opts, cb) {
    this.storage.fetchPreferences(this.walletId, this.copayerId, (err, preferences) => {
      if (err) return cb(err);
      return cb(null, preferences || {});
    });
  }

  _canCreateAddress(ignoreMaxGap, cb) {
    if (ignoreMaxGap) return cb(null, true);

    this.storage.fetchAddresses(this.walletId, (err, addresses: IAddress[]) => {
      if (err) return cb(err);
      const latestAddresses = addresses.filter(x => !x.isChange).slice(-Defaults.MAX_MAIN_ADDRESS_GAP) as IAddress[];
      if (
        latestAddresses.length < Defaults.MAX_MAIN_ADDRESS_GAP ||
        _.some(latestAddresses, {
          hasActivity: true
        })
      )
        return cb(null, true);

      const bc = this._getBlockchainExplorer(latestAddresses[0].coin, latestAddresses[0].network);
      if (!bc) return cb(new Error('Could not get blockchain explorer instance'));
      let activityFound = false;
      let i = latestAddresses.length;
      async.whilst(
        () => {
          return i > 0 && !activityFound;
        },
        next => {
          bc.getAddressActivity(latestAddresses[--i].address, (err, res) => {
            if (err) return next(err);
            activityFound = !!res;
            return next();
          });
        },
        err => {
          if (err) return cb(err);
          if (!activityFound) return cb(null, false);

          const address = latestAddresses[i];
          address.hasActivity = true;
          this.storage.storeAddress(address, err => {
            return cb(err, true);
          });
        }
      );
    });
  }

  _store(wallet, address, cb, checkSync = false) {
    let stoAddress = _.clone(address);
    ChainService.addressToStorageTransform(wallet.coin, wallet.network, stoAddress);
    this.storage.storeAddressAndWallet(wallet, stoAddress, (err, isDuplicate) => {
      if (err) return cb(err);
      this.syncWallet(
        wallet,
        err2 => {
          if (err2) {
            this.logw('Error syncing v8 addresses: ', err2);
          }
          return cb(null, isDuplicate);
        },
        !checkSync
      );
    });
  }

  /**
   * Creates a new address.
   * @param {Object} opts
   * @param {Boolean} [opts.ignoreMaxGap=false] - Ignore constraint of maximum number of consecutive addresses without activity
   * @param {Boolean} opts.noCashAddr (do not use cashaddr, only for backwards compat)
   * @returns {Address} address
   */
  createAddress(opts, cb) {
    opts = opts || {};

    const createNewAddress = (wallet, cb) => {
      let address;
      try {
        address = wallet.createAddress(!!opts.isChange);
      } catch (e) {
        this.logw('Error creating address', e);
        return cb('Bad xPub');
      }

      this._store(
        wallet,
        address,
        (err, duplicate) => {
          if (err) return cb(err);
          if (duplicate) return cb(null, address);
          if (wallet.coin == 'bch' && opts.noCashAddr) {
            address = _.cloneDeep(address);
            address.address = BCHAddressTranslator.translate(address.address, 'copay');
          }

          this._notify(
            'NewAddress',
            {
              address: address.address
            },
            () => {
              return cb(null, address);
            }
          );
        },
        true
      );
    };

    const getFirstAddress = (wallet, cb) => {
      this.storage.fetchAddresses(this.walletId, (err, addresses) => {
        if (err) return cb(err);
        if (!_.isEmpty(addresses)) {
          let x = _.head(addresses);
          ChainService.addressFromStorageTransform(wallet.coin, wallet.network, x);
          return cb(null, x);
        }
        return createNewAddress(wallet, cb);
      });
    };

    this.getWallet({ doNotMigrate: opts.doNotMigrate }, (err, wallet) => {
      if (err) return cb(err);

      if (ChainService.isSingleAddress(wallet.coin)) {
        opts.ignoreMaxGap = true;
        opts.singleAddress = true;
      }

      this._canCreateAddress(opts.ignoreMaxGap || opts.singleAddress || wallet.singleAddress, (err, canCreate) => {
        if (err) return cb(err);
        if (!canCreate) return cb(Errors.MAIN_ADDRESS_GAP_REACHED);

        this._runLocked(
          cb,
          cb => {
            this.getWallet({ doNotMigrate: opts.doNotMigrate }, (err, wallet) => {
              if (err) return cb(err);
              if (!wallet.isComplete()) return cb(Errors.WALLET_NOT_COMPLETE);
              if (wallet.scanStatus == 'error') return cb(Errors.WALLET_NEED_SCAN);

              const createFn = opts.singleAddress || wallet.singleAddress ? getFirstAddress : createNewAddress;
              return createFn(wallet, (err, address) => {
                if (err) {
                  return cb(err);
                }
                return cb(err, address);
              });
            });
          },
          10 * 1000
        );
      });
    });
  }

  /**
   * Get all addresses.
   * @param {Object} opts
   * @param {Numeric} opts.limit (optional) - Limit the resultset. Return all addresses by default.
   * @param {Boolean} [opts.reverse=false] (optional) - Reverse the order of returned addresses.
   * @returns {Address[]}
   */
  getMainAddresses(opts, cb) {
    opts = opts || {};
    this.storage.fetchAddresses(this.walletId, (err, addresses) => {
      if (err) return cb(err);
      if (opts.address) {
        addresses = _.filter(addresses, { address: opts.address });
      }
      let onlyMain = _.reject(addresses, {
        isChange: true
      });
      if (opts.reverse) onlyMain.reverse();
      if (opts.limit > 0) onlyMain = _.take(onlyMain, opts.limit);

      this.getWallet({}, (err, wallet) => {
        _.each(onlyMain, x => {
          ChainService.addressFromStorageTransform(wallet.coin, wallet.network, x);
        });
        return cb(null, onlyMain);
      });
    });
  }

  /**
   * Verifies that a given message was actually sent by an authorized copayer.
   * @param {Object} opts
   * @param {string} opts.message - The message to verify.
   * @param {string} opts.signature - The signature of message to verify.
   * @returns {truthy} The result of the verification.
   */
  verifyMessageSignature(opts, cb) {
    if (!checkRequired(opts, ['message', 'signature'], cb)) return;

    this.getWallet({}, (err, wallet) => {
      if (err) return cb(err);

      const copayer = wallet.getCopayer(this.copayerId);

      const isValid = !!this._getSigningKey(opts.message, opts.signature, copayer.requestPubKeys);
      return cb(null, isValid);
    });
  }

  _getBlockchainExplorer(coin, network): ReturnType<typeof BlockChainExplorer> {
    let opts: Partial<{
      provider: string;
      coin: string;
      network: string;
      userAgent: string;
    }> = {};

    let provider;

    if (this.blockchainExplorer) return this.blockchainExplorer;
    if (this.blockchainExplorerOpts) {
      if (this.blockchainExplorerOpts[coin] && this.blockchainExplorerOpts[coin][network]) {
        opts = this.blockchainExplorerOpts[coin][network];
        provider = opts.provider;
      } else if (this.blockchainExplorerOpts[network]) {
        opts = this.blockchainExplorerOpts[network];
      }
    }
    opts.provider = provider;
    opts.coin = coin;
    opts.network = network;
    opts.userAgent = WalletService.getServiceVersion();
    let bc;
    try {
      bc = BlockChainExplorer(opts);
    } catch (ex) {
      this.logw('Could not instantiate blockchain explorer', ex);
    }
    return bc;
  }

  getUtxosForCurrentWallet(opts, cb) {
    opts = opts || {};

    const utxoKey = utxo => {
      return utxo.txid + '|' + utxo.vout;
    };

    const utxoKey1 = outpoint => {
      var xtxid = outpoint.split('-');
      return xtxid[0] + '|' + xtxid[1];
    };

    let coin, allAddresses, allUtxos, utxoIndex, addressStrs, bc, wallet, blockchainHeight;
    async.series(
      [
        next => {
          this.getWallet({}, (err, w) => {
            if (err) return next(err);

            wallet = w;

            if (wallet.scanStatus == 'error') return cb(Errors.WALLET_NEED_SCAN);

            coin = wallet.coin;

            bc = this._getBlockchainExplorer(coin, wallet.network);
            if (!bc) return cb(new Error('Could not get blockchain explorer instance'));
            return next();
          });
        },
        next => {
          if (_.isArray(opts.addresses)) {
            allAddresses = opts.addresses;
            return next();
          }

          // even with Grouping we need address for pubkeys and path (see last step)
          this.storage.fetchAddresses(this.walletId, (err, addresses) => {
            _.each(addresses, x => {
              ChainService.addressFromStorageTransform(wallet.coin, wallet.network, x);
            });
            allAddresses = addresses;
            if (allAddresses.length == 0) return cb(null, []);

            return next();
          });
        },
        next => {
          addressStrs = _.map(allAddresses, 'address');
          return next();
        },
        next => {
          if (!wallet.isComplete()) return next();
          this._getBlockchainHeight(wallet.coin, wallet.network, (err, height, hash) => {
            if (err) return next(err);
            blockchainHeight = height;
            next();
          });
        },
        next => {
          if (!wallet.isComplete()) return next();

          const dustThreshold = Bitcore_[wallet.coin].Transaction.DUST_AMOUNT;
          const isEscrowPayment = wallet.isZceCompatible() && opts.instantAcceptanceEscrow ? true : false;
          const replaceTxByFee = opts.replaceTxByFee ? true : false;
          bc.getUtxos(
            wallet,
            blockchainHeight,
            (err, utxos) => {
              if (err) return next(err);
              if (utxos.length == 0) return cb(null, []);

              let unusableAddresses = [];
              if (isEscrowPayment) {
                const unusableUtxos = utxos.filter(utxo => utxo.spent || utxo.address.startsWith('p'));
                unusableAddresses = unusableUtxos.map(utxo => utxo.address);
              }

              allUtxos = utxos.filter(x => x.satoshis >= dustThreshold && !unusableAddresses.includes(x.address));

              return next();
            },
            { includeSpent: isEscrowPayment || replaceTxByFee }
          );
        },
        next => {
          if (!wallet.isComplete() || !wallet.isZceCompatible()) return next();

          // Ensure no UTXOs which originate from addresses that were recently used to fund a currently
          // insufficiently confirmed ZCE-secured payment can be used to fund any subsequent transactions
          // until the ZCE-secured payment (and escrow reclaim tx) receives 11 confirmations.
          // Rationale: https://github.com/bitjson/bch-zce#wallet-utxo-selection

          const bchRollingBlockCheckpointNumber = 10;
          const bchReorgSafeBlockHeight = blockchainHeight - bchRollingBlockCheckpointNumber - 1;
          let lockedAddresses = [];
          bc.getTransactions(wallet, bchReorgSafeBlockHeight, (err, txs) => {
            if (err) return next(err);
            const unconfirmedZceTxs = txs.filter(tx => tx.category === 'move' && tx.address.startsWith('p'));
            async.each(
              unconfirmedZceTxs,
              (tx: any, next) => {
                this.getCoinsForTx({ txId: tx.txid }, (err, coins) => {
                  if (err) return next(err);
                  const inputAddresses = coins.inputs.map(input => input.address);
                  lockedAddresses = [...lockedAddresses, ...inputAddresses];
                  return next();
                });
              },
              err => {
                if (err) return next(err);
                allUtxos = allUtxos.map(utxo => {
                  if (lockedAddresses.includes(utxo.address)) {
                    utxo.locked = true;
                  }
                  return utxo;
                });
                return next();
              }
            );
          });
        },
        next => {
          utxoIndex = _.keyBy(allUtxos, utxoKey);

          this.getPendingTxs({}, (err, txps) => {
            if (err) return next(err);

            const lockedInputs = _.map(_.flatten(_.map(txps, 'inputs')), utxoKey);
            _.each(lockedInputs, input => {
              if (utxoIndex[input]) {
                utxoIndex[input].locked = true;
              }
            });
            logger.debug(`Got  ${lockedInputs.length} locked utxos`);
            return next();
          });
        },
        next => {
          const now = Math.floor(Date.now() / 1000);
          // Fetch latest broadcasted txs and remove any spent inputs from the
          // list of UTXOs returned by the block explorer. This counteracts any out-of-sync
          // effects between broadcasting a tx and getting the list of UTXOs.
          // This is especially true in the case of having multiple instances of the block explorer.
          this.storage.fetchBroadcastedTxs(
            this.walletId,
            {
              minTs: now - 24 * 3600,
              limit: 100
            },
            (err, txs) => {
              if (err) return next(err);
              const spentInputs = _.map(_.flatten(_.map(txs, 'inputs')), utxoKey);
              const txIdArray = _.map(opts.inputs, 'txid');

              _.each(spentInputs, input => {
                if (utxoIndex[input]) {
                  utxoIndex[input].spent = true;
                }
              });
              // except spent inputs of the RBF transaction if it's a replacement
              allUtxos = _.reject(allUtxos, utxo => {
                return (
                  (!opts.replaceTxByFee && utxo.spent) ||
                  (utxo.spent && opts.replaceTxByFee && !_.includes(txIdArray, utxo.txid))
                );
              });
              logger.debug(`Got ${allUtxos.length} usable UTXOs`);
              return next();
            }
          );
        },
        // john
        next => {
          if (!opts.excludeMasternode) {
            return next();
          }
          this.storage.fetchMasternodes(this.walletId, undefined, undefined, (err, masternodes) => {
            if (err) return next(err);
            const lockedInputs1 = _.map(_.flatten(_.map(masternodes, 'txid')), utxoKey1);
            _.each(lockedInputs1, input => {
              if (utxoIndex[input]) {
                utxoIndex[input].locked = true;
                utxoIndex[input].isMasternode = true;
              }
            });
            logger.debug(`Got  ${masternodes.length} locked masternode utxos`);
            return next();
          });
        },
        next => {
          // Needed for the clients to sign UTXOs
          const addressToPath = _.keyBy(allAddresses, 'address');
          _.each(allUtxos, utxo => {
            if (!addressToPath[utxo.address]) {
              if (!opts.addresses) this.logw('Ignored UTXO!: ' + utxo.address);
              return;
            }
            utxo.path = addressToPath[utxo.address].path;
            utxo.publicKeys = addressToPath[utxo.address].publicKeys;
          });
          return next();
        }
      ],
      (err: any) => {
        // TODO`
        if (err && err.statusCode == 404) {
          return this.registerWalletV8(wallet, cb);
        }
        return cb(err, allUtxos);
      }
    );
  }

  /**
   * Returns list of UTXOs
   * @param {Object} opts
   * @param {Array} [opts.addresses] - List of addresses. options. only one address is supported
   * @returns {Array} utxos - List of UTXOs.
   */
  getUtxos(opts, cb) {
    opts = opts || {};

    if (opts.coin) {
      return cb(new ClientError('coins option no longer supported'));
    }

    if (opts.addresses) {
      if (opts.addresses.length > 1) return cb(new ClientError('Addresses option only support 1 address'));

      this.getWallet({}, (err, wallet) => {
        if (err) return cb(err);

        const bc = this._getBlockchainExplorer(wallet.coin, wallet.network);
        if (!bc) {
          return cb(new Error('Could not get blockchain explorer instance'));
        }

        const address = opts.addresses[0];
        const A = Bitcore_[wallet.coin].Address;
        let addrObj: { network?: { name?: string } } = {};
        try {
          addrObj = new A(address);
        } catch (ex) {
          return cb(null, []);
        }
        if (addrObj.network.name != wallet.network) {
          return cb(null, []);
        }

        this._getBlockchainHeight(wallet.coin, wallet.network, (err, height, hash) => {
          if (err) return cb(err);
          bc.getAddressUtxos(address, height, (err, utxos) => {
            if (err) return cb(err);
            return cb(null, utxos);
          });
        });
      });
    } else {
      this.getUtxosForCurrentWallet({}, cb);
    }
  }

  // john 20210409
  /**
   * Returns list of UTXOs
   * @param {Object} opts
   * @param {Array} [opts.addresses] - List of addresses. options. only one address is supported
   * @returns {Array} utxos - List of UTXOs.
   */
  getAddressTx(opts, cb) {
    opts = opts || {};

    if (opts.coin) {
      return cb(new ClientError('coins option no longer supported'));
    }

    if (opts.addresses) {
      if (opts.addresses.length > 1) return cb(new ClientError('Addresses option only support 1 address'));

      this.getWallet({}, (err, wallet) => {
        if (err) return cb(err);

        const bc = this._getBlockchainExplorer(wallet.coin, wallet.network);
        if (!bc) {
          return cb(new Error('Could not get blockchain explorer instance'));
        }

        const address = opts.addresses[0];
        const A = Bitcore_[wallet.coin].Address;
        let addrObj: { network?: { name?: string } } = {};
        try {
          addrObj = new A(address);
        } catch (ex) {
          return cb(null, []);
        }
        if (addrObj.network.name != wallet.network) {
          return cb(null, []);
        }

        this._getBlockchainHeight(wallet.coin, wallet.network, (err, height, hash) => {
          if (err) return cb(err);
          bc.getAddressTx(address, height, (err, utxos) => {
            if (err) return cb(err);
            return cb(null, utxos);
          });
        });
      });
    } else {
      this.getUtxosForCurrentWallet({}, cb);
    }
  }

  /**
   * Returns list of Coins for TX
   * @param {Object} opts
   * @param {string} opts.coin - The coin of the transaction.
   * @param {string} opts.network - the network of the transaction.
   * @param {string} opts.txId - the transaction id.
   * @returns {Obejct} coins - Inputs and Outputs of the transaction.
   */
  getCoinsForTx(opts, cb) {
    this.getWallet({}, (err, wallet) => {
      if (!ChainService.isUTXOCoin(wallet.coin)) {
        // this prevents old BWC clients to break
        return cb(null, {
          inputs: [],
          outputs: []
        });
      }
      const bc = this._getBlockchainExplorer(wallet.coin, wallet.network);
      if (!bc) {
        return cb(new Error('Could not get blockchain explorer instance'));
      }

      bc.getCoinsForTx(opts.txId, (err, coins) => {
        if (err) return cb(err);
        return cb(null, coins);
      });
    });
  }

  /**
   * Get wallet balance.
   * @param {Object} opts
   * @returns {Object} balance - Total amount & locked amount.
   */

  getBalance(opts, cb) {
    opts = opts || {};

    if (opts.coin) {
      return cb(new ClientError('coin is not longer supported in getBalance'));
    }
    opts.excludeMasternode = opts.excludeMasternode || true; // john 20210916

    let wallet = opts.wallet;

    const setWallet = cb1 => {
      if (wallet) return cb1();
      this.getWallet({}, (err, ret) => {
        if (err) return cb(err);
        wallet = ret;
        return cb1(null, wallet);
      });
    };

    setWallet(() => {
      if (!wallet.isComplete()) {
        const emptyBalance = {
          totalAmount: 0,
          lockedAmount: 0,
          totalConfirmedAmount: 0,
          lockedConfirmedAmount: 0,
          availableAmount: 0,
          availableConfirmedAmount: 0,
          availableAmountExcludeMasternode: 0,
          availableConfirmedAmountExcludeMasternode: 0
        };
        return cb(null, emptyBalance);
      }

      this.syncWallet(wallet, err => {
        if (err) return cb(err);
        return ChainService.getWalletBalance(this, wallet, opts, cb);
      });
    });
  }

  /**
   * Return info needed to send all funds in the wallet
   * @param {Object} opts
   * @param {number} opts.feeLevel[='normal'] - Optional. Specify the fee level for this TX ('priority', 'normal', 'economy', 'superEconomy') as defined in Defaults.FEE_LEVELS.
   * @param {number} opts.feePerKb - Optional. Specify the fee per KB for this TX (in satoshi).
   * @param {string} opts.excludeUnconfirmedUtxos[=false] - Optional. Do not use UTXOs of unconfirmed transactions as inputs
   * @param {string} opts.returnInputs[=false] - Optional. Return the list of UTXOs that would be included in the tx.
   * @param {string} opts.usePayPro[=false] - Optional. Use fee estimation for paypro
   * @param {string} opts.from - Optional. Specify the sender ETH address.
   * @param {string} opts.excludeMasternode[=false] - Optional. Do not use UTXOs of masternode transactions as inputs
   * @returns {Object} sendMaxInfo
   */
  getSendMaxInfo(opts, cb) {
    opts = opts || {};

    this.getWallet({}, (err, wallet) => {
      if (err) return cb(err);

      const feeArgs = boolToNum(!!opts.feeLevel) + boolToNum(_.isNumber(opts.feePerKb));
      if (feeArgs > 1) return cb(new ClientError('Only one of feeLevel/feePerKb can be specified'));

      if (feeArgs == 0) {
        opts.feeLevel = 'normal';
      }

      const feeLevels = Defaults.FEE_LEVELS[wallet.coin];
      if (opts.feeLevel) {
        if (
          !_.some(feeLevels, {
            name: opts.feeLevel
          })
        )
          return cb(new ClientError('Invalid fee level. Valid values are ' + _.map(feeLevels, 'name').join(', ')));
      }

      if (_.isNumber(opts.feePerKb)) {
        if (opts.feePerKb < Defaults.MIN_FEE_PER_KB || opts.feePerKb > Defaults.MAX_FEE_PER_KB[wallet.coin])
          return cb(new ClientError('Invalid fee per KB'));
      }

      // john 20210409
      if (opts.atomicswap && opts.atomicswap.isAtomicSwap) {
        return ChainService.getRedeemSendMaxInfo(this, wallet, opts, cb);
      }
      return ChainService.getWalletSendMaxInfo(this, wallet, opts, cb);
    });
  }

  _sampleFeeLevels(coin, network, points, cb) {
    const bc = this._getBlockchainExplorer(coin, network);
    if (!bc) return cb(new Error('Could not get blockchain explorer instance'));
    bc.estimateFee(points, (err, result) => {
      if (err) {
        this.logw('Error estimating fee', err);
        return cb(err);
      }

      const failed = [];
      const levels = _.fromPairs(
        _.map(points, p => {
          const feePerKb = _.isObject(result) && result[p] && _.isNumber(result[p]) ? +result[p] : -1;
          if (feePerKb < 0) failed.push(p);

          // NOTE: ONLY BTC/BCH/DOGE/LTC expect feePerKb to be Bitcoin amounts
          // others... expect wei.

          return ChainService.convertFeePerKb(coin, p, feePerKb);
        })
      );

      if (failed.length) {
        const logger = network == 'livenet' ? this.logw : this.logi;
        logger('Could not compute fee estimation in ' + network + ': ' + failed.join(', ') + ' blocks.');
      }

      return cb(null, levels, failed.length);
    });
  }

  /**
   * Returns fee levels for the current state of the network.
   * @param {Object} opts
   * @param {string} [opts.coin = 'vcl'] - The coin to estimate fee levels from.
   * @param {string} [opts.network = 'livenet'] - The Bitcoin network to estimate fee levels from.
   * @returns {Object} feeLevels - A list of fee levels & associated amount per kB in satoshi.
   */
  getFeeLevels(opts, cb) {
    opts = opts || {};

    opts.coin = opts.coin || Defaults.COIN;
    if (!Utils.checkValueInCollection(opts.coin, Constants.COINS)) return cb(new ClientError('Invalid coin'));

    opts.network = opts.network || 'livenet';
    if (!Utils.checkValueInCollection(opts.network, Constants.NETWORKS)) return cb(new ClientError('Invalid network'));

    const cacheKey = 'feeLevel:' + opts.coin + ':' + opts.network;

    this.storage.checkAndUseGlobalCache(cacheKey, Defaults.FEE_LEVEL_CACHE_DURATION, (err, values, oldvalues) => {
      if (err) return cb(err);
      if (values) return cb(null, values, true);

      const feeLevels = Defaults.FEE_LEVELS[opts.coin];

      /*
      if (opts.coin === 'doge') {
        const defaultDogeFeeLevels = feeLevels[0];
        const result: {
          feePerKb?: number;
          nbBlocks?: number;
          level: string;
        } = {
          level: defaultDogeFeeLevels.name,
          nbBlocks: defaultDogeFeeLevels.nbBlocks,
          feePerKb: defaultDogeFeeLevels.defaultValue
        };
        return cb(null, [result]);
      }
      */

      const samplePoints = () => {
        const definedPoints = _.uniq(_.map(feeLevels, 'nbBlocks'));
        return _.uniq(
          _.flatten(
            _.map(definedPoints, p => {
              return _.range(p, p + Defaults.FEE_LEVELS_FALLBACK + 1);
            })
          )
        );
      };

      const getFeeLevel = (feeSamples, level, n, fallback) => {
        let result;

        if (feeSamples[n] >= 0) {
          result = {
            nbBlocks: n,
            feePerKb: feeSamples[n]
          };
        } else {
          if (fallback > 0) {
            result = getFeeLevel(feeSamples, level, n + 1, fallback - 1);
          } else {
            result = {
              feePerKb: level.defaultValue,
              nbBlocks: null
            };
          }
        }
        return result;
      };

      this._sampleFeeLevels(opts.coin, opts.network, samplePoints(), (err, feeSamples, failed) => {
        if (err) {
          if (oldvalues) {
            this.logw('##  There was an error estimating fees... using old cached values');
            return cb(null, oldvalues, true);
          }
        }

        const values = _.map(feeLevels, level => {
          const result: {
            feePerKb?: number;
            nbBlocks?: number;
            level: string;
          } = {
            level: level.name
          };
          if (err) {
            result.feePerKb = level.defaultValue;
            result.nbBlocks = null;
          } else {
            const feeLevel = getFeeLevel(feeSamples, level, level.nbBlocks, Defaults.FEE_LEVELS_FALLBACK);
            result.feePerKb = +(feeLevel.feePerKb * (level.multiplier || 1)).toFixed(0);
            result.nbBlocks = feeLevel.nbBlocks;
          }
          return result;
        });

        // Ensure monotonically decreasing values
        for (let i = 1; i < values.length; i++) {
          values[i].feePerKb = Math.min(values[i].feePerKb, values[i - 1].feePerKb);
        }

        if (failed > 0) {
          this.logw('Not caching default values. Failed:' + failed);
          return cb(null, values);
        }

        this.storage.storeGlobalCache(cacheKey, values, err => {
          if (err) {
            this.logw('Could not store fee level cache');
          }
          return cb(null, values);
        });
      });
    });
  }

  _canCreateTx(cb) {
    this.storage.fetchLastTxs(this.walletId, this.copayerId, 5 + Defaults.BACKOFF_OFFSET, (err, txs) => {
      if (err) return cb(err);

      if (!txs.length) return cb(null, true);

      const lastRejections = _.takeWhile(txs, {
        status: 'rejected'
      });

      const exceededRejections = lastRejections.length - Defaults.BACKOFF_OFFSET;
      if (exceededRejections <= 0) return cb(null, true);

      const lastTxTs = txs[0].createdOn;
      const now = Math.floor(Date.now() / 1000);
      const timeSinceLastRejection = now - lastTxTs;
      const backoffTime = Defaults.BACKOFF_TIME;

      if (timeSinceLastRejection <= backoffTime)
        this.logd('Not allowing to create TX: timeSinceLastRejection/backoffTime', timeSinceLastRejection, backoffTime);

      return cb(null, timeSinceLastRejection > backoffTime);
    });
  }

  _validateOutputs(opts, wallet, cb) {
    if (_.isEmpty(opts.outputs)) return new ClientError('No outputs were specified');

    for (let i = 0; i < opts.outputs.length; i++) {
      const output = opts.outputs[i];
      output.valid = false;

      try {
        ChainService.validateAddress(wallet, output.toAddress, opts);
      } catch (addrErr) {
        return addrErr;
      }

      if (!checkRequired(output, ['toAddress', 'amount'])) {
        return new ClientError('Argument missing in output #' + (i + 1) + '.');
      }

      // john 20220219
      if (!opts.txExtends) {
        if (!ChainService.checkValidTxAmount(wallet.coin, output)) {
          return new ClientError('Invalid amount');
        }

        const error = ChainService.checkDust(wallet.coin, output, opts);
        if (error) return error;
      }
      output.valid = true;
    }
    return null;
  }

  _validateAndSanitizeTxOpts(wallet, opts, cb) {
    async.series(
      [
        next => {
          const feeArgs =
            boolToNum(!!opts.feeLevel) + boolToNum(_.isNumber(opts.feePerKb)) + boolToNum(_.isNumber(opts.fee));
          if (feeArgs > 1) return next(new ClientError('Only one of feeLevel/feePerKb/fee can be specified'));

          if (feeArgs == 0) {
            opts.feeLevel = 'normal';
          }

          const feeLevels = Defaults.FEE_LEVELS[wallet.coin];
          if (opts.feeLevel) {
            if (
              !_.some(feeLevels, {
                name: opts.feeLevel
              })
            )
              return next(
                new ClientError('Invalid fee level. Valid values are ' + _.map(feeLevels, 'name').join(', '))
              );
          }

          const error = ChainService.checkUtxos(wallet.coin, opts);
          if (error) {
            return next(new ClientError('fee can only be set when inputs are specified'));
          }
          next();
        },
        next => {
          if (wallet.singleAddress && opts.changeAddress)
            return next(new ClientError('Cannot specify change address on single-address wallet'));
          next();
        },

        next => {
          if (!opts.sendMax) return next();
          if (!_.isArray(opts.outputs) || opts.outputs.length > 1) {
            return next(new ClientError('Only one output allowed when sendMax is specified'));
          }
          if (_.isNumber(opts.outputs[0].amount))
            return next(new ClientError('Amount is not allowed when sendMax is specified'));
          if (_.isNumber(opts.fee))
            return next(
              new ClientError('Fee is not allowed when sendMax is specified (use feeLevel/feePerKb instead)')
            );

          this.getSendMaxInfo(
            {
              feePerKb: opts.feePerKb,
              excludeUnconfirmedUtxos: !!opts.excludeUnconfirmedUtxos,
              returnInputs: true,
              excludeMasternode: !!opts.excludeMasternode,
              atomicswap: opts.atomicswap
            },
            (err, info) => {
              if (err) return next(err);
              opts.outputs[0].amount = info.amount;
              opts.inputs = info.inputs;
              return next();
            }
          );
        },
        next => {
          const validationError = this._validateOutputs(opts, wallet, next);
          if (validationError) {
            return next(validationError);
          }
          next();
        },
        next => {
          // check outputs are on 'copay' format for BCH
          if (wallet.coin != 'bch') return next();
          if (!opts.noCashAddr) return next();

          // TODO remove one cashaddr is used internally (noCashAddr flag)?
          opts.origAddrOutputs = _.map(opts.outputs, x => {
            const ret: {
              toAddress?: string;
              amount?: number;
              message?: string;
            } = {
              toAddress: x.toAddress,
              amount: x.amount
            };
            if (x.message) ret.message = x.message;

            return ret;
          });
          opts.returnOrigAddrOutputs = false;
          _.each(opts.outputs, x => {
            if (!x.toAddress) return;

            let newAddr;
            try {
              newAddr = Bitcore_['bch'].Address(x.toAddress).toLegacyAddress();
            } catch (e) {
              return next(e);
            }
            if (x.txAddress != newAddr) {
              x.toAddress = newAddr;
              opts.returnOrigAddrOutputs = true;
            }
          });
          next();
        }
      ],
      cb
    );
  }

  _getFeePerKb(wallet, opts, cb) {
    if (_.isNumber(opts.feePerKb)) return cb(null, opts.feePerKb);
    this.getFeeLevels(
      {
        coin: wallet.coin,
        network: wallet.network
      },
      (err, levels) => {
        if (err) return cb(err);
        const level = levels.find(l => l.level === opts.feeLevel);
        if (!level) {
          const msg = 'Could not compute fee for "' + opts.feeLevel + '" level';
          this.logw(msg);
          return cb(new ClientError(msg));
        }
        return cb(null, level.feePerKb);
      }
    );
  }

  _getTransactionCount(wallet, address, cb) {
    const bc = this._getBlockchainExplorer(wallet.coin, wallet.network);
    if (!bc) return cb(new Error('Could not get blockchain explorer instance'));
    bc.getTransactionCount(address, (err, nonce) => {
      if (err) {
        this.logw('Error estimating nonce', err);
        return cb(err);
      }
      return cb(null, nonce);
    });
  }

  getNonce(opts) {
    const bc = this._getBlockchainExplorer(opts.coin, opts.network);
    return new Promise((resolve, reject) => {
      if (!bc) return reject(new Error('Could not get blockchain explorer instance'));
      bc.getTransactionCount(opts.address, (err, nonce) => {
        if (err) {
          this.logw('Error estimating nonce', err);
          return reject(err);
        }
        return resolve(nonce);
      });
    });
  }

  estimateGas(opts) {
    const bc = this._getBlockchainExplorer(opts.coin, opts.network);
    return new Promise((resolve, reject) => {
      if (!bc) return reject(new Error('Could not get blockchain explorer instance'));
      bc.estimateGas(opts, (err, gasLimit) => {
        if (err) {
          this.logw('Error estimating gas limit', err);
          return reject(err);
        }
        return resolve(gasLimit);
      });
    });
  }

  getMultisigContractInstantiationInfo(opts) {
    const bc = this._getBlockchainExplorer('eth', opts.network);
    return new Promise((resolve, reject) => {
      if (!bc) return reject(new Error('Could not get blockchain explorer instance'));
      bc.getMultisigContractInstantiationInfo(opts, (err, contractInstantiationInfo) => {
        if (err) {
          this.logw('Error getting contract instantiation info', err);
          return reject(err);
        }
        return resolve(contractInstantiationInfo);
      });
    });
  }

  getMultisigContractInfo(opts) {
    const bc = this._getBlockchainExplorer('eth', opts.network);
    return new Promise((resolve, reject) => {
      if (!bc) return reject(new Error('Could not get blockchain explorer instance'));
      bc.getMultisigContractInfo(opts, (err, contractInfo) => {
        if (err) {
          this.logw('Error getting contract instantiation info', err);
          return reject(err);
        }
        return resolve(contractInfo);
      });
    });
  }

  getTokenContractInfo(opts) {
    const bc = this._getBlockchainExplorer('eth', opts.network);
    return new Promise((resolve, reject) => {
      if (!bc) return reject(new Error('Could not get blockchain explorer instance'));
      bc.getTokenContractInfo(opts, (err, contractInfo) => {
        if (err) {
          this.logw('Error getting contract info', err);
          return reject(err);
        }
        return resolve(contractInfo);
      });
    });
  }

  getMultisigTxpsInfo(opts) {
    const bc = this._getBlockchainExplorer('eth', opts.network);
    return new Promise((resolve, reject) => {
      if (!bc) return reject(new Error('Could not get blockchain explorer instance'));
      bc.getMultisigTxpsInfo(opts, (err, multisigTxpsInfo) => {
        if (err) {
          this.logw('Error getting contract txps hash', err);
          return reject(err);
        }
        return resolve(multisigTxpsInfo);
      });
    });
  }

  /**
   * Creates a new transaction proposal.
   * @param {Object} opts
   * @param {string} opts.txProposalId - Optional. If provided it will be used as this TX proposal ID. Should be unique in the scope of the wallet.
   * @param {String} opts.coin - tx coin.
   * @param {Array} opts.outputs - List of outputs.
   * @param {string} opts.outputs[].toAddress - Destination address.
   * @param {number} opts.outputs[].amount - Amount to transfer in satoshi.
   * @param {string} opts.outputs[].message - A message to attach to this output.
   * @param {string} opts.message - A message to attach to this transaction.
   * @param {number} opts.feeLevel[='normal'] - Optional. Specify the fee level for this TX ('priority', 'normal', 'economy', 'superEconomy') as defined in Defaults.FEE_LEVELS.
   * @param {number} opts.feePerKb - Optional. Specify the fee per KB for this TX (in satoshi).
   * @param {string} opts.changeAddress - Optional. Use this address as the change address for the tx. The address should belong to the wallet. In the case of singleAddress wallets, the first main address will be used.
   * @param {Boolean} opts.sendMax - Optional. Send maximum amount of funds that make sense under the specified fee/feePerKb conditions. (defaults to false).
   * @param {string} opts.payProUrl - Optional. Paypro URL for peers to verify TX
   * @param {Boolean} opts.excludeUnconfirmedUtxos[=false] - Optional. Do not use UTXOs of unconfirmed transactions as inputs
   * @param {Boolean} opts.dryRun[=false] - Optional. Simulate the action but do not change server state.
   * @param {Array} opts.inputs - Optional. Inputs for this TX
   * @param {Array} opts.txpVersion - Optional. Version for TX Proposal (current = 4, only =3 allowed).
   * @param {number} opts.fee - Optional. Use an fixed fee for this TX (only when opts.inputs is specified)
   * @param {Boolean} opts.noShuffleOutputs - Optional. If set, TX outputs won't be shuffled. Defaults to false
   * @param {Boolean} opts.noCashAddr - do not use cashaddress for bch
   * @param {Boolean} opts.signingMethod[=ecdsa] - do not use cashaddress for bch
   * @param {number} opts.tokenId - optional. ETH ERC721 Contract TokenID
   * @param {string} opts.tokenAddress - optional. ERC20 Token Contract Address
   * @param {string} opts.multisigContractAddress - optional. MULTISIG ETH Contract Address
   * @param {Boolean} opts.isTokenSwap - Optional. To specify if we are trying to make a token swap
   * @param {Boolean} opts.enableRBF - Optional. enable BTC Replace By Fee
   * @param {Boolean} opts.replaceTxByFee - Optional. Ignore locked utxos check ( used for replacing a transaction designated as RBF)
   * @returns {TxProposal} Transaction proposal. outputs address format will use the same format as inpunt.
   */
  createTx(opts, cb) {
    opts = opts ? _.clone(opts) : {};

    // john 20220709
    if (opts.asset && opts.asset.version) {
      return this.createAsset(opts, cb);
    }

    if (opts.relay && opts.relay.cmd) {
      return this.createRelay(opts, cb);
    }

    const checkTxpAlreadyExists = (txProposalId, cb) => {
      if (!txProposalId) return cb();
      this.storage.fetchTx(this.walletId, txProposalId, cb);
    };

    // john 20220219
    if (opts.txExtends) {
      if (opts.txExtends.version == Constants.TX_VERSION_MN_REGISTER) {
        if (!opts.txExtends.masternodePrivKey) return cb(new Error('txExtends masternodePrivKey is require'));
      }
    }

    this._runLocked(
      cb,
      cb => {
        let changeAddress, feePerKb, gasPrice, gasLimit, fee;
        this.getWallet({}, (err, wallet) => {
          if (err) return cb(err);
          if (!wallet.isComplete()) return cb(Errors.WALLET_NOT_COMPLETE);

          if (wallet.scanStatus == 'error') return cb(Errors.WALLET_NEED_SCAN);

          if (config.suspendedChains && config.suspendedChains.includes(wallet.coin)) {
            let Err = Errors.NETWORK_SUSPENDED;
            Err.message = Err.message.replace('$network', wallet.coin.toUpperCase());
            return cb(Err);
          }

          checkTxpAlreadyExists(opts.txProposalId, (err, txp) => {
            if (err) return cb(err);
            if (txp) return cb(null, txp);

            async.series(
              [
                next => {
                  if (ChainService.isUTXOCoin(wallet.coin)) return next();
                  this.getMainAddresses({ reverse: true, limit: 1 }, (err, mainAddr) => {
                    if (err) return next(err);
                    opts.from = mainAddr[0].address;
                    next();
                  });
                },
                next => {
                  this._validateAndSanitizeTxOpts(wallet, opts, next);
                },
                next => {
                  this._canCreateTx((err, canCreate) => {
                    if (err) return next(err);
                    if (!canCreate) return next(Errors.TX_CANNOT_CREATE);
                    next();
                  });
                },
                async next => {
                  if (opts.sendMax) return next();
                  try {
                    changeAddress = await ChainService.getChangeAddress(this, wallet, opts);
                  } catch (error) {
                    return next(error);
                  }
                  return next();
                },
                async next => {
                  if (_.isNumber(opts.fee) && !_.isEmpty(opts.inputs)) return next();

                  try {
                    ({ feePerKb, gasPrice, gasLimit, fee } = await ChainService.getFee(this, wallet, opts));
                  } catch (error) {
                    return next(error);
                  }
                  next();
                },
                async next => {
                  if (!opts.nonce) {
                    try {
                      opts.nonce = await ChainService.getTransactionCount(this, wallet, opts.from);
                    } catch (error) {
                      return next(error);
                    }
                  }
                  return next();
                },
                async next => {
                  opts.signingMethod = opts.signingMethod || 'ecdsa';
                  opts.coin = opts.coin || wallet.coin;

                  if (!['ecdsa', 'schnorr'].includes(opts.signingMethod)) {
                    return next(Errors.WRONG_SIGNING_METHOD);
                  }

                  //  schnorr only on BCH
                  if (opts.coin != 'bch' && opts.signingMethod == 'schnorr') return next(Errors.WRONG_SIGNING_METHOD);

                  return next();
                },
                next => {
                  let txOptsFee = fee;

                  if (!txOptsFee) {
                    const useInputFee = opts.inputs && !_.isNumber(opts.feePerKb);
                    const isNotUtxoCoin = !ChainService.isUTXOCoin(wallet.coin);
                    const shouldUseOptsFee = useInputFee || isNotUtxoCoin;

                    if (shouldUseOptsFee) {
                      txOptsFee = opts.fee;
                    }
                  }
                  // john 20220219
                  var txType;
                  var maxPriorityFeePerGas;
                  var maxFeePerGas;
                  if (opts.coin === 'eth') {
                    txType = opts.txType || 2;
                    maxPriorityFeePerGas = opts.maxPriorityFeePerGas || 1000000007;
                    maxFeePerGas = opts.maxFeePerGas || 1000000007;
                  }

                  const txOpts = {
                    id: opts.txProposalId,
                    walletId: this.walletId,
                    creatorId: this.copayerId,
                    coin: opts.coin,
                    chain: opts.chain ? opts.chain : ChainService.getChain(opts.coin),
                    network: wallet.network,
                    outputs: opts.outputs,
                    message: opts.message,
                    from: opts.from,
                    changeAddress,
                    feeLevel: opts.feeLevel,
                    feePerKb,
                    payProUrl: opts.payProUrl,
                    walletM: wallet.m,
                    walletN: wallet.n,
                    excludeUnconfirmedUtxos: !!opts.excludeUnconfirmedUtxos,
                    instantAcceptanceEscrow: opts.instantAcceptanceEscrow,
                    addressType: wallet.addressType,
                    customData: opts.customData,
                    inputs: opts.inputs,
                    version: opts.txpVersion,
                    fee: txOptsFee,
                    noShuffleOutputs: opts.noShuffleOutputs,
                    gasPrice,
                    nonce: opts.nonce,
                    gasLimit, // Backward compatibility for BWC < v7.1.1
                    data: opts.data, // Backward compatibility for BWC < v7.1.1
                    tokenAddress: opts.tokenAddress,
                    multisigContractAddress: opts.multisigContractAddress,
                    destinationTag: opts.destinationTag,
                    invoiceID: opts.invoiceID,
                    signingMethod: opts.signingMethod,
                    isTokenSwap: opts.isTokenSwap,
                    enableRBF: opts.enableRBF,
                    replaceTxByFee: opts.replaceTxByFee,
                    txExtends: opts.txExtends, // 20220219
                    txType,
                    maxPriorityFeePerGas,
                    maxFeePerGas,
                    accessList: opts.accessList || [],
                    tokenId: opts.tokenId // 20220423
                  };
                  txp = TxProposal.create(txOpts);
                  next();
                },
                next => {
                  return ChainService.selectTxInputs(this, txp, wallet, opts, next);
                },
                async next => {
                  if (!wallet.isZceCompatible(feePerKb) || !opts.instantAcceptanceEscrow) return next();
                  try {
                    opts.inputs = txp.inputs;
                    const escrowAddress = await ChainService.getChangeAddress(this, wallet, opts);
                    txp.escrowAddress = escrowAddress;
                  } catch (error) {
                    return next(error);
                  }
                  if (opts.dryRun) return next();
                  this._store(wallet, txp.escrowAddress, next, true);
                },
                next => {
                  if (!changeAddress || wallet.singleAddress || opts.dryRun || opts.changeAddress) return next();

                  this._store(wallet, txp.changeAddress, next, true);
                },
                next => {
                  if (opts.dryRun) return next();

                  if (txp.coin == 'bch' && txp.changeAddress) {
                    const format = opts.noCashAddr ? 'copay' : 'cashaddr';
                    txp.changeAddress.address = BCHAddressTranslator.translate(txp.changeAddress.address, format);
                  }

                  this.storage.storeTx(wallet.id, txp, next);
                }
              ],
              err => {
                if (err) return cb(err);

                if (txp.coin == 'bch') {
                  if (opts.returnOrigAddrOutputs) {
                    logger.info('Returning Orig BCH address outputs for compat');
                    txp.outputs = opts.origAddrOutputs;
                  }
                }
                return cb(null, txp);
              }
            );
          });
        });
      },
      10 * 1000
    );
  }

  // john 20211228
  /**
   * Creates a new transaction proposal.
   * @param {Object} opts
   * @param {string} opts.txProposalId - Optional. If provided it will be used as this TX proposal ID. Should be unique in the scope of the wallet.
   * @param {Array} opts.atomicswap - atomicswap.
   * @param {Array} opts.atomicswap.contract - atomicswap contract.
   * @param {Array} opts.atomicswap.redeem - atomicswap redeem.
   * @param {String} opts.coin - tx coin.
   * @param {Array} opts.outputs - List of outputs.
   * @param {string} opts.outputs[].toAddress - Destination address.
   * @param {number} opts.outputs[].amount - Amount to transfer in satoshi.
   * @param {string} opts.outputs[].message - A message to attach to this output.
   * @param {string} opts.message - A message to attach to this transaction.
   * @param {number} opts.feeLevel[='normal'] - Optional. Specify the fee level for this TX ('priority', 'normal', 'economy', 'superEconomy') as defined in Defaults.FEE_LEVELS.
   * @param {number} opts.feePerKb - Optional. Specify the fee per KB for this TX (in satoshi).
   * @param {string} opts.changeAddress - Optional. Use this address as the change address for the tx. The address should belong to the wallet. In the case of singleAddress wallets, the first main address will be used.
   * @param {string} opts.payProUrl - Optional. Paypro URL for peers to verify TX
   * @param {Boolean} opts.excludeUnconfirmedUtxos[=false] - Optional. Do not use UTXOs of unconfirmed transactions as inputs
   * @param {Boolean} opts.dryRun[=false] - Optional. Simulate the action but do not change server state.
   * @param {Array} opts.inputs - Optional. Inputs for this TX
   * @param {Array} opts.txpVersion - Optional. Version for TX Proposal (current = 4, only =3 allowed).
   * @param {number} opts.fee - Optional. Use an fixed fee for this TX (only when opts.inputs is specified)
   * @param {Boolean} opts.noShuffleOutputs - Optional. If set, TX outputs won't be shuffled. Defaults to false
   * @param {Boolean} opts.noCashAddr - do not use cashaddress for bch
   * @param {Boolean} opts.signingMethod[=ecdsa] - do not use cashaddress for bch
   * @param {string} opts.tokenAddress - optional. ERC20 Token Contract Address
   * @param {string} opts.multisigContractAddress - optional. MULTISIG ETH Contract Address
   * @param {Boolean} opts.isTokenSwap - Optional. To specify if we are trying to make a token swap
   * @param {Boolean} opts.enableRBF - Optional. enable BTC Replace By Fee
   * @param {Boolean} opts.replaceTxByFee - Optional. Ignore locked utxos check ( used for replacing a transaction designated as RBF)
   * @returns {TxProposal} Transaction proposal. outputs address format will use the same format as inpunt.
   */
  createRedeemTx(opts, cb) {
    opts = opts ? _.clone(opts) : {};

    opts.coin = opts.coin || Defaults.COIN;
    const checkTxpAlreadyExists = (txProposalId, cb) => {
      if (!txProposalId) return cb();
      this.storage.fetchTx(this.walletId, txProposalId, cb);
    };

    // john 20211026
    if (!opts.atomicswap || !opts.atomicswap.contract) return cb(new Error('atomicswap contract is required'));

    // john 20220113
    if (!_.isArray(opts.outputs) || opts.outputs.length > 1) {
      return cb(new ClientError('Only one output allowed'));
    }

    // john 20220219
    if (opts.outputs.length == 1 && opts.outputs[0].toAddress) {
      var addr = new new Bitcore_[opts.coin].Address(opts.outputs[0].toAddress, opts.network)();
      if (addr.type != Bitcore_[opts.coin].Address.PayToPublicKeyHash) {
        return cb(new ClientError('This address type is not supported'));
      }
    }

    this._runLocked(
      cb,
      cb => {
        let changeAddress, feePerKb, gasPrice, gasLimit, fee;
        this.getWallet({}, (err, wallet) => {
          if (err) return cb(err);
          if (!wallet.isComplete()) return cb(Errors.WALLET_NOT_COMPLETE);
          // john 20220219
          if (wallet.n != 1 && wallet.m != 1) return cb(Errors.WALLET_NOT_SUPPORT);
          if (wallet.addressType != Constants.SCRIPT_TYPES.P2PKH) return cb(Errors.WALLET_NOT_SUPPORT);

          if (wallet.scanStatus == 'error') return cb(Errors.WALLET_NEED_SCAN);

          if (config.suspendedChains && config.suspendedChains.includes(wallet.coin)) {
            let Err = Errors.NETWORK_SUSPENDED;
            Err.message = Err.message.replace('$network', wallet.coin.toUpperCase());
            return cb(Err);
          }

          checkTxpAlreadyExists(opts.txProposalId, (err, txp) => {
            if (err) return cb(err);
            if (txp) return cb(null, txp);

            async.series(
              [
                next => {
                  // john 20210409
                  if (opts.outputs[0].amount) {
                    delete opts.outputs[0].amount;
                  }
                  opts.sendMax = true;
                  let cnt = new Bitcore_[txp.coin].atomicswap.AuditContract(opts.atomicswap.contract);
                  if (!cnt.isAtomicSwap) return next(new Error('atomicswap contract is invalid'));
                  opts.atomicswap.lockTime = cnt.lockTime;
                  opts.atomicswap.isAtomicSwap = true;
                  opts.atomicswapAddr = cnt.contractAddr;
                  opts.atomicswapSecretHash = cnt.secretHash;
                  let signAddr;
                  if (opts.atomicswap.redeem) {
                    signAddr = cnt.recipientAddr;
                  } else {
                    signAddr = cnt.refundAddr;
                  }
                  let curTime = Math.round(new Date().getTime() / 1000);
                  if (cnt.lockTime > curTime) {
                    next(new Error('the lock time is no expired'));
                  }
                  this.storage.fetchAddressByWalletId(this.walletId, signAddr, (err, address) => {
                    if (err || !address) return next(new Error('atomicswap signAddr is invalid'));
                    opts.atomicswap.signAddr = address;
                    next();
                  });
                },
                next => {
                  this.getUtxos({ addresses: [opts.atomicswapAddr] }, (err, utxos) => {
                    if (err || !utxos || utxos.length == 0)
                      return next(new Error('atomicswap contract has been spent'));
                    utxos[0].path = opts.atomicswap.signAddr.path;
                    utxos[0].publicKeys = opts.atomicswap.signAddr.publicKeys;
                    opts.atomicswap.utxos = utxos;
                    next();
                  });
                },
                next => {
                  if (ChainService.isUTXOCoin(wallet.coin)) return next();
                  this.getMainAddresses({ reverse: true, limit: 1 }, (err, mainAddr) => {
                    if (err) return next(err);
                    opts.from = mainAddr[0].address;
                    next();
                  });
                },
                next => {
                  this._validateAndSanitizeTxOpts(wallet, opts, next);
                },
                next => {
                  this._canCreateTx((err, canCreate) => {
                    if (err) return next(err);
                    if (!canCreate) return next(Errors.TX_CANNOT_CREATE);
                    next();
                  });
                },
                async next => {
                  if (_.isNumber(opts.fee) && !_.isEmpty(opts.inputs)) return next();

                  try {
                    ({ feePerKb, gasPrice, gasLimit, fee } = await ChainService.getFee(this, wallet, opts));
                  } catch (error) {
                    return next(error);
                  }
                  next();
                },
                async next => {
                  if (!opts.nonce) {
                    try {
                      opts.nonce = await ChainService.getTransactionCount(this, wallet, opts.from);
                    } catch (error) {
                      return next(error);
                    }
                  }
                  return next();
                },
                async next => {
                  opts.signingMethod = opts.signingMethod || 'ecdsa';
                  opts.coin = opts.coin || wallet.coin;

                  if (!['ecdsa', 'schnorr'].includes(opts.signingMethod)) {
                    return next(Errors.WRONG_SIGNING_METHOD);
                  }

                  //  schnorr only on BCH
                  if (opts.coin != 'bch' && opts.signingMethod == 'schnorr') return next(Errors.WRONG_SIGNING_METHOD);

                  return next();
                },
                next => {
                  let txOptsFee = fee;

                  if (!txOptsFee) {
                    const useInputFee = opts.inputs && !_.isNumber(opts.feePerKb);
                    const isNotUtxoCoin = !ChainService.isUTXOCoin(wallet.coin);
                    const shouldUseOptsFee = useInputFee || isNotUtxoCoin;

                    if (shouldUseOptsFee) {
                      txOptsFee = opts.fee;
                    }
                  }

                  const txOpts = {
                    id: opts.txProposalId,
                    walletId: this.walletId,
                    creatorId: this.copayerId,
                    coin: opts.coin,
                    chain: opts.chain ? opts.chain : ChainService.getChain(opts.coin),
                    network: wallet.network,
                    outputs: opts.outputs,
                    message: opts.message,
                    from: opts.from,
                    changeAddress,
                    feeLevel: opts.feeLevel,
                    feePerKb,
                    payProUrl: opts.payProUrl,
                    walletM: wallet.m,
                    walletN: wallet.n,
                    excludeUnconfirmedUtxos: !!opts.excludeUnconfirmedUtxos,
                    instantAcceptanceEscrow: opts.instantAcceptanceEscrow,
                    addressType: wallet.addressType,
                    customData: opts.customData,
                    inputs: opts.inputs,
                    version: opts.txpVersion,
                    fee: txOptsFee,
                    noShuffleOutputs: opts.noShuffleOutputs,
                    gasPrice,
                    nonce: opts.nonce,
                    gasLimit, // Backward compatibility for BWC < v7.1.1
                    data: opts.data, // Backward compatibility for BWC < v7.1.1
                    tokenAddress: opts.tokenAddress,
                    multisigContractAddress: opts.multisigContractAddress,
                    destinationTag: opts.destinationTag,
                    invoiceID: opts.invoiceID,
                    signingMethod: opts.signingMethod,
                    isTokenSwap: opts.isTokenSwap,
                    enableRBF: opts.enableRBF,
                    replaceTxByFee: opts.replaceTxByFee,
                    atomicswap: opts.atomicswap, // john 20210409
                    atomicswapAddr: opts.atomicswapAddr,
                    atomicswapSecretHash: opts.atomicswapSecretHash
                  };
                  txp = TxProposal.create(txOpts);
                  next();
                },
                next => {
                  return ChainService.selectTxInputs(this, txp, wallet, opts, next);
                },
                async next => {
                  if (!wallet.isZceCompatible() || !opts.instantAcceptanceEscrow) return next();
                  try {
                    opts.inputs = txp.inputs;
                    const escrowAddress = await ChainService.getChangeAddress(this, wallet, opts);
                    txp.escrowAddress = escrowAddress;
                  } catch (error) {
                    return next(error);
                  }
                  if (opts.dryRun) return next();
                  this._store(wallet, txp.escrowAddress, next, true);
                },
                next => {
                  if (!changeAddress || wallet.singleAddress || opts.dryRun || opts.changeAddress) return next();

                  if (txp.atomicswap) {
                    if (txp.atomicswap.utxos) {
                      delete txp.atomicswap.utxos;
                    }
                    if (txp.atomicswap.signAddr) {
                      delete txp.atomicswap.signAddr;
                    }
                  }

                  this._store(wallet, txp.changeAddress, next, true);
                },
                next => {
                  if (opts.dryRun) return next();

                  if (txp.atomicswap) {
                    if (txp.atomicswap.utxos) {
                      delete txp.atomicswap.utxos;
                    }
                    if (txp.atomicswap.signAddr) {
                      delete txp.atomicswap.signAddr;
                    }
                  }
                  if (txp.coin == 'bch' && txp.changeAddress) {
                    const format = opts.noCashAddr ? 'copay' : 'cashaddr';
                    txp.changeAddress.address = BCHAddressTranslator.translate(txp.changeAddress.address, format);
                  }

                  this.storage.storeTx(wallet.id, txp, next);
                }
              ],
              err => {
                if (err) return cb(err);

                if (txp.coin == 'bch') {
                  if (opts.returnOrigAddrOutputs) {
                    logger.info('Returning Orig BCH address outputs for compat');
                    txp.outputs = opts.origAddrOutputs;
                  }
                }
                return cb(null, txp);
              }
            );
          });
        });
      },
      10 * 1000
    );
  }
  // john 20211228
  /**
   * Creates a new transaction proposal.
   * @param {Object} opts
   * @param {string} opts.txProposalId - Optional. If provided it will be used as this TX proposal ID. Should be unique in the scope of the wallet.
   * @param {Array} opts.atomicswap - atomicswap.
   * @param {Array} opts.atomicswap.secretHash - atomicswap.secretHash.
   * @param {Array} opts.atomicswap.initiate - atomicswap.initiate.
   * @param {String} opts.coin - tx coin.
   * @param {Array} opts.outputs - List of outputs.
   * @param {string} opts.outputs[].toAddress - Destination address.
   * @param {number} opts.outputs[].amount - Amount to transfer in satoshi.
   * @param {string} opts.outputs[].message - A message to attach to this output.
   * @param {string} opts.message - A message to attach to this transaction.
   * @param {number} opts.feeLevel[='normal'] - Optional. Specify the fee level for this TX ('priority', 'normal', 'economy', 'superEconomy') as defined in Defaults.FEE_LEVELS.
   * @param {number} opts.feePerKb - Optional. Specify the fee per KB for this TX (in satoshi).
   * @param {string} opts.changeAddress - Optional. Use this address as the change address for the tx. The address should belong to the wallet. In the case of singleAddress wallets, the first main address will be used.
   * @param {string} opts.payProUrl - Optional. Paypro URL for peers to verify TX
   * @param {Boolean} opts.excludeUnconfirmedUtxos[=false] - Optional. Do not use UTXOs of unconfirmed transactions as inputs
   * @param {Boolean} opts.dryRun[=false] - Optional. Simulate the action but do not change server state.
   * @param {Array} opts.inputs - Optional. Inputs for this TX
   * @param {Array} opts.txpVersion - Optional. Version for TX Proposal (current = 4, only =3 allowed).
   * @param {number} opts.fee - Optional. Use an fixed fee for this TX (only when opts.inputs is specified)
   * @param {Boolean} opts.noShuffleOutputs - Optional. If set, TX outputs won't be shuffled. Defaults to false
   * @param {Boolean} opts.noCashAddr - do not use cashaddress for bch
   * @param {Boolean} opts.signingMethod[=ecdsa] - do not use cashaddress for bch
   * @param {string} opts.tokenAddress - optional. ERC20 Token Contract Address
   * @param {string} opts.multisigContractAddress - optional. MULTISIG ETH Contract Address
   * @param {Boolean} opts.isTokenSwap - Optional. To specify if we are trying to make a token swap
   * @param {Boolean} opts.enableRBF - Optional. enable BTC Replace By Fee
   * @param {Boolean} opts.replaceTxByFee - Optional. Ignore locked utxos check ( used for replacing a transaction designated as RBF)
   * @returns {TxProposal} Transaction proposal. outputs address format will use the same format as inpunt.
   */
  createAtomicSwapTx(opts, cb) {
    opts = opts ? _.clone(opts) : {};

    opts.coin = opts.coin || Defaults.COIN;
    const checkTxpAlreadyExists = (txProposalId, cb) => {
      if (!txProposalId) return cb();
      this.storage.fetchTx(this.walletId, txProposalId, cb);
    };

    // john 20220113
    if (!_.isArray(opts.outputs) || opts.outputs.length > 1) {
      return cb(new ClientError('Only one output allowed'));
    }

    // john 20220219
    if (opts.outputs.length == 1 && opts.outputs[0].toAddress) {
      var addr = new new Bitcore_[opts.coin].Address(opts.outputs[0].toAddress, opts.network)();
      if (addr.type != Bitcore_[opts.coin].Address.PayToPublicKeyHash) {
        return cb(new ClientError('This address type is not supported'));
      }
    }

    this._runLocked(
      cb,
      cb => {
        let changeAddress, feePerKb, gasPrice, gasLimit, fee;
        this.getWallet({}, (err, wallet) => {
          if (err) return cb(err);
          if (!wallet.isComplete()) return cb(Errors.WALLET_NOT_COMPLETE);
          // john 20220219
          if (wallet.n != 1 && wallet.m != 1) return cb(Errors.WALLET_NOT_SUPPORT);
          if (wallet.addressType != Constants.SCRIPT_TYPES.P2PKH) return cb(Errors.WALLET_NOT_SUPPORT);

          if (wallet.scanStatus == 'error') return cb(Errors.WALLET_NEED_SCAN);

          if (config.suspendedChains && config.suspendedChains.includes(wallet.coin)) {
            let Err = Errors.NETWORK_SUSPENDED;
            Err.message = Err.message.replace('$network', wallet.coin.toUpperCase());
            return cb(Err);
          }

          checkTxpAlreadyExists(opts.txProposalId, (err, txp) => {
            if (err) return cb(err);
            if (txp) return cb(null, txp);

            async.series(
              [
                next => {
                  if (ChainService.isUTXOCoin(wallet.coin)) return next();
                  this.getMainAddresses({ reverse: true, limit: 1 }, (err, mainAddr) => {
                    if (err) return next(err);
                    opts.from = mainAddr[0].address;
                    next();
                  });
                },
                next => {
                  this._validateAndSanitizeTxOpts(wallet, opts, next);
                },
                next => {
                  this._canCreateTx((err, canCreate) => {
                    if (err) return next(err);
                    if (!canCreate) return next(Errors.TX_CANNOT_CREATE);
                    next();
                  });
                },
                async next => {
                  if (opts.sendMax) return next();
                  try {
                    changeAddress = await ChainService.getChangeAddress(this, wallet, opts);
                  } catch (error) {
                    return next(error);
                  }
                  return next();
                },
                next => {
                  if (opts.atomicswap) {
                    this.getMainAddresses(
                      { reverse: true, limit: 1, address: opts.outputs[0].toAddress },
                      (err, addr) => {
                        if (err) return next(err);
                        if (addr && addr.length > 0)
                          return next(new Error('The redemption address must be for another wallet'));
                        next();
                      }
                    );
                  } else {
                    next();
                  }
                },
                async next => {
                  try {
                    let contract = Bitcore_[opts.coin].atomicswap.CreateContract(
                      opts.atomicswap.secretHash,
                      opts.outputs[0].toAddress,
                      changeAddress.address,
                      opts.atomicswap.initiate
                    );
                    let cnt = Bitcore_[opts.coin].atomicswap.AuditContract(contract.hex);
                    if (!cnt.isAtomicSwap) next(new Error('An error occurred in atomicswap contract creation'));
                    opts.outputs[0].toAddress = cnt.contractAddr;
                    opts.atomicswap.contract = contract.hex;
                    opts.atomicswapAddr = cnt.contractAddr;
                    opts.atomicswapSecretHash = cnt.secretHash;
                  } catch (error) {
                    return next(error);
                  }
                  return next();
                },
                async next => {
                  if (_.isNumber(opts.fee) && !_.isEmpty(opts.inputs)) return next();

                  try {
                    ({ feePerKb, gasPrice, gasLimit, fee } = await ChainService.getFee(this, wallet, opts));
                  } catch (error) {
                    return next(error);
                  }
                  next();
                },
                async next => {
                  if (!opts.nonce) {
                    try {
                      opts.nonce = await ChainService.getTransactionCount(this, wallet, opts.from);
                    } catch (error) {
                      return next(error);
                    }
                  }
                  return next();
                },
                async next => {
                  opts.signingMethod = opts.signingMethod || 'ecdsa';
                  opts.coin = opts.coin || wallet.coin;

                  if (!['ecdsa', 'schnorr'].includes(opts.signingMethod)) {
                    return next(Errors.WRONG_SIGNING_METHOD);
                  }

                  //  schnorr only on BCH
                  if (opts.coin != 'bch' && opts.signingMethod == 'schnorr') return next(Errors.WRONG_SIGNING_METHOD);

                  return next();
                },
                next => {
                  let txOptsFee = fee;

                  if (!txOptsFee) {
                    const useInputFee = opts.inputs && !_.isNumber(opts.feePerKb);
                    const isNotUtxoCoin = !ChainService.isUTXOCoin(wallet.coin);
                    const shouldUseOptsFee = useInputFee || isNotUtxoCoin;

                    if (shouldUseOptsFee) {
                      txOptsFee = opts.fee;
                    }
                  }

                  const txOpts = {
                    id: opts.txProposalId,
                    walletId: this.walletId,
                    creatorId: this.copayerId,
                    coin: opts.coin,
                    chain: opts.chain ? opts.chain : ChainService.getChain(opts.coin),
                    network: wallet.network,
                    outputs: opts.outputs,
                    message: opts.message,
                    from: opts.from,
                    changeAddress,
                    feeLevel: opts.feeLevel,
                    feePerKb,
                    payProUrl: opts.payProUrl,
                    walletM: wallet.m,
                    walletN: wallet.n,
                    excludeUnconfirmedUtxos: !!opts.excludeUnconfirmedUtxos,
                    instantAcceptanceEscrow: opts.instantAcceptanceEscrow,
                    addressType: wallet.addressType,
                    customData: opts.customData,
                    inputs: opts.inputs,
                    version: opts.txpVersion,
                    fee: txOptsFee,
                    noShuffleOutputs: opts.noShuffleOutputs,
                    gasPrice,
                    nonce: opts.nonce,
                    gasLimit, // Backward compatibility for BWC < v7.1.1
                    data: opts.data, // Backward compatibility for BWC < v7.1.1
                    tokenAddress: opts.tokenAddress,
                    multisigContractAddress: opts.multisigContractAddress,
                    destinationTag: opts.destinationTag,
                    invoiceID: opts.invoiceID,
                    signingMethod: opts.signingMethod,
                    isTokenSwap: opts.isTokenSwap,
                    enableRBF: opts.enableRBF,
                    replaceTxByFee: opts.replaceTxByFee,
                    atomicswap: opts.atomicswap, // john 20210409
                    atomicswapAddr: opts.atomicswapAddr,
                    atomicswapSecretHash: opts.atomicswapSecretHash
                  };
                  txp = TxProposal.create(txOpts);
                  next();
                },
                next => {
                  return ChainService.selectTxInputs(this, txp, wallet, opts, next);
                },
                async next => {
                  if (!wallet.isZceCompatible() || !opts.instantAcceptanceEscrow) return next();
                  try {
                    opts.inputs = txp.inputs;
                    const escrowAddress = await ChainService.getChangeAddress(this, wallet, opts);
                    txp.escrowAddress = escrowAddress;
                  } catch (error) {
                    return next(error);
                  }
                  if (opts.dryRun) return next();
                  this._store(wallet, txp.escrowAddress, next, true);
                },
                next => {
                  if (!changeAddress || wallet.singleAddress || opts.dryRun || opts.changeAddress) return next();

                  this._store(wallet, txp.changeAddress, next, true);
                },
                next => {
                  if (opts.dryRun) return next();

                  if (txp.coin == 'bch' && txp.changeAddress) {
                    const format = opts.noCashAddr ? 'copay' : 'cashaddr';
                    txp.changeAddress.address = BCHAddressTranslator.translate(txp.changeAddress.address, format);
                  }

                  this.storage.storeTx(wallet.id, txp, next);
                }
              ],
              err => {
                if (err) return cb(err);

                if (txp.coin == 'bch') {
                  if (opts.returnOrigAddrOutputs) {
                    logger.info('Returning Orig BCH address outputs for compat');
                    txp.outputs = opts.origAddrOutputs;
                  }
                }
                return cb(null, txp);
              }
            );
          });
        });
      },
      10 * 1000
    );
  }

  /**
   * Publish an already created tx proposal so inputs are locked and other copayers in the wallet can see it.
   * @param {Object} opts
   * @param {string} opts.txProposalId - The tx id.
   * @param {string} opts.proposalSignature - S(raw tx). Used by other copayers to verify the proposal.
   * @param {Boolean} [opts.noCashAddr] - do not use cashaddress for bch
   */
  publishTx(opts, cb) {
    if (!checkRequired(opts, ['txProposalId', 'proposalSignature'], cb)) return;

    this._runLocked(cb, cb => {
      this.getWallet({}, (err, wallet) => {
        if (err) return cb(err);

        if (config.suspendedChains && config.suspendedChains.includes(wallet.coin)) {
          let Err = Errors.NETWORK_SUSPENDED;
          Err.message = Err.message.replace('$network', wallet.coin.toUpperCase());
          return cb(Err);
        }

        this.storage.fetchTx(this.walletId, opts.txProposalId, (err, txp) => {
          if (err) return cb(err);
          if (!txp) return cb(Errors.TX_NOT_FOUND);
          if (!txp.isTemporary()) return cb(null, txp);
          if (txp.txExtends && txp.txExtends.version) {
            if (!opts.outScripts) cb(new Error('outScripts is required'));
            txp.txExtends.outScripts = opts.outScripts;
          }

          const copayer = wallet.getCopayer(this.copayerId);

          //  john 20210409
          if (txp.atomicswap) {
            if (txp.atomicswap.contract) {
              txp.atomicswap.isAtomicSwap = false;
              let cnt = Bitcore_[opts.coin].atomicswap.AuditContract(txp.atomicswap.contract);
              if (cnt.isAtomicSwap) {
                txp.atomicswap.isAtomicSwap = cnt.isAtomicSwap;
                txp.atomicswapAddr = cnt.contractAddr;
                txp.atomicswapSecretHash = cnt.secretHash;
              }
            }
            if (!txp.atomicswap.isAtomicSwap) {
              cb(new Error('atomicswap contract is invalid'));
            }
          }

          let raw;
          try {
            if (txp.coin.toLowerCase() == 'vcl') {
              raw = txp.getRawTx1();
            } else {
              raw = txp.getRawTx();
            }
          } catch (ex) {
            return cb(ex);
          }
          const signingKey = this._getSigningKey(raw, opts.proposalSignature, copayer.requestPubKeys);
          if (!signingKey) {
            return cb(new ClientError('Invalid proposal signature'));
          }

          // Save signature info for other copayers to check
          txp.proposalSignature = opts.proposalSignature;
          if (signingKey.selfSigned) {
            txp.proposalSignaturePubKey = signingKey.key;
            txp.proposalSignaturePubKeySig = signingKey.signature;
          }

          if (txp.atomicswap && txp.atomicswap.isAtomicSwap) {
            this.getUtxos({ addresses: [txp.atomicswapAddr] }, (err, utxos) => {
              if (err || !utxos) return cb(new Error('atomicswap contract  has been spent'));
              txp.status = 'pending';
              this.storage.storeTx(this.walletId, txp, err => {
                if (err) return cb(err);

                this._notifyTxProposalAction('NewTxProposal', txp, () => {
                  return cb(null, txp);
                });
              });
            });
          } else if (txp.asset && txp.asset.version) {
            txp.status = 'pending';
            this.storage.storeTx(this.walletId, txp, err => {
              if (err) return cb(err);

              this._notifyTxProposalAction('NewTxProposal', txp, () => {
                return cb(null, txp);
              });
            });
          } else {
            ChainService.checkTxUTXOs(this, txp, opts, err => {
              if (err) return cb(err);
              txp.status = 'pending';
              this.storage.storeTx(this.walletId, txp, err => {
                if (err) return cb(err);

                this._notifyTxProposalAction('NewTxProposal', txp, () => {
                  if (txp.coin == 'bch' && txp.changeAddress) {
                    const format = opts.noCashAddr ? 'copay' : 'cashaddr';
                    txp.changeAddress.address = BCHAddressTranslator.translate(txp.changeAddress.address, format);
                  }
                  return cb(null, txp);
                });
              });
            });
          }
        });
      });
    });
  }

  /**
   * Retrieves a tx from storage.
   * @param {Object} opts
   * @param {string} opts.txProposalId - The tx id.
   * @returns {Object} txProposal
   */
  getTx(opts, cb) {
    this.storage.fetchTx(this.walletId, opts.txProposalId, (err, txp) => {
      if (err) return cb(err);
      if (!txp) return cb(Errors.TX_NOT_FOUND);

      if (!txp.txid) return cb(null, txp);

      this.storage.fetchTxNote(this.walletId, txp.txid, (err, note) => {
        if (err) {
          this.logw('Error fetching tx note for ' + txp.txid);
        }
        txp.note = note;
        return cb(null, txp);
      });
    });
  }

  /**
   * Edit note associated to a txid.
   * @param {Object} opts
   * @param {string} opts.txid - The txid of the tx on the blockchain.
   * @param {string} opts.body - The contents of the note.
   */
  editTxNote(opts, cb) {
    if (!checkRequired(opts, 'txid', cb)) return;

    this._runLocked(cb, cb => {
      this.storage.fetchTxNote(this.walletId, opts.txid, (err, note) => {
        if (err) return cb(err);

        if (!note) {
          note = TxNote.create({
            walletId: this.walletId,
            txid: opts.txid,
            copayerId: this.copayerId,
            body: opts.body
          });
        } else {
          note.edit(opts.body, this.copayerId);
        }
        this.storage.storeTxNote(note, err => {
          if (err) return cb(err);
          this.storage.fetchTxNote(this.walletId, opts.txid, cb);
        });
      });
    });
  }

  /**
   * Get tx notes.
   * @param {Object} opts
   * @param {string} opts.txid - The txid associated with the note.
   */
  getTxNote(opts, cb) {
    if (!checkRequired(opts, 'txid', cb)) return;
    this.storage.fetchTxNote(this.walletId, opts.txid, cb);
  }

  /**
   * Get tx notes.
   * @param {Object} opts
   * @param {string} opts.minTs[=0] - The start date used to filter notes.
   */
  getTxNotes(opts, cb) {
    opts = opts || {};
    this.storage.fetchTxNotes(this.walletId, opts, cb);
  }

  /**
   * removeWallet
   *
   * @param opts
   * @param cb
   * @return {undefined}
   */
  removeWallet(opts, cb) {
    this._runLocked(cb, cb => {
      this.storage.removeWallet(this.walletId, cb);
    });
  }

  getRemainingDeleteLockTime(txp) {
    const now = Math.floor(Date.now() / 1000);

    const lockTimeRemaining = txp.createdOn + Defaults.DELETE_LOCKTIME - now;
    if (lockTimeRemaining < 0) return 0;

    // not the creator? need to wait
    if (txp.creatorId !== this.copayerId) return lockTimeRemaining;

    // has other approvers? need to wait
    const approvers = txp.getApprovers();
    if (approvers.length > 1 || (approvers.length == 1 && approvers[0] !== this.copayerId)) return lockTimeRemaining;

    return 0;
  }

  /**
   * removePendingTx
   *
   * @param opts
   * @param {string} opts.txProposalId - The tx id.
   * @return {undefined}
   */
  removePendingTx(opts, cb) {
    if (!checkRequired(opts, ['txProposalId'], cb)) return;

    this._runLocked(cb, cb => {
      this.getTx(
        {
          txProposalId: opts.txProposalId
        },
        (err, txp) => {
          if (err) return cb(err);

          if (!txp.isPending()) return cb(Errors.TX_NOT_PENDING);

          const deleteLockTime = this.getRemainingDeleteLockTime(txp);
          if (deleteLockTime > 0) return cb(Errors.TX_CANNOT_REMOVE);

          this.storage.removeTx(this.walletId, txp.id, () => {
            this._notifyTxProposalAction('TxProposalRemoved', txp, cb);
          });
        }
      );
    });
  }

  _broadcastRawTx(coin, network, raw, cb) {
    const bc = this._getBlockchainExplorer(coin, network);
    if (!bc) return cb(new Error('Could not get blockchain explorer instance'));
    bc.broadcast(raw, (err, txid) => {
      if (err) return cb(err);
      return cb(null, txid);
    });
  }

  /**
   * Broadcast a raw transaction.
   * @param {Object} opts
   * @param {string} [opts.coin = 'vcl'] - The coin for this transaction.
   * @param {string} [opts.network = 'livenet'] - The Bitcoin network for this transaction.
   * @param {string} opts.rawTx - Raw tx data.
   */
  broadcastRawTx(opts, cb) {
    if (!checkRequired(opts, ['network', 'rawTx'], cb)) return;

    opts.coin = opts.coin || Defaults.COIN;
    if (!Utils.checkValueInCollection(opts.coin, Constants.COINS)) return cb(new ClientError('Invalid coin'));

    opts.network = opts.network || 'livenet';
    if (!Utils.checkValueInCollection(opts.network, Constants.NETWORKS)) return cb(new ClientError('Invalid network'));

    this._broadcastRawTx(opts.coin, opts.network, opts.rawTx, cb);
  }

  _checkTxInBlockchain(txp, cb) {
    if (!txp.txid) return cb();
    const bc = this._getBlockchainExplorer(txp.coin, txp.network);
    if (!bc) return cb(new Error('Could not get blockchain explorer instance'));
    bc.getTransaction(txp.txid, (err, tx) => {
      if (err) return cb(err);
      return cb(null, !!tx);
    });
  }

  // john 20220114
  getRawTransactionById(opts, cb) {
    if (!opts.txid || !opts.coin || !opts.network) return cb();
    const bc = this._getBlockchainExplorer(opts.coin, opts.network);
    if (!bc) return cb(new Error('Could not get blockchain explorer instance'));
    bc.getRawTransaction(opts.txid, (err, rawHex) => {
      if (err) return cb(err);
      if (!rawHex || _.isEmpty(rawHex)) {
        return cb(new Error('failed to get txid'));
      }
      return cb(null, rawHex);
    });
  }

  // john 20210409
  getAtomicSwapInfo(opts, cb) {
    if (!opts.txid || !opts.coin || !opts.network) return cb();
    const bc = this._getBlockchainExplorer(opts.coin, opts.network);
    if (!bc) return cb(new Error('Could not get blockchain explorer instance'));
    bc.getRawTransaction(opts.txid, (err, rawHex) => {
      if (err) return cb(err);
      if (!rawHex || _.isEmpty(rawHex)) {
        return cb(new Error('failed to get txid'));
      }
      let info = Bitcore_[opts.coin].atomicswap.ExtractContract(rawHex);
      return cb(null, info);
    });
  }

  _checkTxFromAddress(txp, cb) {
    async.series(
      [
        next => {
          // txp.atomicswapStatus = 'pending';
          this.getAddressTx({ addresses: [txp.atomicswapAddr] }, (err, utxos) => {
            if (err || utxos.length != 1) return next(new Error('invalid atomicswap contractAddr'));
            if (utxos[0].spentTxid.length == 0) return cb(null, txp);
            if (utxos[0].spentTxid && txp.atomicswap.initiate) {
              txp.atomicswapStatus = 'finished';
            } else {
              txp.utxo = utxos[0];
            }
            next();
          });
        },
        next => {
          if (txp.utxo) {
            this.getAtomicSwapInfo(
              {
                txid: txp.utxo.spentTxid,
                coin: txp.coin,
                network: txp.network
              },
              (err, info) => {
                delete txp.utxo;
                if (info && info.isAtomicSwap) {
                  if (!info.redeem) {
                    txp.atomicswapStatus = 'finished';
                  } else {
                    txp.atomicswap.secret = info.secret;
                    txp.atomicswapStatus = 'notify';
                  }
                }
                next();
              }
            );
          } else {
            next();
          }
        },
        next => {
          this._processAtomicSwap(
            txp,
            {
              byThirdParty: true,
              state: txp.atomicswapStatus
            },
            next
          );
        }
      ],
      err => {
        if (err) return cb(err);
        return cb(null, txp);
      }
    );
  }

  /*
  _checkTxFromAddress(txp, cb) {
    async.series(
        [
          next => {
            // txp.atomicswapStatus = 'pending';
            this.getAddressTx({addresses: [txp.atomicswapAddr]}, (err,utxos) => {
              if (err || utxos.length != 1) return next(new Error('invalid atomicswap contractAddr'));
              if(utxos[0].spentTxid.length == 0 ) return cb(null, txp);
              if(utxos[0].spentTxid && txp.atomicswap.initiate){
                txp.atomicswapStatus = 'finished';
              }else {
                txp.utxo = utxos[0];
              }
              next()
            });
          },
          next => {
            if(txp.utxo) {
              this.getCoinsForTx({txId: txp.utxo.spentTxid}, (err, tx) => {
                delete txp.utxo;
                if (tx.outputs.length != 1) {
                  txp.atomicswapStatus = 'finished';
                } else {
                  txp.atomicswapRewardAddr = tx.outputs[0].address;
                }
                next();
              });
            }else{
              next();
            }
          },
          next => {
            if(txp.atomicswapRewardAddr) {
              this.getMainAddresses({coin: txp.coin, address: txp.atomicswapRewardAddr}, (err, addresses) => {
                delete txp.atomicswapRewardAddr;
                if (err) cb(err);
                if (!addresses) {
		  // john 20211026
                  if (txp.atomicswap && txp.atomicswap.initiate) {
                    txp.atomicswapStatus = 'finished';
                  } else {
                    txp.atomicswapStatus = 'notify';
                  }
                } else {
                  txp.atomicswapStatus = 'finished';
                }
                next()
              });
            }else{
              next();
            }
          },
          next => {
            this._processAtomicSwap(
                txp,
                {
                  byThirdParty: true,
                  state: txp.atomicswapStatus,
                },
                next
            )
          }
        ],
        err => {
          if (err) return cb(err);
          return cb(null, txp);
        }
    );
  }
  */

  /**
   * Sign a transaction proposal.
   * @param {Object} opts
   * @param {string} opts.txProposalId - The identifier of the transaction.
   * @param {string} opts.signatures - The signatures of the inputs of this tx for this copayer (in appearance order)
   * @param {string} opts.maxTxpVersion - Client's maximum supported txp version
   * @param {boolean} opts.supportBchSchnorr - indication whether to use schnorr for signing tx
   */
  signTx(opts, cb) {
    if (!checkRequired(opts, ['txProposalId', 'signatures'], cb)) return;
    opts.maxTxpVersion = opts.maxTxpVersion || 3;

    this.getWallet({}, (err, wallet) => {
      if (err) return cb(err);

      if (config.suspendedChains && config.suspendedChains.includes(wallet.coin)) {
        let Err = Errors.NETWORK_SUSPENDED;
        Err.message = Err.message.replace('$network', wallet.coin.toUpperCase());
        return cb(Err);
      }

      this.getTx(
        {
          txProposalId: opts.txProposalId
        },
        (err, txp) => {
          if (err) return cb(err);

          if (opts.maxTxpVersion < txp.version) {
            return cb(
              new ClientError(
                Errors.codes.UPGRADE_NEEDED,
                'Your client does not support signing this transaction. Please upgrade'
              )
            );
          }

          //  john 20210409
          if (txp.atomicswap) {
            if (txp.atomicswap.contract) {
              txp.atomicswap.isAtomicSwap = false;
              let cnt = Bitcore_[opts.coin].atomicswap.AuditContract(txp.atomicswap.contract);
              if (cnt.isAtomicSwap) {
                txp.atomicswap.isAtomicSwap = cnt.isAtomicSwap;
                txp.atomicswapAddr = cnt.contractAddr;
                txp.atomicswapSecretHash = cnt.secretHash;
              }
            }
            if (!txp.atomicswap.isAtomicSwap) {
              cb(new Error('atomicswap contract is invalid'));
            }
            if (txp.atomicswap.redeem && !opts.atomicswapSecret) {
              cb(new Error('atomicswap secret is required'));
            }

            if (opts.atomicswapSecret && opts.atomicswapSecret.length == 64) {
              if (
                txp.atomicswapSecretHash !=
                new Bitcore_[opts.coin].crypto.Hash.sha256(Buffer.from(opts.atomicswapSecret, 'hex')).toString('hex')
              ) {
                cb(new Error('atomicswap secret is invalid'));
              }
              txp.atomicswap.secret = opts.atomicswapSecret;
            }
          }

          const action = _.find(txp.actions, {
            copayerId: this.copayerId
          });
          if (action) return cb(Errors.COPAYER_VOTED);
          if (!txp.isPending()) return cb(Errors.TX_NOT_PENDING);

          if (txp.signingMethod === 'schnorr' && !opts.supportBchSchnorr) return cb(Errors.UPGRADE_NEEDED);

          const copayer = wallet.getCopayer(this.copayerId);

          try {
            if (!txp.sign(this.copayerId, opts.signatures, copayer.xPubKey)) {
              this.logw('Error signing transaction (BAD_SIGNATURES)');
              this.logw('Client version:', this.clientVersion);
              this.logw('Arguments:', JSON.stringify(opts));
              this.logw('Transaction proposal:', JSON.stringify(txp));
              const raw = txp.getRawTx();
              this.logw('Raw tx:', raw);
              return cb(Errors.BAD_SIGNATURES);
            }
          } catch (ex) {
            this.logw('Error signing transaction proposal', ex);
            return cb(ex);
          }

          this.storage.storeTx(this.walletId, txp, err => {
            if (err) return cb(err);

            async.series(
              [
                next => {
                  this._notifyTxProposalAction(
                    'TxProposalAcceptedBy',
                    txp,
                    {
                      copayerId: this.copayerId
                    },
                    next
                  );
                },
                next => {
                  if (txp.isAccepted()) {
                    this._notifyTxProposalAction('TxProposalFinallyAccepted', txp, next);
                  } else {
                    next();
                  }
                }
              ],
              () => {
                return cb(null, txp);
              }
            );
          });
        }
      );
    });
  }

  _processBroadcast(txp, opts, cb) {
    $.checkState(txp.txid, 'Failed state: txp.txid undefined at <_processBroadcast()>');
    opts = opts || {};
    txp.setBroadcasted();

    async.series(
      [
        next => {
          // john 20210409
          if (txp.atomicswap && txp.atomicswap.isAtomicSwap && txp.atomicswap.redeem != undefined) {
            this.storage.fetchAtomicSwapBySecretHash(this.walletId, txp, (err, txs) => {
              if (err) return next();
              if (!txs) return next();
              txs = _.reject(txs, tx => {
                return tx.atomicswap.redeem != undefined;
              });

              let tx = txs[0];
              tx.setAtomicswaped();
              this.storage.storeTx(this.walletId, tx, err => {
                if (err) return next(err);
                next();
              });
            });
          } else {
            next();
          }
        },
        next => {
          this.storage.storeTx(this.walletId, txp, err => {
            if (err) return next(err);

            const extraArgs = {
              txid: txp.txid
            };
            if (opts.byThirdParty) {
              this._notifyTxProposalAction('NewOutgoingTxByThirdParty', txp, extraArgs);
            } else {
              this._notifyRedeemTxProposalAction('NewOutgoingTx', txp, extraArgs);
            }
            next();
          });
        },
        next => {
          if (!txp.txExtends) return next();
          if (!txp.txExtends.version) return next();
          if (!txp.txExtends.outScripts) return next();

          if (txp.txExtends.version == Constants.TX_VERSION_MN_REGISTER) {
            try {
              let txProReg = new Bitcore_[txp.coin].masternode.ProRegTx.fromString(txp.txExtends.outScripts);
              if (!txProReg.collateralId) return next();
              let masternodeStatus: {
                createdOn?: number;
                coin?: string;
                network?: string;
                address?: string;
                txid?: string;
                masternodePrivKey?: string;
                masternodePubKey?: string;
                ownerAddr?: string;
                voteAddr?: string;
                payAddr?: string;
                reward?: number;
                walletId?: string;
              } = {};
              masternodeStatus.coin = txp.coin;
              masternodeStatus.network = txp.network;
              masternodeStatus.txid = txProReg.collateralId + '-' + txProReg.collateralIndex;
              masternodeStatus.payAddr = txProReg.payAddr;
              masternodeStatus.voteAddr = txProReg.voteAddr;
              masternodeStatus.ownerAddr = txProReg.ownerAddr;
              masternodeStatus.address = txProReg.host + ':' + parseInt(txProReg.port);
              masternodeStatus.reward = txProReg.reward;
              masternodeStatus.masternodePubKey = txProReg.masternodePubKey;
              masternodeStatus.masternodePrivKey = txp.txExtends.masternodePrivKey;
              masternodeStatus.walletId = this.walletId;
              let masternodes = Masternodes.create(masternodeStatus);
              this.storage.storeMasternode(this.walletId, masternodes, err => {
                if (err) return next(err);
                const extraArgs = {
                  txid: txp.txid
                };
                this._notifyMasternodeAction('NewMasternode', masternodes, extraArgs);
                next();
              });
            } catch (ex) {
              next(ex);
            }
          } else if (txp.txExtends.version == Constants.TX_VERSION_MN_UPDATE_SERVICE) {
            try {
              let txProUpService = new Bitcore_[txp.coin].masternode.ProUpServiceTx.fromString(
                txp.txExtends.outScripts
              );
              if (!txProUpService.proTxHash) return next();
              if (!txProUpService.host || !txProUpService.port) return next();
              let masternode: {
                coin?: string;
                network?: string;
                address?: string;
                payAddr?: string;
                proTxHash?: string;
              } = {};
              masternode.address = txProUpService.host + ':' + txProUpService.port;
              masternode.payAddr = txProUpService.payAddr;
              masternode.coin = txp.coin;
              masternode.network = txp.network;
              masternode.proTxHash = txProUpService.proTxHash;
              this.storage.updateMasternodePart(this.walletId, masternode, err => {
                if (err) return next(err);
                const extraArgs = {
                  txid: txp.txid
                };
                this._notifyMasternodeAction('MasternodeUpService', masternode, extraArgs);
                next();
              });
            } catch (ex) {
              next(ex);
            }
          } else if (txp.txExtends.version == Constants.TX_VERSION_MN_UPDATE_REGISTRAR) {
            try {
              let txProUpReg = new Bitcore_[txp.coin].masternode.ProUpRegTx.fromString(txp.txExtends.outScripts);
              if (!txProUpReg.proTxHash) return next();
              if (!txp.txExtends.masternodePrivKey || !txProUpReg.masternodePubKey) return next();
              if (!txProUpReg.voteAddr || !txProUpReg.payAddr) return next();
              let masternode: {
                coin?: string;
                network?: string;
                masternodePrivKey?: string;
                masternodePubKey?: string;
                voteAddr?: string;
                payAddr?: string;
                proTxHash?: string;
              } = {};
              masternode.masternodePrivKey = txp.txExtends.masternodePrivKey;
              masternode.masternodePubKey = txProUpReg.masternodePubKey;
              masternode.voteAddr = txProUpReg.voteAddr;
              masternode.payAddr = txProUpReg.payAddr;
              masternode.coin = txp.coin;
              masternode.network = txp.network;
              masternode.proTxHash = txProUpReg.proTxHash;
              this.storage.updateMasternodePart(this.walletId, masternode, err => {
                if (err) return next(err);
                const extraArgs = {
                  txid: txp.txid
                };
                this._notifyMasternodeAction('MasternodeUpService', masternode, extraArgs);
                next();
              });
            } catch (ex) {
              next(ex);
            }
          }
        }
      ],
      err => {
        if (err) cb(err);
        return cb(null, txp);
      }
    );
  }

  // john 20210409
  _processAtomicSwap(txp, opts, cb) {
    $.checkState(txp.txid);
    opts = opts || {};

    if (opts.state == 'finished') {
      txp.setAtomicswaped();
    }
    if (txp.atomicswapStatus) {
      delete txp.atomicswapStatus;
    }
    this.storage.storeTx(this.walletId, txp, err => {
      if (err) return cb(err);

      const extraArgs = {
        txid: txp.txid
      };

      if (opts.state == 'notify') {
        if (opts.byThirdParty) {
          this._notifyRedeemTxProposalAction('NewAtomicSwapOutgoingTxByThirdParty', txp, extraArgs);
        } else {
          this._notifyRedeemTxProposalAction('NewAtomicSwapOutgoingTx', txp, extraArgs);
        }
      }

      return cb(null, txp);
    });
  }

  /**
   * Broadcast a transaction proposal.
   * @param {Object} opts
   * @param {string} opts.txProposalId - The identifier of the transaction.
   */
  broadcastTx(opts, cb) {
    if (!checkRequired(opts, ['txProposalId'], cb)) return;

    this.getWallet({}, (err, wallet) => {
      if (err) return cb(err);

      if (config.suspendedChains && config.suspendedChains.includes(wallet.coin)) {
        let Err = Errors.NETWORK_SUSPENDED;
        Err.message = Err.message.replace('$network', wallet.coin.toUpperCase());
        return cb(Err);
      }

      this.getTx(
        {
          txProposalId: opts.txProposalId
        },
        (err, txp) => {
          if (err) return cb(err);

          if (txp.status == 'broadcasted') return cb(Errors.TX_ALREADY_BROADCASTED);
          if (txp.status != 'accepted') return cb(Errors.TX_NOT_ACCEPTED);

          //  john 20210409
          if (txp.atomicswap) {
            if (txp.atomicswap.contract) {
              let cnt = Bitcore_[txp.coin].atomicswap.AuditContract(txp.atomicswap.contract);
              txp.atomicswap.isAtomicSwap = cnt.isAtomicSwap;
            }
            if (!txp.atomicswap.isAtomicSwap) {
              cb(new Error('atomicswap contract is invalid'));
            }
          }

          const sub = TxConfirmationSub.create({
            copayerId: txp.creatorId,
            txid: txp.txid,
            walletId: txp.walletId,
            amount: txp.amount,
            isActive: true,
            isCreator: true
          });
          this.storage.storeTxConfirmationSub(sub, err => {
            if (err) logger.error('Could not store Tx confirmation subscription: ', err);

            let raw;
            try {
              raw = txp.getRawTx();
            } catch (ex) {
              return cb(ex);
            }
            this._broadcastRawTx(wallet.coin, wallet.network, raw, (err, txid) => {
              if (err || txid != txp.txid) {
                if (!err || txp.txid != txid) {
                  logger.warn(`Broadcast failed for: ${raw}`);
                } else {
                  logger.warn(`Broadcast failed: ${err}`);
                }

                const broadcastErr = err;
                // Check if tx already in blockchain
                this._checkTxInBlockchain(txp, (err, isInBlockchain) => {
                  if (err) return cb(err);
                  if (!isInBlockchain) return cb(broadcastErr || 'broadcast error');

                  this._processBroadcast(
                    txp,
                    {
                      byThirdParty: true
                    },
                    cb
                  );
                });
              } else {
                this._processBroadcast(
                  txp,
                  {
                    byThirdParty: false
                  },
                  err => {
                    if (err) return cb(err);
                    return cb(null, txp);
                  }
                );
              }
            });
          });
        }
      );
    });
  }

  /**
   * Reject a transaction proposal.
   * @param {Object} opts
   * @param {string} opts.txProposalId - The identifier of the transaction.
   * @param {string} [opts.reason] - A message to other copayers explaining the rejection.
   */
  rejectTx(opts, cb) {
    if (!checkRequired(opts, ['txProposalId'], cb)) return;

    this.getTx(
      {
        txProposalId: opts.txProposalId
      },
      (err, txp) => {
        if (err) return cb(err);

        const action = _.find(txp.actions, {
          copayerId: this.copayerId
        });

        if (action) return cb(Errors.COPAYER_VOTED);
        if (txp.status != 'pending') return cb(Errors.TX_NOT_PENDING);

        txp.reject(this.copayerId, opts.reason);

        this.storage.storeTx(this.walletId, txp, err => {
          if (err) return cb(err);

          async.series(
            [
              next => {
                this._notifyTxProposalAction(
                  'TxProposalRejectedBy',
                  txp,
                  {
                    copayerId: this.copayerId
                  },
                  next
                );
              },
              next => {
                if (txp.status == 'rejected') {
                  const rejectedBy = _.map(
                    _.filter(txp.actions, {
                      type: 'reject'
                    }),
                    'copayerId'
                  );

                  this._notifyTxProposalAction(
                    'TxProposalFinallyRejected',
                    txp,
                    {
                      rejectedBy
                    },
                    next
                  );
                } else {
                  next();
                }
              }
            ],
            () => {
              return cb(null, txp);
            }
          );
        });
      }
    );
  }

  /**
   * Retrieves pending transaction proposals.
   * @param {Object} opts
   * @param {Boolean} opts.noCashAddr (do not use cashaddr, only for backwards compat)
   * @param {String} opts.tokenAddress ERC20 Token Contract Address
   * @param {String} opts.multisigContractAddress MULTISIG ETH Contract Address
   * @param {String} opts.network  The network of the MULTISIG ETH transactions
   * @returns {TxProposal[]} Transaction proposal.
   */
  async getPendingTxs(opts, cb) {
    if (opts.tokenAddress) {
      return cb();
    } else if (opts.multisigContractAddress) {
      try {
        const multisigTxpsInfo = await this.getMultisigTxpsInfo(opts);
        const txps = await this.storage.fetchEthPendingTxs(multisigTxpsInfo);
        return cb(null, txps);
      } catch (error) {
        return cb(error);
      }
    } else {
      this.storage.fetchPendingTxs(this.walletId, (err, txps) => {
        if (err) return cb(err);

        _.each(txps, txp => {
          txp.deleteLockTime = this.getRemainingDeleteLockTime(txp);
        });

        async.each(
          txps,
          (txp: ITxProposal, next) => {
            if (txp.status != 'accepted') return next();

            this._checkTxInBlockchain(txp, (err, isInBlockchain) => {
              if (err || !isInBlockchain) return next(err);
              this._processBroadcast(
                txp,
                {
                  byThirdParty: true
                },
                next
              );
            });
          },
          err => {
            txps = _.reject(txps, txp => {
              return txp.status == 'broadcasted';
            });

            if (txps[0] && txps[0].coin == 'bch') {
              const format = opts.noCashAddr ? 'copay' : 'cashaddr';
              _.each(txps, x => {
                if (x.changeAddress) {
                  x.changeAddress.address = BCHAddressTranslator.translate(x.changeAddress.address, format);
                }
                _.each(x.outputs, x => {
                  if (x.toAddress) {
                    x.toAddress = BCHAddressTranslator.translate(x.toAddress, format);
                  }
                });
              });
            }
            return cb(err, txps);
          }
        );
      });
    }
  }

  // john 20211228
  /**
   * Retrieves pending transaction proposals.
   * @param {Object} opts
   * @param {Boolean} opts.noCashAddr (do not use cashaddr, only for backwards compat)
   * @param {String} opts.tokenAddress ERC20 Token Contract Address
   * @param {String} opts.multisigContractAddress MULTISIG ETH Contract Address
   * @param {String} opts.network  The network of the MULTISIG ETH transactions
   * @returns {TxProposal[]} Transaction proposal.
   */
  async getPendingAtomicSwapTxs(opts, cb) {
    if (opts.tokenAddress) {
      return cb();
    } else if (opts.multisigContractAddress) {
      try {
        const multisigTxpsInfo = await this.getMultisigTxpsInfo(opts);
        const txps = await this.storage.fetchEthPendingTxs(multisigTxpsInfo);
        return cb(null, txps);
      } catch (error) {
        return cb(error);
      }
    } else {
      this.storage.fetchAtomicSwapPendingTxs(this.walletId, (err, txps) => {
        if (err) return cb(err);

        _.each(txps, txp => {
          txp.deleteLockTime = this.getRemainingDeleteLockTime(txp);
          if (txp.atomicswap) {
            let cnt = new Bitcore_[txp.coin].atomicswap.AuditContract(txp.atomicswap.contract);
            txp.atomicswap.isAtomicSwap = cnt.isAtomicSwap;
          }
        });

        txps = _.reject(txps, txp => {
          return (
            !txp.atomicswap ||
            !txp.atomicswap.isAtomicSwap ||
            txp.atomicswap.redeem != undefined ||
            txp.status != 'broadcasted'
          );
        });

        async.each(
          txps,
          (txp: ITxProposal, next) => {
            this._checkTxInBlockchain(txp, (err, isInBlockchain) => {
              if (err || !isInBlockchain) {
                txp.atomicswapAddr = null;
                return next(err);
              }
              this._checkTxFromAddress(txp, next);
            });
          },
          err => {
            txps = _.reject(txps, txp => {
              return txp.atomicswapAddr == null;
            });

            if (txps[0] && txps[0].coin == 'bch') {
              const format = opts.noCashAddr ? 'copay' : 'cashaddr';
              _.each(txps, x => {
                if (x.changeAddress) {
                  x.changeAddress.address = BCHAddressTranslator.translate(x.changeAddress.address, format);
                }
                _.each(x.outputs, x => {
                  if (x.toAddress) {
                    x.toAddress = BCHAddressTranslator.translate(x.toAddress, format);
                  }
                });
              });
            }
            return cb(err, txps);
          }
        );
      });
    }
  }

  /**
   * Retrieves all transaction proposals in the range (maxTs-minTs)
   * Times are in UNIX EPOCH
   *
   * @param {Object} opts.minTs (defaults to 0)
   * @param {Object} opts.maxTs (defaults to now)
   * @param {Object} opts.limit
   * @returns {TxProposal[]} Transaction proposals, newer first
   */
  getTxs(opts, cb) {
    this.storage.fetchTxs(this.walletId, opts, (err, txps) => {
      if (err) return cb(err);
      return cb(null, txps);
    });
  }

  /**
   * Retrieves notifications after a specific id or from a given ts (whichever is more recent).
   *
   * @param {Object} opts
   * @param {Object} opts.notificationId (optional)
   * @param {Object} opts.minTs (optional) - default 0.
   * @returns {Notification[]} Notifications
   */
  getNotifications(opts, cb) {
    opts = opts || {};

    this.getWallet({}, (err, wallet) => {
      if (err) return cb(err);

      async.map(
        [`${wallet.coin}:${wallet.network}`, this.walletId],
        (walletId, next) => {
          this.storage.fetchNotifications(walletId, opts.notificationId, opts.minTs || 0, next);
        },
        (err, res) => {
          if (err) return cb(err);

          const notifications = _.sortBy(
            _.map(_.flatten(res), (n: INotification) => {
              n.walletId = this.walletId;
              return n;
            }),
            'id'
          );

          return cb(null, notifications);
        }
      );
    });
  }

  _normalizeTxHistory(walletId, txs: any[], dustThreshold, bcHeight, cb) {
    if (_.isEmpty(txs)) return cb(null, txs);

    // console.log('[server.js.2915:txs:] IN NORMALIZE',txs); //TODO
    const now = Math.floor(Date.now() / 1000);

    // One fee per TXID
    const indexedFee: any = _.keyBy(_.filter(txs, { category: 'fee' } as any), 'txid');
    const indexedSend = _.keyBy(_.filter(txs, { category: 'send' } as any), 'txid');
    const seenSend = {};
    const seenReceive = {};

    const moves: { [txid: string]: ITxProposal } = {};
    // remove 'fees' and 'moves' (probably change addresses)
    txs = _.filter(txs, tx => {
      // double spend or error
      // This should be shown on the client, so we dont remove it here
      //    if (tx.height && tx.height <= -3)
      //      return false;

      if (tx.category == 'receive') {
        if (tx.satoshis < dustThreshold) return false;

        const output = {
          address: tx.address,
          amount: Math.abs(tx.satoshis)
        };
        if (seenReceive[tx.txid]) {
          seenReceive[tx.txid].outputs.push(output);
          return false;
        } else {
          tx.outputs = [output];
          seenReceive[tx.txid] = tx;
          return true;
        }
      }
      if (tx.category == 'send') {
        const output = {
          address: tx.address,
          amount: Math.abs(tx.satoshis)
        };
        if (seenSend[tx.txid]) {
          seenSend[tx.txid].outputs.push(output);
          return false;
        } else {
          tx.outputs = [output];
          seenSend[tx.txid] = tx;
          return true;
        }
      }

      // move without send?
      if (tx.category == 'move' && !indexedSend[tx.txid]) {
        const output = {
          address: tx.address,
          amount: Math.abs(tx.satoshis)
        };

        if (moves[tx.txid]) {
          moves[tx.txid].outputs.push(output);
          return false;
        } else {
          moves[tx.txid] = tx;
          tx.outputs = [output];
          return true;
        }
      }
    });

    // Filter out moves:
    // This are moves from the wallet to itself. There are 2+ outputs. one if the change
    // the other a main address for the wallet.
    _.each(moves, (v, k) => {
      if (v.outputs.length <= 1) {
        delete moves[k];
      }
    });

    const fixMoves = cb2 => {
      if (_.isEmpty(moves)) return cb2();

      // each detected duplicate output move
      const moves3 = _.flatten(_.map(_.values(moves), 'outputs'));
      // check output address for change address
      this.storage.fetchAddressesByWalletId(walletId, _.map(moves3, 'address'), (err, addrs) => {
        if (err) return cb(err);

        const isChangeAddress = _.countBy(_.filter(addrs, { isChange: true }), 'address');
        _.each(moves, x => {
          _.remove(x.outputs, i => {
            return isChangeAddress[i.address];
          });
        });
        return cb2();
      });
    };

    fixMoves(err => {
      if (err) return cb(err);

      const ret = _.filter(
        _.map([].concat(txs), tx => {
          const t = new Date(tx.blockTime).getTime() / 1000;
          const c = tx.height >= 0 && bcHeight >= tx.height ? bcHeight - tx.height + 1 : 0;
          const ret = {
            id: tx.id,
            txid: tx.txid,
            confirmations: c,
            blockheight: tx.height > 0 ? tx.height : null,
            fees: tx.fee || (indexedFee[tx.txid] ? Math.abs(indexedFee[tx.txid].satoshis) : null),
            time: t,
            size: tx.size,
            amount: 0,
            action: undefined,
            addressTo: undefined,
            outputs: undefined,
            dust: false,
            error: tx.error,
            internal: tx.internal,
            network: tx.network,
            chain: tx.chain,
            data: tx.data,
            abiType: tx.abiType,
            gasPrice: tx.gasPrice,
            gasLimit: tx.gasLimit,
            receipt: tx.receipt,
            nonce: tx.nonce
          };
          switch (tx.category) {
            case 'send':
              ret.action = 'sent';
              ret.amount = Math.abs(_.sumBy(tx.outputs, 'amount')) || Math.abs(tx.satoshis);
              ret.addressTo = tx.outputs ? tx.outputs[0].address : null;
              ret.outputs = tx.outputs;
              break;
            case 'receive':
              ret.action = 'received';
              ret.outputs = tx.outputs;
              ret.amount = Math.abs(_.sumBy(tx.outputs, 'amount')) || Math.abs(tx.satoshis);
              ret.dust = ret.amount < dustThreshold;
              break;
            case 'move':
              ret.action = 'moved';
              ret.amount = Math.abs(tx.satoshis);
              ret.addressTo = tx.outputs && tx.outputs.length ? tx.outputs[0].address : null;
              ret.outputs = tx.outputs;
              break;
            default:
              ret.action = 'invalid';
          }

          // not available
          // inputs: inputs,
          return ret;

          // filter out dust
        }),
        x => {
          return !x.dust;
        }
      );

      // console.log('[server.js.2965:ret:] END',ret); //TODO
      return cb(null, ret);
    });
  }

  _getBlockchainHeight(coin, network, cb) {
    const cacheKey = Storage.BCHEIGHT_KEY + ':' + coin + ':' + network;

    this.storage.checkAndUseGlobalCache(cacheKey, Defaults.BLOCKHEIGHT_CACHE_TIME, (err, values) => {
      if (err) return cb(err);

      if (values) return cb(null, values.current, values.hash, true);

      values = {};

      const bc = this._getBlockchainExplorer(coin, network);
      if (!bc) return cb(new Error('Could not get blockchain explorer instance'));
      bc.getBlockchainHeight((err, height, hash) => {
        if (!err && height > 0) {
          values.current = height;
          values.hash = hash;
        } else {
          return cb(err || 'wrong height');
        }

        this.storage.storeGlobalCache(cacheKey, values, err => {
          if (err) {
            this.logw('Could not store bc heigth cache');
          }
          return cb(null, values.current, values.hash);
        });
      });
    });
  }

  updateWalletV8Keys(wallet) {
    if (!wallet.beAuthPrivateKey2) {
      this.logd('Adding wallet beAuthKey');
      wallet.updateBEKeys();
    }
  }

  registerWalletV8(wallet: Wallet, cb) {
    if (wallet.beRegistered) {
      return cb();
    }
    const bc = this._getBlockchainExplorer(wallet.coin, wallet.network);

    this.logd('Registering wallet');
    bc.register(wallet, err => {
      if (err) {
        return cb(err);
      }
      wallet.beRegistered = true;
      return this.storage.storeWallet(wallet, err => cb(err, true));
    });
  }

  checkWalletSync(bc, wallet, simpleRun, cb) {
    if (!wallet.addressManager && !wallet.addressManager.receiveAddressIndex) return cb(null, true);

    // check cache
    const totalAddresses = wallet.addressManager.receiveAddressIndex + wallet.addressManager.changeAddressIndex;

    this.storage.getWalletAddressChecked(wallet.id, (err, checkedTotal) => {
      if (checkedTotal == totalAddresses) {
        logger.debug('addresses checked already');
        return cb(null, true);
      }

      // only check total number of addreses
      if (simpleRun) return cb();

      this.storage.walletCheck({ walletId: wallet.id }).then((localCheck: { sum: number }) => {
        bc.getCheckData(wallet, (err, serverCheck) => {
          // If there is an error, just ignore it (server does not support walletCheck)
          if (err) {
            this.logw('Error at bitcore WalletCheck, ignoring' + err);
            return cb();
          }

          const isOK = serverCheck.sum == localCheck.sum;

          if (isOK) {
            logger.debug('Wallet Sync Check OK');
          } else {
            logger.warn('ERROR: Wallet check failed:', localCheck, serverCheck);
            return cb(null, isOK);
          }

          this.storage.setWalletAddressChecked(wallet.id, totalAddresses, err => {
            return cb(null, isOK);
          });
        });
      });
    });
  }

  // Syncs wallet regitration and address with a V8 type blockexplorerer
  syncWallet(wallet, cb, skipCheck?, count?) {
    count = count || 0;
    const bc = this._getBlockchainExplorer(wallet.coin, wallet.network);
    if (!bc) {
      return cb(new Error('Could not get blockchain explorer instance'));
    }

    this.updateWalletV8Keys(wallet);
    this.registerWalletV8(wallet, (err, justRegistered) => {
      if (err) {
        return cb(err);
      }

      // First
      this.checkWalletSync(bc, wallet, true, (err, isOK) => {
        // ignore err
        if (isOK && !justRegistered) return cb();

        this.storage.fetchUnsyncAddresses(this.walletId, (err, addresses) => {
          if (err) {
            return cb(err);
          }

          const syncAddr = (addresses, icb) => {
            if (!addresses || _.isEmpty(addresses)) {
              // this.logi('Addresses already sync');
              return icb();
            }

            const addressStr = _.map(addresses, x => {
              ChainService.addressFromStorageTransform(wallet.coin, wallet.network, x);
              return x.address;
            });

            this.logd('Syncing addresses: ', addressStr.length);
            bc.addAddresses(wallet, addressStr, err => {
              if (err) return cb(err);
              this.storage.markSyncedAddresses(addressStr, icb);
            });
          };

          syncAddr(addresses, err => {
            if (skipCheck || doNotCheckV8) return cb();

            this.checkWalletSync(bc, wallet, false, (err, isOK) => {
              // ignore err
              if (err) return cb();

              if (isOK) return cb();

              if (count++ >= 1) {
                logger.warn('## ERROR: TRIED TO SYNC WALLET AND FAILED. GIVING UP');
                return cb();
              }
              logger.info('Trying to RESYNC wallet... count:' + count);

              // Reset sync and sync again...
              wallet.beRegistered = false;
              this.storage.deregisterWallet(wallet.id, () => {
                this.syncWallet(wallet, cb, false, count);
              });
            });
          });
        });
      });
    });
  }

  static _getResultTx(wallet, indexedAddresses, tx, opts) {
    let amountIn, amountOut, amountOutChange;
    let amount, action, addressTo;
    let inputs, outputs, foreignCrafted;

    const sum = (items, isMine, isChange = false) => {
      const filter: { isMine?: boolean; isChange?: boolean } = {};
      if (_.isBoolean(isMine)) filter.isMine = isMine;
      if (_.isBoolean(isChange)) filter.isChange = isChange;
      return _.sumBy(_.filter(items, filter), 'amount');
    };

    const classify = items => {
      return _.map(items, item => {
        const address = indexedAddresses[item.address];
        return {
          address: item.address,
          amount: item.amount,
          isMine: !!address,
          isChange: address ? address.isChange || wallet.singleAddress : false
        };
      });
    };

    if (tx.outputs.length || tx.inputs.length) {
      inputs = classify(tx.inputs);
      outputs = classify(tx.outputs);
      amountIn = sum(inputs, true);
      amountOut = sum(outputs, true, false);
      amountOutChange = sum(outputs, true, true);
      if (amountIn == amountOut + amountOutChange + (amountIn > 0 ? tx.fees : 0)) {
        amount = amountOut;
        action = 'moved';
      } else {
        // BWS standard sent
        // (amountIn > 0 && amountOutChange >0 && outputs.length <= 2)
        amount = amountIn - amountOut - amountOutChange - (amountIn > 0 && amountOutChange > 0 ? tx.fees : 0);
        action = amount > 0 ? 'sent' : 'received';
      }

      amount = Math.abs(amount);
      if (action == 'sent' || action == 'moved') {
        const firstExternalOutput = outputs.find(o => o.isMine === false);
        addressTo = firstExternalOutput ? firstExternalOutput.address : null;
      }

      if (action == 'sent' && inputs.length != _.filter(inputs, 'isMine').length) {
        foreignCrafted = true;
      }
    } else {
      action = 'invalid';
      amount = 0;
    }

    const formatOutput = o => {
      return {
        amount: o.amount,
        address: o.address
      };
    };

    const newTx = {
      txid: tx.txid,
      action,
      amount,
      fees: tx.fees,
      time: tx.time,
      addressTo,
      confirmations: tx.confirmations,
      foreignCrafted,
      outputs: undefined,
      feePerKb: undefined,
      inputs: undefined
    };

    if (_.isNumber(tx.size) && tx.size > 0) {
      newTx.feePerKb = +((tx.fees * 1000) / tx.size).toFixed();
    }

    if (opts.includeExtendedInfo) {
      newTx.inputs = _.map(inputs, input => {
        return _.pick(input, 'address', 'amount', 'isMine');
      });
      newTx.outputs = _.map(outputs, output => {
        return _.pick(output, 'address', 'amount', 'isMine');
      });
    } else {
      outputs = _.filter(outputs, {
        isChange: false
      });
      if (action == 'received') {
        outputs = _.filter(outputs, {
          isMine: true
        });
      }
      newTx.outputs = _.map(outputs, formatOutput);
    }

    return newTx;
  }

  static _addProposalInfo(tx: any, indexedProposals: { [txid: string]: TxProposal }, opts: any) {
    opts = opts || {};
    const proposal = indexedProposals[tx.txid];
    if (proposal) {
      tx.createdOn = proposal.createdOn;
      tx.proposalId = proposal.id;
      tx.proposalType = proposal.type;
      tx.creatorName = proposal.creatorName;
      tx.message = proposal.message;
      tx.nonce = proposal.nonce;
      tx.actions = _.map(proposal.actions, action => {
        return _.pick(action, ['createdOn', 'type', 'copayerId', 'copayerName', 'comment']);
      });
      _.each(tx.outputs, output => {
        const query = {
          toAddress: output.address,
          amount: output.amount
        };
        if (proposal.outputs) {
          const txpOut = proposal.outputs.find(o => o.toAddress === output.address && o.amount === output.amount);
          output.message = txpOut ? txpOut.message : null;
        }
      });
      tx.customData = proposal.customData;

      tx.createdOn = proposal.createdOn;
      if (opts.includeExtendedInfo) {
        tx.raw = proposal.raw;
      }
      // .sentTs = proposal.sentTs;
      // .merchant = proposal.merchant;
      // .paymentAckMemo = proposal.paymentAckMemo;
    }
  }

  static _addProposalInfo2(tx: any, indexedProposals: { [txid: string]: TxProposal }, opts: any) {
    opts = opts || {};
    const proposal = indexedProposals[tx.txid];
    if (proposal) {
      tx.createdOn = proposal.createdOn;
      tx.proposalId = proposal.id;
      tx.proposalType = proposal.type;
      tx.creatorName = proposal.creatorName;
      tx.message = proposal.message;
      tx.nonce = proposal.nonce;
      tx.actions = _.map(proposal.actions, action => {
        return _.pick(action, ['createdOn', 'type', 'copayerId', 'copayerName', 'comment']);
      });
      _.each(tx.outputs, output => {
        const query = {
          toAddress: output.addresses[0],
          amount: output.value
        };
        if (proposal.outputs) {
          const txpOut = proposal.outputs.find(o => o.toAddress === output.address && o.amount === output.amount);
          output.message = txpOut ? txpOut.message : null;
        }
      });
      tx.customData = proposal.customData;

      tx.createdOn = proposal.createdOn;
    }
  }

  static _addNotesInfo(tx, indexedNotes) {
    const note = indexedNotes[tx.txid];
    if (note) {
      tx.note = _.pick(note, ['body', 'editedBy', 'editedByName', 'editedOn']);
    }
  }

  /**
   * // Create Advertisement
   * @param opts
   * @param cb
   */
  createAdvert(opts, cb) {
    opts = opts ? _.clone(opts) : {};

    // Usually do error checking on preconditions
    if (!checkRequired(opts, ['title'], cb)) {
      return;
    }
    // Check if ad exists already

    const checkIfAdvertExistsAlready = (adId, cb) => {
      this.storage.fetchAdvert(opts.adId, (err, result) => {
        if (err) return cb(err);

        if (result) {
          return cb(Errors.AD_ALREADY_EXISTS);
        }

        if (!result) {
          let x = new Advertisement();

          x.advertisementId = opts.advertisementId || Uuid.v4();
          x.name = opts.name;
          x.title = opts.title;
          x.country = opts.country;
          x.type = opts.type;
          x.body = opts.body;
          x.imgUrl = opts.imgUrl;
          x.linkText = opts.linkText;
          x.linkUrl = opts.linkUrl;
          x.isAdActive = opts.isAdActive;
          x.dismissible = opts.dismissible;
          x.signature = opts.signature;
          x.app = opts.app;
          x.isTesting = opts.isTesting;

          return cb(null, x);
        }
      });
    };

    this._runLocked(
      cb,
      cb => {
        checkIfAdvertExistsAlready(opts.adId, (err, advert) => {
          if (err) throw err;
          if (advert) {
            try {
              this.storage.storeAdvert(advert, cb);
            } catch (err) {
              throw err;
            }
          }
        });
      },
      10 * 1000
    );
  }

  /**
   * Get All active (live) advertisements
   * @param opts
   * @param opts.adId - adId of advert to get
   * @param cb
   */
  getAdvert(opts, cb) {
    this.storage.fetchAdvert(opts.adId, (err, advert) => {
      if (err) return cb(err);
      return cb(null, advert);
    });
  }

  /**
   * Get All active (live) advertisements
   * @param opts
   * @param cb
   */
  getAdverts(opts, cb) {
    this.storage.fetchActiveAdverts((err, adverts) => {
      if (err) return cb(err);
      return cb(null, adverts);
    });
  }

  /**
   * Get adverts by country
   * @param opts.country
   * @param cb
   */
  getAdvertsByCountry(opts, cb) {
    this.storage.fetchAdvertsByCountry(opts.country, (err, adverts) => {
      if (err) return cb(err);
      return cb(null, adverts);
    });
  }

  /**
   * Get All active (live) advertisements
   * @param opts
   * @param cb
   */
  getTestingAdverts(opts, cb) {
    this.storage.fetchTestingAdverts((err, adverts) => {
      if (err) return cb(err);
      return cb(null, adverts);
    });
  }

  /**
   * Get all adverts regardless of inactive or active.
   * @param opts
   * @param cb
   */
  getAllAdverts(opts, cb) {
    this._runLocked(cb, cb => {
      this.getAllAdverts(opts, cb);
    });
  }

  removeAdvert(opts, cb) {
    opts = opts ? _.clone(opts) : {};

    // Usually do error checking on preconditions
    if (!checkRequired(opts, ['adId'], cb)) {
      throw new Error('adId is missing');
    }
    // Check if ad exists already

    const checkIfAdvertExistsAlready = (adId, cb) => {
      this.storage.fetchAdvert(opts.adId, (err, result) => {
        if (err) return cb(err);

        if (!result) {
          throw new Error('Advertisement does not exist: ' + opts.adId);
        }

        if (result) {
          this.logw('Advert already exists');
          return cb(null, adId);
        }
      });
    };

    try {
      this._runLocked(
        cb,
        cb => {
          checkIfAdvertExistsAlready(opts.adId, (err, adId) => {
            if (err) throw err;
            this.storage.removeAdvert(adId, cb); // TODO: add to errordefinitions Errors.ADVERTISEMENT already exists
          });
        },
        10 * 1000
      );
    } catch (err) {
      throw err;
    }
  }

  activateAdvert(opts, cb) {
    opts = opts ? _.clone(opts) : {};
    // Usually do error checking on preconditions
    if (!checkRequired(opts, ['adId'], cb)) {
      throw new Error('adId is missing');
    }

    this.storage.activateAdvert(opts.adId, (err, result) => {
      if (err) return cb(err);
      return cb(null, result);
    });
  }

  deactivateAdvert(opts, cb) {
    opts = opts ? _.clone(opts) : {};
    // Usually do error checking on preconditions
    if (!checkRequired(opts, ['adId'], cb)) {
      throw new Error('adId is missing');
    }

    this.storage.deactivateAdvert(opts.adId, (err, result) => {
      if (err) return cb(err);
      return cb(null, result);
    });
  }

  // john
  static _addProposalInfo1(tx: any, proposal: TxProposal, opts: any) {
    opts = opts || {};
    if (proposal) {
      tx.createdOn = proposal.createdOn;
      tx.proposalId = proposal.id;
      tx.proposalType = proposal.type;
      tx.creatorName = proposal.creatorName;
      tx.message = proposal.message;
      tx.actions = _.map(proposal.actions, action => {
        return _.pick(action, ['createdOn', 'type', 'copayerId', 'copayerName', 'comment']);
      });
      _.each(tx.outputs, output => {
        const query = {
          toAddress: output.address,
          amount: output.amount
        };
        if (proposal.outputs) {
          const txpOut = proposal.outputs.find(o => o.toAddress === output.address && o.amount === output.amount);
          output.message = txpOut ? txpOut.message : null;
        }
      });
      tx.customData = proposal.customData;

      tx.createdOn = proposal.createdOn;
      if (opts.includeExtendedInfo) {
        tx.raw = proposal.raw;
      }
      // .sentTs = proposal.sentTs;
      // .merchant = proposal.merchant;
      // .paymentAckMemo = proposal.paymentAckMemo;
    }
  }

  // john
  async addCustomData(tx) {
    var { err, txs } = await this.storage.fetchTxByHashAsync(tx['txid']);
    if (err || !txs) return tx;
    WalletService._addProposalInfo1(tx, txs, {});
    return tx;
  }

  async addCustomDatas(txs, res, cb) {
    var finalTxs = [];
    for (const tx of txs) {
      var tx1 = await this.addCustomData(tx);
      finalTxs.push(tx1);
    }
    return cb(null, { finalTxs, res });
  }

  tagLowFeeTxs(wallet: IWallet, txs: any[], cb) {
    const unconfirmed = txs.filter(tx => tx.confirmations === 0);
    if (_.isEmpty(unconfirmed)) return cb();

    this.getFeeLevels(
      {
        coin: wallet.coin,
        network: wallet.network
      },
      (err, levels) => {
        if (err) {
          this.logw('Could not fetch fee levels', err);
        } else {
          const level = levels.find(l => l.level === 'superEconomy');
          if (!level || !level.nbBlocks) {
            this.logi('Cannot compute super economy fee level from blockchain');
          } else {
            const minFeePerKb = level.feePerKb;
            _.each(unconfirmed, tx => {
              tx.lowFees = tx.feePerKb < minFeePerKb;
            });
          }
        }
        return cb();
      }
    );
  }

  getTxHistoryV8(bc, wallet, opts, skip, limit, cb) {
    let bcHeight,
      bcHash,
      sinceTx,
      lastTxs,
      cacheStatus,
      resultTxs = [],
      fromCache = false;
    let txsToCache = [],
      fromBc;
    let streamData;
    let streamKey;

    let walletCacheKey = wallet.id;
    if (opts.tokenAddress) {
      wallet.tokenAddress = opts.tokenAddress;
      walletCacheKey = `${wallet.id}-${opts.tokenAddress}`;
    }

    if (opts.multisigContractAddress) {
      wallet.multisigContractAddress = opts.multisigContractAddress;
      walletCacheKey = `${wallet.id}-${opts.multisigContractAddress}`;
    }

    async.series(
      [
        next => {
          // be sure the wallet is onsync
          this.syncWallet(wallet, next, true);
        },
        next => {
          this._getBlockchainHeight(wallet.coin, wallet.network, (err, height, hash) => {
            if (err) return next(err);
            bcHeight = height;
            bcHash = hash;
            streamKey = (this.userAgent || '') + '-' + limit + '-' + bcHash;
            return next();
          });
        },
        next => {
          this.storage.getTxHistoryCacheStatusV8(walletCacheKey, (err, inCacheStatus) => {
            if (err) return cb(err);
            cacheStatus = inCacheStatus;
            return next();
          });
        },
        next => {
          if (skip == 0 || !streamKey) return next();

          logger.debug('Checking streamKey/skip', streamKey, skip);
          this.storage.getTxHistoryStreamV8(walletCacheKey, (err, result) => {
            if (err) return next(err);
            if (!result) return next();

            if (result.streamKey != streamKey) {
              logger.debug('Deleting old stream cache:' + result.streamKey);
              return this.storage.clearTxHistoryStreamV8(walletCacheKey, next);
            }

            streamData = result.items;
            logger.debug(`Using stream cache: ${streamData.length} txs`);
            return next();
          });
        },
        next => {
          if (streamData) {
            lastTxs = streamData;
            return next();
          }

          const startBlock = cacheStatus.updatedHeight || 0;
          logger.debug('GET HISTORY v8 startBlock/bcH]', startBlock, bcHeight); // TODO

          bc.getTransactions(wallet, startBlock, (err, txs) => {
            if (err) return cb(err);
            const dustThreshold = ChainService.getDustAmountValue(wallet.coin);
            this._normalizeTxHistory(walletCacheKey, txs, dustThreshold, bcHeight, (err, inTxs: any[]) => {
              if (err) return cb(err);

              if (cacheStatus.tipTxId) {
                // first item is the most recent tx.
                // removes already cache txs
                lastTxs = _.takeWhile(inTxs, tx => {
                  // cacheTxs are very confirmed, so can't be reorged
                  return tx.txid != cacheStatus.tipTxId;
                });

                // only store stream IF cache is been used.
                //
                logger.info(`Storing stream cache for ${walletCacheKey}: ${lastTxs.length} txs`);
                return this.storage.storeTxHistoryStreamV8(walletCacheKey, streamKey, lastTxs, next);
              }

              lastTxs = inTxs;
              return next();
            });
          });
        },
        next => {
          // Case 1.
          //            t -->
          //  | Old TXS    | ======= LAST TXS ========== \
          //                     ^skip+limit       ^skip

          // Do we have enough results in last txs?
          if (lastTxs.length >= skip + limit) {
            resultTxs = lastTxs.slice(skip, skip + limit);
            fromCache = false;
            fromBc = true;
            return next();
          }
          // Case 2.
          // compose result (if the wallet has move that `limit`txs)
          //            t -->
          //  | Old TXS    |  [x]======= LAST TXS ==========[0] \
          //       ^skip+limit       ^skip
          if (lastTxs.length >= skip) {
            resultTxs = lastTxs.slice(skip); // grab from skip to the end.

            skip = 0;
            limit -= resultTxs.length;
            fromBc = resultTxs.length > 0;
          } else {
            // Case 3.
            //            t -->
            //  | Old TXS ------------------ | ======= LAST TXS ========== \
            //       ^skip+limit       ^skip

            skip -= lastTxs.length;
          }
          // Complete result
          this.storage.getTxHistoryCacheV8(walletCacheKey, skip, limit, (err, oldTxs) => {
            if (err) {
              return next(err);
            }

            if (oldTxs.length) {
              fromCache = true;
            }

            // update confirmations from height
            _.each(oldTxs, x => {
              if (x.blockheight > 0 && bcHeight >= x.blockheight) {
                x.confirmations = bcHeight - x.blockheight + 1;
              }
            });

            resultTxs = resultTxs.concat(oldTxs);
            return next();
          });
        },
        next => {
          if (streamData) {
            return next();
          }
          // We have now TXs from 'tipHeight` to end in `lastTxs`.
          // Store hard confirmed TXs
          // confirmations here is bcHeight - tip + 1, so OK.
          txsToCache = _.filter(lastTxs, i => {
            if (i.confirmations < Defaults.CONFIRMATIONS_TO_START_CACHING) {
              return false;
            }
            if (!cacheStatus.tipHeight) return true;

            return i.blockheight > cacheStatus.tipHeight;
          });

          logger.debug(`Found ${lastTxs.length} new txs. Caching ${txsToCache.length}`);
          if (!txsToCache.length) {
            return next();
          }

          const updateHeight = bcHeight - Defaults.CONFIRMATIONS_TO_START_CACHING;
          this.storage.storeTxHistoryCacheV8(walletCacheKey, cacheStatus.tipIndex, txsToCache, updateHeight, next);
        }
      ],
      err => {
        if (err) return cb(err);
        return cb(null, {
          items: resultTxs,
          fromCache,
          fromBc,
          useStream: !!streamData
        });
      }
    );
  }

  /**
   * Retrieves all transactions (incoming & outgoing)
   * Times are in UNIX EPOCH
   *
   * @param {Object} opts
   * @param {Number} opts.skip (defaults to 0)
   * @param {Number} opts.limit
   * @param {String} opts.tokenAddress ERC20 Token Contract Address
   * @param {String} opts.multisigContractAddress MULTISIG ETH Contract Address
   * @param {Number} opts.includeExtendedInfo[=false] - Include all inputs/outputs for every tx.
   * @returns {TxProposal[]} Transaction proposals, first newer
   */
  getTxHistory(opts, cb) {
    let bc;
    opts = opts || {};

    // 50 is accepted by insight.
    // TODO move it to a bigger number with v8 is fully deployed
    opts.limit = _.isUndefined(opts.limit) ? 50 : opts.limit;
    if (opts.limit > Defaults.HISTORY_LIMIT) return cb(Errors.HISTORY_LIMIT_EXCEEDED);

    this.getWallet({}, (err, wallet) => {
      if (err) return cb(err);

      if (wallet.scanStatus == 'error') return cb(Errors.WALLET_NEED_SCAN);

      if (wallet.scanStatus == 'running') return cb(Errors.WALLET_BUSY);

      bc = this._getBlockchainExplorer(wallet.coin, wallet.network);
      if (!bc) return cb(new Error('Could not get blockchain explorer instance'));

      const from = opts.skip || 0;
      const to = from + opts.limit;

      async.waterfall(
        [
          next => {
            this.getTxHistoryV8(bc, wallet, opts, from, opts.limit, next);
          },
          (txs: { items: Array<{ time: number }> }, next) => {
            if (!txs || _.isEmpty(txs.items)) {
              return next();
            }
            // TODO optimize this...
            // Fetch all proposals in [t - 7 days, t + 1 day]
            const minTs = _.minBy(txs.items, 'time').time - 7 * 24 * 3600;
            const maxTs = _.maxBy(txs.items, 'time').time + 1 * 24 * 3600;

            async.parallel(
              [
                done => {
                  this.storage.fetchTxs(
                    this.walletId,
                    {
                      minTs,
                      maxTs
                    },
                    done
                  );
                },
                done => {
                  this.storage.fetchTxNotes(
                    this.walletId,
                    {
                      minTs
                    },
                    done
                  );
                }
              ],
              (err, res) => {
                return next(err, {
                  txs,
                  txps: res[0],
                  notes: res[1]
                });
              }
            );
          }
        ],
        (err, res: any) => {
          if (err) return cb(err);
          if (!res) return cb(null, []);
          // TODO we are indexing everything again, each query.
          const indexedProposals = _.keyBy(res.txps, 'txid');
          const indexedNotes = _.keyBy(res.notes, 'txid');

          const finalTxs = _.map(res.txs.items, tx => {
            WalletService._addProposalInfo(tx, indexedProposals, opts);
            WalletService._addNotesInfo(tx, indexedNotes);
            return tx;
          });
          this.tagLowFeeTxs(wallet, finalTxs, err => {
            if (err) this.logw('Failed to tag unconfirmed with low fee');

            if (res.txs.fromCache) {
              let p = '';
              if (res.txs.fromBc) {
                p = 'Partial';
              }
              this.logd(`${p} History from cache ${from}/${to}: ${finalTxs.length} txs`);
            } else {
              this.logd(`History from bc ${from}/${to}: ${finalTxs.length} txs`);
            }
            return cb(null, finalTxs, !!res.txs.fromCache, !!res.txs.useStream);
          });
        }
      );
    });
  }

  /**
   * Retrieves all transactions (incoming & outgoing)
   * Times are in UNIX EPOCH
   *
   * @param {Object} opts
   * @param {Number} opts.skip (defaults to 0)
   * @param {Number} opts.limit
   * @param {String} opts.tokenAddress ERC20 Token Contract Address
   * @param {String} opts.multisigContractAddress MULTISIG ETH Contract Address
   * @param {Number} opts.includeExtendedInfo[=false] - Include all inputs/outputs for every tx.
   * @returns {TxProposal[]} Transaction proposals, first newer
   */
  getTxHistory2(opts, cb) {
    let bc;
    opts = opts || {};

    // 50 is accepted by insight.
    // TODO move it to a bigger number with v8 is fully deployed
    opts.pageSize = _.isUndefined(opts.pageSize) ? 50 : opts.pageSize;
    if (opts.pageSize > Defaults.HISTORY_LIMIT) return cb(Errors.HISTORY_LIMIT_EXCEEDED);

    this.getWallet({}, (err, wallet) => {
      if (err) return cb(err);

      if (wallet.scanStatus == 'error') return cb(Errors.WALLET_NEED_SCAN);

      if (wallet.scanStatus == 'running') return cb(Errors.WALLET_BUSY);

      bc = this._getBlockchainExplorer(wallet.coin, wallet.network);
      if (!bc) return cb(new Error('Could not get blockchain explorer instance'));

      const from = (opts.page || 0) * opts.pageSize;
      const to = from + opts.pageSize;
      const zpub = this.xPubTozPub(wallet);

      async.waterfall(
        [
          next => {
            var options = 'details=txs&pageSize=' + opts.pageSize;
            if (opts.page) {
              options += '&page=' + opts.page;
            }

            sjs.utils
              .fetchBackendAccount(config.blockbookUrl, zpub, options, true)
              .then(ret => {
                var ret1 = _.omit(ret, ['tokensAsset', 'tokens', 'transactions']);
                var items = [];
                _.each(ret.transactions, tx => {
                  var item = {
                    txid: tx.txid,
                    confirmations: tx.confirmations,
                    blockheight: tx.blockHeight,
                    fees: tx.fees,
                    time: tx.blockTime,
                    size: tx.hex.length / 2,
                    amount: 0,
                    action: this.getTxType(tx),
                    addressTo: null,
                    outputs: tx.vout,
                    dust: false
                  };
                  items.push(item);
                });
                ret1.transactions = items;
                next(null, ret1);
              })
              .catch(err => {
                next(err);
              });
          },
          (txs: { transactions: Array<{ time: number }> }, next) => {
            if (!txs || _.isEmpty(txs.transactions)) {
              return next();
            }
            // TODO optimize this...
            // Fetch all proposals in [t - 7 days, t + 1 day]
            const minTs = _.minBy(txs.transactions, 'time').time - 7 * 24 * 3600;
            const maxTs = _.maxBy(txs.transactions, 'time').time + 1 * 24 * 3600;
            async.parallel(
              [
                done => {
                  this.storage.fetchTxs(
                    this.walletId,
                    {
                      minTs,
                      maxTs
                    },
                    done
                  );
                },
                done => {
                  this.storage.fetchTxNotes(
                    this.walletId,
                    {
                      minTs
                    },
                    done
                  );
                }
              ],
              (err, res) => {
                return next(err, {
                  txs,
                  txps: res[0],
                  notes: res[1]
                });
              }
            );
          }
        ],
        (err, res: any) => {
          if (err) return cb(err);
          if (!res) return cb(null, []);
          // TODO we are indexing everything again, each query.
          const indexedProposals = _.keyBy(res.txps, 'txid');
          const indexedNotes = _.keyBy(res.notes, 'txid');

          const finalTxs = _.map(res.txs.transactions, tx => {
            WalletService._addProposalInfo2(tx, indexedProposals, opts);
            WalletService._addNotesInfo(tx, indexedNotes);
            return tx;
          });
          res.txs.transactions = finalTxs;
          return cb(null, res.txs);
        }
      );
    });
  }

  /**
   * Scan the blockchain looking for addresses having some activity
   *
   * @param {Object} opts
   * @param {Boolean} opts.includeCopayerBranches (defaults to false)
   * @param {Boolean} opts.startingStep (estimate address number magniture (dflt to 1k), only
   * for optimization)
   */
  scan(opts, cb) {
    opts = opts || {};
    opts.startingStep = opts.startingStep || 1000;

    this.getWallet({}, (err, wallet) => {
      if (err) return cb(err);
      if (!wallet.isComplete()) return cb(Errors.WALLET_NOT_COMPLETE);

      // OCT2018: We dont allow copayer's BIP45 addr scanning anymore (for performance)
      // for BIP44 wallets.
      if (wallet.derivationStrategy === Constants.DERIVATION_STRATEGIES.BIP44) {
        opts.includeCopayerBranches = false;
      }

      // no powerScan when scanning copayer Branches
      if (opts.includeCopayerBranches) {
        opts.startingStep = 1;
      }

      this.storage.clearWalletCache(this.walletId, () => {
        // single address or non UTXO coins do not scan.
        if (wallet.singleAddress) return cb();
        if (!ChainService.isUTXOCoin(wallet.coin)) return cb();

        this._runLocked(cb, cb => {
          wallet.scanStatus = 'running';
          this.storage.storeWallet(wallet, err => {
            if (err) return cb(err);

            const bc = this._getBlockchainExplorer(wallet.coin, wallet.network);
            if (!bc) return cb(new Error('Could not get blockchain explorer instance'));
            opts.bc = bc;
            let step = opts.startingStep;
            async.doWhilst(
              next => {
                this._runScan(wallet, step, opts, next);
              },
              () => {
                step = step / 10;
                return step >= 1;
              },
              cb
            );
          });
        });
      });
    });
  }

  _runScan(wallet: Wallet, step, opts, cb) {
    const scanBranch = (wallet: Wallet, derivator, cb) => {
      let inactiveCounter = 0;
      const allAddresses = [];

      let gap = Defaults.SCAN_ADDRESS_GAP;

      // when powerScanning, we just accept gap<=3
      if (step > 1) {
        gap = _.min([gap, 3]);
      }

      async.whilst(
        () => {
          //      this.logi('Scanning addr branch: %s index: %d gap %d step %d', derivator.id, derivator.index(), inactiveCounter, step);
          return inactiveCounter < gap;
        },
        next => {
          const address = derivator.derive();

          opts.bc.getAddressActivity(address.address, (err, activity) => {
            if (err) return next(err);
            //       console.log('[server.js.3779:address:] SCANING:' + address.address+ ':'+address.path + " :" + !!activity); //TODO

            allAddresses.push(address);
            inactiveCounter = activity ? 0 : inactiveCounter + 1;
            return next();
          });
        },
        err => {
          derivator.rewind(gap);
          return cb(err, _.dropRight(allAddresses, gap));
        }
      );
    };

    const derivators = [];
    _.each([false, true], isChange => {
      derivators.push({
        id: wallet.addressManager.getBaseAddressPath(isChange),
        derive: _.bind(wallet.createAddress, wallet, isChange, step),
        index: _.bind(wallet.addressManager.getCurrentIndex, wallet.addressManager, isChange),
        rewind: _.bind(wallet.addressManager.rewindIndex, wallet.addressManager, isChange, step),
        getSkippedAddress: _.bind(wallet.getSkippedAddress, wallet)
      });
      if (opts.includeCopayerBranches) {
        _.each(wallet.copayers, copayer => {
          if (copayer.addressManager) {
            derivators.push({
              id: copayer.addressManager.getBaseAddressPath(isChange),
              derive: _.bind(copayer.createAddress, copayer, wallet, isChange),
              index: _.bind(copayer.addressManager.getCurrentIndex, copayer.addressManager, isChange),
              rewind: _.bind(copayer.addressManager.rewindIndex, copayer.addressManager, isChange, step)
            });
          }
        });
      }
    });

    async.eachSeries(
      derivators,
      (derivator, next) => {
        let addresses = [];
        scanBranch(wallet, derivator, (err, scannedAddresses) => {
          if (err) return next(err);
          addresses = addresses.concat(scannedAddresses);

          if (step > 1) {
            this.logd('Deriving addresses for scan steps gaps DERIVATOR:' + derivator.id);

            let addr,
              i = 0;
            // tslint:disable-next-line:no-conditional-assignment
            while ((addr = derivator.getSkippedAddress())) {
              addresses.push(addr);
              i++;
            }
            // this.logi(i + ' addresses were added.');
          }

          this._store(wallet, addresses, next);
        });
      },
      error => {
        this.storage.fetchWallet(wallet.id, (err, wallet) => {
          if (err) return cb(err);
          wallet.scanStatus = error ? 'error' : 'success';
          this.storage.storeWallet(wallet, err => {
            return cb(error || err);
          });
        });
      }
    );
  }

  /**
   * Start a scan process.
   *
   * @param {Object} opts
   * @param {Boolean} opts.includeCopayerBranches (defaults to false)
   */
  startScan(opts, cb) {
    const scanFinished = err => {
      const data = {
        result: err ? 'error' : 'success',
        error: undefined
      };
      if (err) data.error = err;
      this._notify('ScanFinished', data, {
        isGlobal: true
      });
    };

    this.getWallet({}, (err, wallet) => {
      if (err) return cb(err);
      if (!wallet.isComplete()) return cb(Errors.WALLET_NOT_COMPLETE);

      // single address or non UTXO coins do not scan.
      if (wallet.singleAddress) return cb();
      if (!ChainService.isUTXOCoin(wallet.coin)) return cb();

      setTimeout(() => {
        wallet.beRegistered = false;
        this.storage.deregisterWallet(wallet.id, () => {
          this.scan(opts, scanFinished);
        });
      }, 100);

      return cb(null, {
        started: true
      });
    });
  }

  /**
   * Returns exchange rate for the specified currency & timestamp.
   * @param {Object} opts
   * @param {string} opts.code - Currency ISO code.
   * @param {Date} [opts.ts] - A timestamp to base the rate on (default Date.now()).
   * @param {String} [opts.provider] - A provider of exchange rates (default 'BitPay').
   * @returns {Object} rates - The exchange rate.
   */
  getFiatRate(opts, cb) {
    if (!checkRequired(opts, ['code'], cb)) return;

    this.fiatRateService.getRate(opts, (err, rate) => {
      if (err) return cb(err);
      return cb(null, rate);
    });
  }

  /**
   * Returns exchange rates of the supported fiat currencies for all coins.
   * @param {Object} opts
   * @param {String} [opts.code] - Currency ISO code (e.g: USD, EUR, ARS).
   * @param {Date} [opts.ts] - A timestamp to base the rate on (default Date.now()).
   * @param {String} [opts.provider] - A provider of exchange rates (default 'BitPay').
   * @returns {Array} rates - The exchange rate.
   */
  getFiatRates(opts, cb) {
    if (_.isNaN(opts.ts) || _.isArray(opts.ts)) return cb(new ClientError('Invalid timestamp'));

    this.fiatRateService.getRates(opts, (err, rates) => {
      if (err) return cb(err);
      return cb(null, rates);
    });
  }

  /**
   * Returns exchange rates of the supported fiat currencies for the specified coin.
   * @param {Object} opts
   * @param {String} opts.coin - The coin requested (btc, bch, eth, xrp, , ltc).
   * @param {String} [opts.code] - Currency ISO code (e.g: USD, EUR, ARS).
   * @param {Date} [opts.ts] - A timestamp to base the rate on (default Date.now()).
   * @param {String} [opts.provider] - A provider of exchange rates (default 'BitPay').
   * @returns {Array} rates - The exchange rate.
   */
  getFiatRatesByCoin(opts, cb) {
    if (!checkRequired(opts, ['coin'], cb)) return;
    if (_.isNaN(opts.ts) || _.isArray(opts.ts)) return cb(new ClientError('Invalid timestamp'));

    this.fiatRateService.getRatesByCoin(opts, (err, rate) => {
      if (err) return cb(err);
      return cb(null, rate);
    });
  }

  /**
   * Returns historical exchange rates for the specified currency & timestamp range.
   * @param {Object} opts
   * @param {string} opts.code - Currency ISO code.
   * @param {Date} opts.ts - The oldest timestamp in the range to Date.now().
   * @param {String} [opts.provider] - A provider of exchange rates (default 'BitPay').
   * @returns {Object} rates - The exchange rate.
   */
  getHistoricalRates(opts, cb) {
    if (!checkRequired(opts, ['code'], cb)) return;

    this.fiatRateService.getHistoricalRates(opts, (err, rates) => {
      if (err) return cb(err);
      return cb(null, rates);
    });
  }

  /**
   * Subscribe this copayer to the Push Notifications service using the specified token.
   * @param {Object} opts
   * @param {string} opts.token - The token representing the app/device.
   * @param {string} [opts.packageName] - The restricted_package_name option associated with this token.
   * @param {string} [opts.platform] - The platform associated with this token.
   * @param {string} [opts.walletId] - The walletId associated with this token.
   */
  pushNotificationsSubscribe(opts, cb) {
    if (!checkRequired(opts, ['token'], cb)) return;
    const sub = PushNotificationSub.create({
      copayerId: this.copayerId,
      token: opts.token,
      packageName: opts.packageName,
      platform: opts.platform,
      walletId: opts.walletId
    });

    this.storage.storePushNotificationSub(sub, cb);
  }

  /**
   * Unsubscribe this copayer to the Push Notifications service using the specified token.
   * @param {Object} opts
   * @param {string} opts.token - The token representing the app/device.
   */
  pushNotificationsUnsubscribe(opts, cb) {
    if (!checkRequired(opts, ['token'], cb)) return;

    this.storage.removePushNotificationSub(this.copayerId, opts.token, cb);
  }

  /**
   * Subscribe this copayer to the specified tx to get a notification when the tx confirms.
   * @param {Object} opts
   * @param {string} opts.txid - The txid of the tx to be notified of.
   */
  txConfirmationSubscribe(opts, cb) {
    if (!checkRequired(opts, ['txid'], cb)) return;

    const sub = TxConfirmationSub.create({
      copayerId: this.copayerId,
      walletId: this.walletId,
      txid: opts.txid,
      amount: opts.amount,
      isCreator: true
    });

    this.storage.storeTxConfirmationSub(sub, cb);
  }

  /**
   * Unsubscribe this copayer to the Push Notifications service using the specified token.
   * @param {Object} opts
   * @param {string} opts.txid - The txid of the tx to be notified of.
   */
  txConfirmationUnsubscribe(opts, cb) {
    if (!checkRequired(opts, ['txid'], cb)) return;

    this.storage.removeTxConfirmationSub(this.copayerId, opts.txid, cb);
  }

  getServicesData(cb) {
    const data = config.services ?? {};
    return cb(null, data);
  }

  simplexGetKeys(req) {
    if (!config.simplex) throw new Error('Simplex missing credentials');

    let env = 'sandbox';
    if (req.body.env && req.body.env == 'production') {
      env = 'production';
    }
    delete req.body.env;

    const keys = {
      API: config.simplex[env].api,
      API_KEY: config.simplex[env].apiKey,
      APP_PROVIDER_ID: config.simplex[env].appProviderId
    };

    return keys;
  }

  simplexGetQuote(req): Promise<any> {
    return new Promise((resolve, reject) => {
      const keys = this.simplexGetKeys(req);

      const API = keys.API;
      const API_KEY = keys.API_KEY;
      const ip = Utils.getIpFromReq(req);

      req.body.client_ip = ip;
      req.body.wallet_id = keys.APP_PROVIDER_ID;

      const headers = {
        'Content-Type': 'application/json',
        Authorization: 'ApiKey ' + API_KEY
      };

      this.request.post(
        API + '/wallet/merchant/v2/quote',
        {
          headers,
          body: req.body,
          json: true
        },
        (err, data) => {
          if (err) {
            return reject(err.body ? err.body : err);
          } else {
            return resolve(data.body ? data.body : null);
          }
        }
      );
    });
  }

  simplexPaymentRequest(req): Promise<any> {
    return new Promise((resolve, reject) => {
      const keys = this.simplexGetKeys(req);

      const API = keys.API;
      const API_KEY = keys.API_KEY;
      const appProviderId = keys.APP_PROVIDER_ID;
      const paymentId = Uuid.v4();
      const orderId = Uuid.v4();
      const apiHost = keys.API;
      const ip = Utils.getIpFromReq(req);

      if (
        !checkRequired(req.body, ['account_details', 'transaction_details']) &&
        !checkRequired(req.body.transaction_details, ['payment_details'])
      ) {
        return reject(new ClientError("Simplex's request missing arguments"));
      }

      req.body.account_details.app_provider_id = appProviderId;
      req.body.account_details.signup_login = {
        ip,
        location: '',
        uaid: '',
        accept_language: 'de,en-US;q=0.7,en;q=0.3',
        http_accept_language: 'de,en-US;q=0.7,en;q=0.3',
        user_agent: req.body.account_details.signup_login ? req.body.account_details.signup_login.user_agent : '', // Format: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0'
        cookie_session_id: '',
        timestamp: req.body.account_details.signup_login ? req.body.account_details.signup_login.timestamp : ''
      };

      req.body.transaction_details.payment_details.payment_id = paymentId;
      req.body.transaction_details.payment_details.order_id = orderId;

      const headers = {
        'Content-Type': 'application/json',
        Authorization: 'ApiKey ' + API_KEY
      };

      this.request.post(
        API + '/wallet/merchant/v2/payments/partner/data',
        {
          headers,
          body: req.body,
          json: true
        },
        (err, data) => {
          if (err) {
            return reject(err.body ? err.body : err);
          } else {
            data.body.payment_id = paymentId;
            data.body.order_id = orderId;
            data.body.app_provider_id = appProviderId;
            data.body.api_host = apiHost;
            return resolve(data.body);
          }
        }
      );
    });
  }

  simplexGetEvents(req): Promise<any> {
    return new Promise((resolve, reject) => {
      if (!config.simplex) return reject(new Error('Simplex missing credentials'));
      if (!req.env || (req.env != 'sandbox' && req.env != 'production'))
        return reject(new Error("Simplex's request wrong environment"));

      const API = config.simplex[req.env].api;
      const API_KEY = config.simplex[req.env].apiKey;
      const headers = {
        'Content-Type': 'application/json',
        Authorization: 'ApiKey ' + API_KEY
      };

      this.request.get(
        API + '/wallet/merchant/v2/events',
        {
          headers,
          json: true
        },
        (err, data) => {
          if (err) {
            return reject(err.body ? err.body : null);
          } else {
            return resolve(data.body ? data.body : null);
          }
        }
      );
    });
  }

  wyreGetKeys(req) {
    if (!config.wyre) throw new Error('Wyre missing credentials');

    let env = 'sandbox';
    if (req.body.env && req.body.env == 'production') {
      env = 'production';
    }
    delete req.body.env;

    const keys = {
      API: config.wyre[env].api,
      API_KEY: config.wyre[env].apiKey,
      SECRET_API_KEY: config.wyre[env].secretApiKey,
      ACCOUNT_ID: config.wyre[env].appProviderAccountId
    };

    return keys;
  }

  wyreWalletOrderQuotation(req): Promise<any> {
    return new Promise((resolve, reject) => {
      const keys = this.wyreGetKeys(req);
      req.body.accountId = keys.ACCOUNT_ID;

      if (req.body.amountIncludeFees) {
        if (
          !checkRequired(req.body, ['sourceAmount', 'sourceCurrency', 'destCurrency', 'dest', 'country', 'walletType'])
        ) {
          return reject(new ClientError("Wyre's request missing arguments"));
        }
      } else {
        if (!checkRequired(req.body, ['amount', 'sourceCurrency', 'destCurrency', 'dest', 'country'])) {
          return reject(new ClientError("Wyre's request missing arguments"));
        }
      }

      const URL: string = `${keys.API}/v3/orders/quote/partner?timestamp=${Date.now().toString()}`;
      const XApiSignature: string = URL + JSON.stringify(req.body);
      const XApiSignatureHash: string = Bitcore.crypto.Hash.sha256hmac(
        Buffer.from(XApiSignature),
        Buffer.from(keys.SECRET_API_KEY)
      ).toString('hex');

      const headers = {
        'Content-Type': 'application/json',
        'X-Api-Key': keys.API_KEY,
        'X-Api-Signature': XApiSignatureHash
      };

      this.request.post(
        URL,
        {
          headers,
          body: req.body,
          json: true
        },
        (err, data) => {
          if (err) {
            return reject(err.body ? err.body : err);
          } else {
            return resolve(data.body);
          }
        }
      );
    });
  }

  wyreWalletOrderReservation(req): Promise<any> {
    return new Promise((resolve, reject) => {
      const keys = this.wyreGetKeys(req);
      req.body.referrerAccountId = keys.ACCOUNT_ID;

      if (req.body.amountIncludeFees) {
        if (
          !checkRequired(req.body, [
            'sourceAmount',
            'sourceCurrency',
            'destCurrency',
            'dest',
            'country',
            'paymentMethod'
          ])
        ) {
          return reject(new ClientError("Wyre's request missing arguments"));
        }
      } else {
        if (!checkRequired(req.body, ['amount', 'sourceCurrency', 'destCurrency', 'dest', 'paymentMethod'])) {
          return reject(new ClientError("Wyre's request missing arguments"));
        }
      }

      const URL: string = `${keys.API}/v3/orders/reserve?timestamp=${Date.now().toString()}`;
      const XApiSignature: string = URL + JSON.stringify(req.body);
      const XApiSignatureHash: string = Bitcore.crypto.Hash.sha256hmac(
        Buffer.from(XApiSignature),
        Buffer.from(keys.SECRET_API_KEY)
      ).toString('hex');

      const headers = {
        'Content-Type': 'application/json',
        'X-Api-Key': keys.API_KEY,
        'X-Api-Signature': XApiSignatureHash
      };

      this.request.post(
        URL,
        {
          headers,
          body: req.body,
          json: true
        },
        (err, data) => {
          if (err) {
            return reject(err.body ? err.body : err);
          } else {
            return resolve(data.body);
          }
        }
      );
    });
  }

  changellyGetKeys(req) {
    if (!config.changelly) {
      logger.warn('Changelly missing credentials');
      throw new Error('ClientError: Service not configured.');
    }

    const keys = {
      API: config.changelly.api,
      API_KEY: config.changelly.apiKey,
      SECRET: config.changelly.secret
    };

    return keys;
  }

  changellySignRequests(message, secret: string) {
    if (!message || !secret) throw new Error('Missing parameters to sign Changelly request');

    const sign: string = Bitcore.crypto.Hash.sha512hmac(
      Buffer.from(JSON.stringify(message)),
      Buffer.from(secret)
    ).toString('hex');

    return sign;
  }

  changellyGetCurrencies(req): Promise<any> {
    return new Promise((resolve, reject) => {
      const keys = this.changellyGetKeys(req);

      if (!checkRequired(req.body, ['id'])) {
        return reject(new ClientError('changellyGetCurrencies request missing arguments'));
      }

      const message = {
        jsonrpc: '2.0',
        id: req.body.id,
        method: req.body.full ? 'getCurrenciesFull' : 'getCurrencies',
        params: {}
      };

      const URL: string = keys.API;
      const sign: string = this.changellySignRequests(message, keys.SECRET);

      const headers = {
        'Content-Type': 'application/json',
        sign,
        'api-key': keys.API_KEY
      };

      this.request.post(
        URL,
        {
          headers,
          body: message,
          json: true
        },
        (err, data) => {
          if (err) {
            return reject(err.body ?? err);
          } else {
            return resolve(data.body);
          }
        }
      );
    });
  }

  changellyGetPairsParams(req): Promise<any> {
    return new Promise((resolve, reject) => {
      const keys = this.changellyGetKeys(req);

      if (!checkRequired(req.body, ['id', 'coinFrom', 'coinTo'])) {
        return reject(new ClientError('changellyGetPairsParams request missing arguments'));
      }

      const message = {
        id: req.body.id,
        jsonrpc: '2.0',
        method: 'getPairsParams',
        params: [
          {
            from: req.body.coinFrom,
            to: req.body.coinTo
          }
        ]
      };

      const URL: string = keys.API;
      const sign: string = this.changellySignRequests(message, keys.SECRET);

      const headers = {
        'Content-Type': 'application/json',
        sign,
        'api-key': keys.API_KEY
      };

      this.request.post(
        URL,
        {
          headers,
          body: message,
          json: true
        },
        (err, data) => {
          if (err) {
            return reject(err.body ?? err);
          } else {
            return resolve(data.body);
          }
        }
      );
    });
  }

  changellyGetFixRateForAmount(req): Promise<any> {
    return new Promise((resolve, reject) => {
      const keys = this.changellyGetKeys(req);

      if (!checkRequired(req.body, ['id', 'coinFrom', 'coinTo', 'amountFrom'])) {
        return reject(new ClientError('changellyGetFixRateForAmount request missing arguments'));
      }

      const message = {
        id: req.body.id,
        jsonrpc: '2.0',
        method: 'getFixRateForAmount',
        params: [
          {
            from: req.body.coinFrom,
            to: req.body.coinTo,
            amountFrom: req.body.amountFrom
          }
        ]
      };

      const URL: string = keys.API;
      const sign: string = this.changellySignRequests(message, keys.SECRET);

      const headers = {
        'Content-Type': 'application/json',
        sign,
        'api-key': keys.API_KEY
      };

      this.request.post(
        URL,
        {
          headers,
          body: message,
          json: true
        },
        (err, data) => {
          if (err) {
            return reject(err.body ?? err);
          } else {
            return resolve(data.body);
          }
        }
      );
    });
  }

  changellyCreateFixTransaction(req): Promise<any> {
    return new Promise((resolve, reject) => {
      const keys = this.changellyGetKeys(req);

      if (
        !checkRequired(req.body, [
          'id',
          'coinFrom',
          'coinTo',
          'amountFrom',
          'addressTo',
          'fixedRateId',
          'refundAddress'
        ])
      ) {
        return reject(new ClientError('changellyCreateFixTransaction request missing arguments'));
      }

      const message = {
        id: req.body.id,
        jsonrpc: '2.0',
        method: 'createFixTransaction',
        params: {
          from: req.body.coinFrom,
          to: req.body.coinTo,
          address: req.body.addressTo,
          amountFrom: req.body.amountFrom,
          rateId: req.body.fixedRateId,
          refundAddress: req.body.refundAddress
        }
      };

      const URL: string = keys.API;
      const sign: string = this.changellySignRequests(message, keys.SECRET);

      const headers = {
        'Content-Type': 'application/json',
        sign,
        'api-key': keys.API_KEY
      };

      this.request.post(
        URL,
        {
          headers,
          body: message,
          json: true
        },
        (err, data) => {
          if (err) {
            return reject(err.body ?? err);
          } else {
            return resolve(data.body);
          }
        }
      );
    });
  }

  changellyGetStatus(req): Promise<any> {
    return new Promise((resolve, reject) => {
      const keys = this.changellyGetKeys(req);

      if (!checkRequired(req.body, ['id', 'exchangeTxId'])) {
        return reject(new ClientError('changellyGetStatus request missing arguments'));
      }

      const message = {
        jsonrpc: '2.0',
        id: req.body.id,
        method: 'getStatus',
        params: {
          id: req.body.exchangeTxId
        }
      };

      const URL: string = keys.API;
      const sign: string = this.changellySignRequests(message, keys.SECRET);

      const headers = {
        'Content-Type': 'application/json',
        sign,
        'api-key': keys.API_KEY
      };

      this.request.post(
        URL,
        {
          headers,
          body: message,
          json: true
        },
        (err, data) => {
          if (err) {
            return reject(err.body ?? err);
          } else {
            return resolve(data.body);
          }
        }
      );
    });
  }

  oneInchGetCredentials() {
    if (!config.oneInch) throw new Error('1Inch missing credentials');

    const credentials = {
      API: config.oneInch.api,
      referrerAddress: config.oneInch.referrerAddress,
      referrerFee: config.oneInch.referrerFee
    };

    return credentials;
  }

  oneInchGetReferrerFee(req): Promise<any> {
    return new Promise((resolve, reject) => {
      const credentials = this.oneInchGetCredentials();

      const referrerFee: number = credentials.referrerFee;

      resolve({ referrerFee });
    });
  }

  oneInchGetSwap(req): Promise<any> {
    return new Promise((resolve, reject) => {
      const credentials = this.oneInchGetCredentials();

      if (
        !checkRequired(req.body, [
          'fromTokenAddress',
          'toTokenAddress',
          'amount',
          'fromAddress',
          'slippage',
          'destReceiver'
        ])
      ) {
        return reject(new ClientError('oneInchGetSwap request missing arguments'));
      }

      const headers = {
        'Content-Type': 'application/json'
      };

      let qs = [];
      qs.push('fromTokenAddress=' + req.body.fromTokenAddress);
      qs.push('toTokenAddress=' + req.body.toTokenAddress);
      qs.push('amount=' + req.body.amount);
      qs.push('fromAddress=' + req.body.fromAddress);
      qs.push('slippage=' + req.body.slippage);
      qs.push('destReceiver=' + req.body.destReceiver);

      if (credentials.referrerFee) qs.push('fee=' + credentials.referrerFee);
      if (credentials.referrerAddress) qs.push('referrerAddress=' + credentials.referrerAddress);

      const URL: string = credentials.API + '/v3.0/1/swap/?' + qs.join('&');

      this.request.get(
        URL,
        {
          headers,
          json: true
        },
        (err, data) => {
          if (err) {
            return reject(err.body ?? err);
          } else {
            return resolve(data.body);
          }
        }
      );
    });
  }

  oneInchGetTokens(req): Promise<any> {
    return new Promise((resolve, reject) => {
      const credentials = this.oneInchGetCredentials();

      const headers = {
        'Content-Type': 'application/json'
      };

      const URL: string = credentials.API + '/v3.0/1/tokens';

      this.request.get(
        URL,
        {
          headers,
          json: true
        },
        (err, data) => {
          if (err) {
            return reject(err.body ?? err);
          } else {
            return resolve(data.body.tokens);
          }
        }
      );
    });
  }

  checkServiceAvailability(req): boolean {
    if (!checkRequired(req.body, ['service', 'opts'])) {
      throw new ClientError('checkServiceAvailability request missing arguments');
    }

    let serviceEnabled: boolean;

    switch (req.body.service) {
      case '1inch':
        if (req.body.opts?.country?.toUpperCase() === 'US') {
          serviceEnabled = false;
        } else {
          serviceEnabled = true;
        }
        break;

      default:
        serviceEnabled = true;
        break;
    }

    return serviceEnabled;
  }

  getSpenderApprovalWhitelist(cb) {
    if (Services.ERC20_SPENDER_APPROVAL_WHITELIST) {
      return cb(null, Services.ERC20_SPENDER_APPROVAL_WHITELIST);
    } else {
      return cb(new Error('Could not get ERC20 spender approval whitelist'));
    }
  }

  getPayId(url: string): Promise<any> {
    return new Promise((resolve, reject) => {
      const headers = {
        'PayID-Version': '1.0',
        Accept: 'application/payid+json'
      };
      this.request.get(
        url,
        {
          headers,
          json: true
        },
        (err, data) => {
          if (err) {
            return reject(err.body ? err.body : err);
          } else {
            return resolve(data.body ? data.body : data);
          }
        }
      );
    });
  }

  discoverPayId(req): Promise<any> {
    return new Promise((resolve, reject) => {
      const URL: string = `https://${req.domain}/.well-known/webfinger?resource=payid%3A${req.handle}%24${req.domain}`;
      const headers = {
        'PayID-Version': '1.0',
        Accept: 'application/payid+json'
      };
      this.request.get(
        URL,
        {
          headers,
          json: true
        },
        (err, data) => {
          if (err) {
            return reject(err.body ? err.body : err);
          } else {
            let url;
            if (data.body && data.body.links && data.body.links[0].template) {
              const template: string = data.body.links[0].template;
              url = template.replace('{acctpart}', req.handle);
            } else {
              url = `https://${req.domain}/${req.handle}`;
            }
            this.getPayId(url)
              .then(data => {
                return resolve(data);
              })
              .catch(err => {
                return reject(err);
              });
          }
        }
      );
    });
  }

  clearWalletCache(): Promise<boolean> {
    return new Promise(resolve => {
      this.storage.clearWalletCache(this.walletId, () => {
        resolve(true);
      });
    });
  }

  // john
  getMasternodeCollateral(opts, cb) {
    opts = opts || {};

    if (opts.coin) {
      return cb(new ClientError('coin is not longer supported in getMasternodeCollateral'));
    }

    this.getWallet({}, (err, wallet) => {
      if (err) return cb(err);

      if (!wallet.isComplete()) return cb(Errors.WALLET_NOT_COMPLETE);
      if (wallet.scanStatus == 'error') return cb(Errors.WALLET_NEED_SCAN);
      if (wallet.n != 1 && wallet.m != 1) return cb(Errors.WALLET_NOT_SUPPORT);
      // john 20220219
      if (wallet.addressType != Constants.SCRIPT_TYPES.P2PKH && wallet.addressType != Constants.SCRIPT_TYPES.P2WPKH)
        return cb(Errors.WALLET_NOT_SUPPORT);

      this.getUtxosForCurrentWallet(
        {
          coin: opts.coin
        },
        (err, utxos) => {
          if (err) return cb(err);

          let ret = new Array();
          _.each(utxos, utxo => {
            if (utxo.satoshis == Constants.COLLATERAL_COIN) {
              ret.push(utxo);
            }
          });

          return cb(null, ret);
        }
      );
    });
  }

  removeMasternodes(opts, cb) {
    opts = opts || {};

    opts.coin = opts.coin || Defaults.COIN;
    if (!Utils.checkValueInCollection(opts.coin, Constants.COINS)) {
      return cb(new ClientError('Invalid coin'));
    }

    if (opts.coin != 'vcl') {
      return cb(new ClientError('coin is not longer supported in removeMasternode'));
    }

    opts.network = opts.network || 'livenet';
    if (!Utils.checkValueInCollection(opts.network, Constants.NETWORKS)) {
      return cb(new ClientError('Invalid network'));
    }

    this.getWallet({}, (err, wallet) => {
      if (err) return cb(err);
      if (!wallet.isComplete()) return cb(Errors.WALLET_NOT_COMPLETE);

      if (wallet.scanStatus == 'error') return cb(Errors.WALLET_NEED_SCAN);

      this.storage.removeMasternodes(wallet.id, opts.txid, cb);
    });
  }

  getMasternodes(opts, cb) {
    opts = opts || {};

    opts.coin = opts.coin || Defaults.COIN;
    if (!Utils.checkValueInCollection(opts.coin, Constants.COINS)) {
      return cb(new ClientError('Invalid coin'));
    }

    if (opts.coin != 'vcl') {
      return cb(new ClientError('coin is not longer supported in masternodes'));
    }

    opts.network = opts.network || 'livenet';
    if (!Utils.checkValueInCollection(opts.network, Constants.NETWORKS)) {
      return cb(new ClientError('Invalid network'));
    }

    this.getWallet({}, (err, wallet) => {
      if (err) return cb(err);
      if (!wallet.isComplete()) return cb(Errors.WALLET_NOT_COMPLETE);

      if (wallet.scanStatus == 'error') return cb(Errors.WALLET_NEED_SCAN);

      this.storage.fetchMasternodes(wallet.id, opts.txid, opts.proTxHash, cb);
    });
  }

  getMasternodeStatus(opts, cb) {
    opts = opts || {};

    opts.coin = opts.coin || Defaults.COIN;
    if (!Utils.checkValueInCollection(opts.coin, Constants.COINS)) {
      return cb(new ClientError('Invalid coin'));
    }

    if (opts.coin != 'vcl') {
      return cb(new ClientError('coin is not longer supported in MasternodeStatus'));
    }

    opts.network = opts.network || 'livenet';
    if (!Utils.checkValueInCollection(opts.network, Constants.NETWORKS)) {
      return cb(new ClientError('Invalid network'));
    }

    const bc = this._getBlockchainExplorer(opts.coin, opts.network);
    if (!bc) return cb(new Error('Could not get blockchain explorer instance'));
    bc.getMasternodeStatus(opts, (err, ret) => {
      if (err) return cb(err);
      return cb(null, ret);
    });
  }

  broadcastMasternode(opts, cb) {
    /*
    opts = opts || {};

    opts.coin = opts.coin || Defaults.COIN;
    if (!Utils.checkValueInCollection(opts.coin, Constants.COINS)) {
      return cb(new ClientError('Invalid coin'));
    }

    if (opts.coin != 'vcl') {
      return cb(new ClientError('coin is not longer supported in broadcastMasternode'));
    }

    if (!opts.masternodeKey) {
      return cb(new ClientError('Invalid masternode private key'));
    }

    opts.network = opts.network || 'livenet';
    if (!Utils.checkValueInCollection(opts.network, Constants.NETWORKS)) {
      return cb(new ClientError('Invalid network'));
    }

    this.getWallet({}, (err, wallet) => {
      if (err) return cb(err);
      if (!wallet.isComplete()) return cb(Errors.WALLET_NOT_COMPLETE);

      if (wallet.scanStatus == 'error') return cb(Errors.WALLET_NEED_SCAN);

      const bc = this._getBlockchainExplorer(opts.coin, opts.network);
      if (!bc) return cb(new Error('Could not get blockchain explorer instance'));
      bc.broadcastMasternode(opts.rawTx, (err, ret) => {
        if (err) return cb(err);
        // john

        let masternodeStatus: {
          coin?: string;
          network?: string;
          address?: string;
          txid?: string;
          masternodeKey?: string;
          status?: string;
          walletId?: string;
        } = {};
        if (!ret.errorMessage) {
          _.forEach(_.keys(ret), function(key) {
            if (ret[key].outpoint && ret[key].addr) {
              masternodeStatus.coin = wallet.coin;
              masternodeStatus.network = wallet.network;
              masternodeStatus.address = ret[key].addr;
              masternodeStatus.txid = ret[key].outpoint;
              masternodeStatus.masternodeKey = opts.masternodeKey;
              masternodeStatus.status = 'PRE_ENABLED';
              masternodeStatus.walletId = wallet.id;
              return;
            }
          });
          let masternodes = Masternodes.create(masternodeStatus);
          this.storage.storeMasternode(wallet.id, masternodes, err => {
            if (!err) {
              this._notify(
                'NewMasternode',
                {
                  coin: masternodes.coin,
                  network: masternodes.network,
                  address: masternodes.address,
                  txid: masternodes.txid,
                  masternodeKey: masternodes.masternodeKey,
                  status: masternodes.status
                },
                () => {}
              );
            }
          });
        }
        if (opts.jsonHeader) {
          return cb(null, { response: ret });
        } else {
          return cb(null, ret);
        }
      });
    });
    */
    cb(null);
  }

  getMasternodePing(opts, cb) {
    opts = opts || {};

    opts.coin = opts.coin || Defaults.COIN;
    if (!Utils.checkValueInCollection(opts.coin, Constants.COINS)) {
      return cb(new ClientError('Invalid coin'));
    }

    opts.network = opts.network || 'livenet';
    if (!Utils.checkValueInCollection(opts.network, Constants.NETWORKS)) {
      return cb(new ClientError('Invalid network'));
    }

    if (!opts.txid) {
      return cb(new ClientError('not utxo txid'));
    }

    if (!opts.vout) {
      return cb(new ClientError('not utxo vout'));
    }

    async.series(
      [
        next => {
          this.getUtxosForCurrentWallet(
            {
              coin: opts.coin
            },
            (err, utxos) => {
              if (err) return cb(err);

              let bfind = false;
              _.each(utxos, utxo => {
                if (utxo.txid == opts.txid && utxo.vout == opts.vout && utxo.satoshis == Constants.COLLATERAL_COIN) {
                  opts.address = utxo.address;
                  opts.publicKeys = utxo.publicKeys;
                  opts.path = utxo.path;
                  opts.confirmations = utxo.confirmations;
                  bfind = true;
                  return false;
                }
              });
              if (bfind) {
                if (opts.confirmations >= Constants.MASTERNODE_MIN_CONFIRMATIONS) {
                  next();
                } else {
                  return cb('Collateral payment must have at least 15 confirmations');
                }
              } else {
                return cb('Invalid utxo');
              }
            }
          );
        },
        next => {
          this._getBlockchainHeight(opts.coin, opts.network, (err, height, hash) => {
            opts.currentHeight = height;
            if (err) return cb(err);
            next();
          });
        },
        next => {
          const bc = this._getBlockchainExplorer(opts.coin, opts.network);
          if (!bc) return cb(new Error('Could not get blockchain explorer instance'));
          bc.getBlockHashInHeight(opts.currentHeight - 12, (err, height, hash) => {
            if (!err && height > 0) {
              opts.pingHeight = height;
              opts.pingHash = hash;
              return cb(null, opts);
            } else {
              return cb(err || 'wrong height');
            }
          });
        }
      ],
      err => {
        if (err) return cb(err);
      }
    );
  }

  // john 20220219
  getMasternodeBlsGenerate(opts, cb) {
    opts = opts || {};

    opts.coin = opts.coin || Defaults.COIN;
    if (!Utils.checkValueInCollection(opts.coin, Constants.COINS)) {
      return cb(new ClientError('Invalid coin'));
    }

    if (opts.coin != 'vcl') {
      return cb(new ClientError('coin is not longer supported in MasternodeStatus'));
    }

    opts.network = opts.network || 'livenet';
    if (!Utils.checkValueInCollection(opts.network, Constants.NETWORKS)) {
      return cb(new ClientError('Invalid network'));
    }

    const bc = this._getBlockchainExplorer(opts.coin, opts.network);
    if (!bc) return cb(new Error('Could not get blockchain explorer instance'));
    bc.getMasternodeBlsGenerate(opts, (err, ret) => {
      if (err) return cb(err);
      return cb(null, ret);
    });
  }

  getMasternodeBlsSign(opts, cb) {
    opts = opts || {};

    opts.coin = opts.coin || Defaults.COIN;
    if (!Utils.checkValueInCollection(opts.coin, Constants.COINS)) {
      return cb(new ClientError('Invalid coin'));
    }

    if (opts.coin != 'vcl') {
      return cb(new ClientError('coin is not longer supported in MasternodeStatus'));
    }

    opts.network = opts.network || 'livenet';
    if (!Utils.checkValueInCollection(opts.network, Constants.NETWORKS)) {
      return cb(new ClientError('Invalid network'));
    }

    if (!opts.msgHash) {
      return cb(new ClientError('Invalid msgHash'));
    }

    if (!opts.masternodePrivateKey) {
      return cb(new ClientError('Invalid masternodePrivateKey'));
    }

    const bc = this._getBlockchainExplorer(opts.coin, opts.network);
    if (!bc) return cb(new Error('Could not get blockchain explorer instance'));
    bc.getMasternodeBlsSign(opts, (err, ret) => {
      if (err) return cb(err);
      return cb(null, ret);
    });
  }

  createAsset(opts, cb) {
    this.logd('assset created');

    if (opts.coin != 'vcl') {
      return cb(new Error('coin is not supported'));
    }

    if (opts.asset.version == stxjs.utils.SYSCOIN_TX_VERSION_ALLOCATION_SEND) {
      if (!opts.asset.assetGuid) {
        return cb(new Error('assetGuid is required'));
      }
      if (!_.isArray(opts.outputs) || opts.outputs.length == 0) {
        return cb(new Error('outputs is required'));
      }

      for (var i = 0; i < opts.outputs.length; i++) {
        if (!opts.outputs[i].toAddress) return cb(new Error('toAddress is required'));
        if (!opts.outputs[i].amount) return cb(new Error('amount is required'));
      }
    } else if (opts.asset.version == 0x02) {
      if (!_.isArray(opts.outputs) || opts.outputs.length == 0) {
        return cb(new Error('outputs is required'));
      }
      for (var i = 0; i < opts.outputs.length; i++) {
        if (!opts.outputs[i].toAddress) return cb(new Error('toAddress is required'));
        if (!opts.outputs[i].amount) return cb(new Error('amount is required'));
      }
    } else if (opts.asset.version == stxjs.utils.SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_ETHEREUM) {
      if (!opts.asset.ethAddr) return cb(new Error('ethAddr is required'));
    } else if (opts.asset.version == stxjs.utils.SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_SYSCOIN) {
    } else if (opts.asset.version == stxjs.utils.SYSCOIN_TX_VERSION_ALLOCATION_MINT) {
      if (!opts.asset.ethtxid) return cb(new Error('ethtxid is required'));
    } else {
      return cb(new Error('asset version is invalid'));
    }

    const checkTxpAlreadyExists = (txProposalId, cb) => {
      if (!txProposalId) return cb();
      this.storage.fetchTx(this.walletId, txProposalId, cb);
    };

    this._runLocked(
      cb,
      cb => {
        let changeAddress, feePerKb, gasPrice, gasLimit, fee, assetChangeAddress, sysChangeAddress;
        this.getWallet({}, (err, wallet) => {
          if (err) return cb(err);
          if (!wallet.isComplete()) return cb(Errors.WALLET_NOT_COMPLETE);

          if (wallet.scanStatus == 'error') return cb(Errors.WALLET_NEED_SCAN);

          if (config.suspendedChains && config.suspendedChains.includes(wallet.coin)) {
            let Err = Errors.NETWORK_SUSPENDED;
            Err.message = Err.message.replace('$network', wallet.coin.toUpperCase());
            return cb(Err);
          }

          checkTxpAlreadyExists(opts.txProposalId, (err, txp) => {
            if (err) return cb(err);
            if (txp) return cb(null, txp);

            async.series(
              [
                next => {
                  if (ChainService.isUTXOCoin(wallet.coin)) return next();
                  this.getMainAddresses({ reverse: true, limit: 1 }, (err, mainAddr) => {
                    if (err) return next(err);
                    opts.from = mainAddr[0].address;
                    next();
                  });
                },
                next => {
                  this._canCreateTx((err, canCreate) => {
                    if (err) return next(err);
                    if (!canCreate) return next(Errors.TX_CANNOT_CREATE);
                    next();
                  });
                },
                async next => {
                  if (
                    opts.asset.version == stxjs.utils.SYSCOIN_TX_VERSION_ALLOCATION_SEND ||
                    opts.asset.version == stxjs.utils.SYSCOIN_TX_VERSION_ALLOCATION_MINT ||
                    opts.asset.version == stxjs.utils.SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_ETHEREUM ||
                    opts.asset.version == stxjs.utils.SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_SYSCOIN
                  ) {
                    try {
                      sysChangeAddress = await ChainService.getChangeAddress(this, wallet, opts);
                      assetChangeAddress = await ChainService.getChangeAddress(this, wallet, opts);
                    } catch (error) {
                      return next(error);
                    }
                    return next();
                  } else if (opts.asset.version == 0x02) {
                    try {
                      sysChangeAddress = await ChainService.getChangeAddress(this, wallet, opts);
                    } catch (error) {
                      return next(error);
                    }
                    return next();
                  } else {
                    return next(new Error('asset version is not supported'));
                  }
                },
                async next => {
                  if (_.isNumber(opts.fee) && !_.isEmpty(opts.inputs)) return next();

                  try {
                    ({ feePerKb, gasPrice, gasLimit, fee } = await ChainService.getFee(this, wallet, opts));
                  } catch (error) {
                    return next(error);
                  }
                  next();
                },
                async next => {
                  opts.signingMethod = opts.signingMethod || 'ecdsa';
                  opts.coin = opts.coin || wallet.coin;

                  if (!['ecdsa', 'schnorr'].includes(opts.signingMethod)) {
                    return next(Errors.WRONG_SIGNING_METHOD);
                  }

                  return next();
                },
                next => {
                  let txOptsFee = fee;

                  if (!txOptsFee) {
                    const useInputFee = opts.inputs && !_.isNumber(opts.feePerKb);
                    const isNotUtxoCoin = !ChainService.isUTXOCoin(wallet.coin);
                    const shouldUseOptsFee = useInputFee || isNotUtxoCoin;

                    if (shouldUseOptsFee) {
                      txOptsFee = opts.fee;
                    }
                  }

                  var txType, maxPriorityFeePerGas, maxFeePerGas;

                  const txOpts = {
                    id: opts.txProposalId,
                    walletId: this.walletId,
                    creatorId: this.copayerId,
                    coin: opts.coin,
                    chain: opts.chain ? opts.chain : ChainService.getChain(opts.coin),
                    network: wallet.network,
                    outputs: opts.outputs,
                    message: opts.message,
                    from: opts.from,
                    changeAddress,
                    feeLevel: opts.feeLevel,
                    feePerKb,
                    payProUrl: opts.payProUrl,
                    walletM: wallet.m,
                    walletN: wallet.n,
                    excludeUnconfirmedUtxos: !!opts.excludeUnconfirmedUtxos,
                    instantAcceptanceEscrow: opts.instantAcceptanceEscrow,
                    addressType: wallet.addressType,
                    customData: opts.customData,
                    inputs: opts.inputs,
                    version: opts.txpVersion,
                    fee: txOptsFee,
                    noShuffleOutputs: opts.noShuffleOutputs,
                    gasPrice,
                    nonce: opts.nonce,
                    gasLimit, // Backward compatibility for BWC < v7.1.1
                    data: opts.data, // Backward compatibility for BWC < v7.1.1
                    tokenAddress: opts.tokenAddress,
                    multisigContractAddress: opts.multisigContractAddress,
                    destinationTag: opts.destinationTag,
                    invoiceID: opts.invoiceID,
                    signingMethod: opts.signingMethod,
                    isTokenSwap: opts.isTokenSwap,
                    enableRBF: opts.enableRBF,
                    replaceTxByFee: opts.replaceTxByFee,
                    txExtends: opts.txExtends, // 20220219
                    txType,
                    maxPriorityFeePerGas,
                    maxFeePerGas,
                    accessList: opts.accessList || [],
                    tokenId: opts.tokenId, // 20220423
                    asset: opts.asset // 20220709
                  };
                  txp = TxProposal.create(txOpts);
                  next();
                },
                async next => {
                  if (
                    opts.asset.version == stxjs.utils.SYSCOIN_TX_VERSION_ALLOCATION_SEND ||
                    opts.asset.version == 0x02 ||
                    opts.asset.version == stxjs.utils.SYSCOIN_TX_VERSION_ALLOCATION_MINT ||
                    opts.asset.version == stxjs.utils.SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_ETHEREUM ||
                    opts.asset.version == stxjs.utils.SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_SYSCOIN
                  ) {
                    const zpub = this.xPubTozPub(wallet);
                    var decimals = 0;
                    if (opts.asset.version == 2) {
                      decimals = 8;
                    } else {
                      var odecimals = await sjs.utils.fetchBackendAsset(syscoinjs.blockbookURL, opts.asset.assetGuid);
                      if (!odecimals) {
                        return next(new Error('decimal is invalid'));
                      }
                      decimals = odecimals.decimals;
                    }
                    decimals = decimals - 8;

                    var outputs = [];
                    opts.outputs.forEach((o, idx) => {
                      var output = {
                        value: new sjs.utils.BN(o.amount * Math.pow(10, decimals)),
                        address: o.toAddress
                      };
                      outputs.push(output);
                    });

                    var feeRate = new sjs.utils.BN(10);
                    if (feePerKb > 0) {
                      var feePerByte = (feePerKb + 999) / 1000;
                      if (feePerByte < 10) {
                        feePerByte = 10;
                      }
                      feeRate = new sjs.utils.BN(feePerByte);
                    }

                    var psbt;
                    if (opts.asset.version == 0x02) {
                      const txOpts = { rbf: false };
                      this.logd('assset created');
                      psbt = await syscoinjs.createTransaction(
                        txOpts,
                        sysChangeAddress.address,
                        outputs,
                        feeRate,
                        zpub
                      );
                    } else if (
                      opts.asset.version == stxjs.utils.SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_ETHEREUM ||
                      opts.asset.version == stxjs.utils.SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_SYSCOIN
                    ) {
                      const txOpts = { rbf: true };
                      var assetOpts = {};
                      if (opts.asset.version == stxjs.utils.SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_ETHEREUM) {
                        assetOpts = { ethaddress: Buffer.from(opts.asset.ethAddr, 'hex') };
                      }
                      const assetMap = new Map([
                        [
                          opts.asset.assetGuid,
                          {
                            changeAddress: assetChangeAddress.address,
                            outputs: [
                              {
                                value: new sjs.utils.BN(opts.outputs[0].amount * Math.pow(10, decimals)),
                                address: sysChangeAddress.address
                              }
                            ]
                          }
                        ]
                      ]);
                      this.logd('assset burn');
                      psbt = await syscoinjs.assetAllocationBurn(
                        assetOpts,
                        txOpts,
                        assetMap,
                        sysChangeAddress.address,
                        feeRate,
                        zpub
                      );
                    } else if (opts.asset.version == stxjs.utils.SYSCOIN_TX_VERSION_ALLOCATION_MINT) {
                      const txOpts = { rbf: true };
                      const assetOpts = {
                        ethtxid: opts.asset.ethtxid,
                        web3url: config.web3Url
                      };
                      this.logd('assset mint');
                      psbt = await syscoinjs.assetAllocationMint(
                        assetOpts,
                        txOpts,
                        null,
                        sysChangeAddress.address,
                        feeRate,
                        zpub,
                        null,
                        null,
                        assetChangeAddress.address
                      );
                    } else {
                      const txOpts = { rbf: false };
                      const assetMap = new Map([
                        [opts.asset.assetGuid, { changeAddress: assetChangeAddress.address, outputs }]
                      ]);
                      this.logd('assset send');
                      psbt = await syscoinjs.assetAllocationSend(
                        txOpts,
                        assetMap,
                        sysChangeAddress.address,
                        feeRate,
                        zpub
                      );
                    }
                    if (!psbt) {
                      return next(new Error(Errors.INSUFFICIENT_FUNDS));
                    }

                    var myTx = psbt.psbt.extractTransaction1(true);
                    txp.outputs = [];
                    txp.outputOrder = [];
                    var totalInputs = 0;
                    var totalOutputs = 0;
                    myTx.outs.forEach((o, idx) => {
                      $.checkState(o.script, 'Output should have either script specified');
                      var output = {
                        script: o.script.toString('hex'),
                        amount: o.value
                      };
                      txp.outputs.push(output);
                      totalOutputs = totalOutputs + o.value;
                      txp.outputOrder.push(idx);
                    });

                    var rootPath = Deriver.pathFor(opts.coin, opts.network);
                    var xinputs = [];
                    myTx.ins.forEach((input, idx) => {
                      var xinput = {
                        address: input.address,
                        satoshis: input.satoshis,
                        txid: input.hash.reverse().toString('hex'),
                        vout: input.index,
                        script: input.script.toString('hex'),
                        path: '',
                        sequenceNumber: 0
                      };
                      var pos = input.path.indexOf(rootPath);
                      xinput.path = 'm' + input.path.substr(pos + rootPath.length, input.path.length);
                      xinput.sequenceNumber = input.sequence;
                      xinputs.push(xinput);
                      totalInputs = totalInputs + input.satoshis;
                    });
                    txp.setInputs(xinputs);

                    if (txp.asset.version == 2) {
                      txp.amount = 0;
                    }
                    txp.asset.version = myTx.version;
                    txp.fee = totalInputs - totalOutputs;

                    next();
                  } else {
                    return next(new Error('asset version is not supported'));
                  }
                },
                next => {
                  if (opts.dryRun) return next();

                  this.storage.storeTx(wallet.id, txp, next);
                }
              ],
              err => {
                if (err) return cb(err);
                return cb(null, txp);
              }
            );
          });
        });
      },
      10 * 1000
    );
  }

  xPubTozPub(wallet) {
    const copayer = wallet.getCopayer(this.copayerId);
    var data = new Bitcore.encoding.Base58Check.decode(copayer.xPubKey);
    data[0] = 0x04;
    data[1] = 0xb2;
    data[2] = 0x47;
    data[3] = 0x46;
    return Bitcore.encoding.Base58Check.encode(data);
  }

  createRelay(opts, cb) {
    if (opts.coin != 'eth') {
      return cb(new Error('coin is not supported'));
    }

    if (opts.relay.cmd == 1) {
      if (!_.isArray(opts.outputs) || opts.outputs.length == 0) {
        return cb(new Error('outputs is required'));
      }
      if (opts.outputs.length != 1) {
        return cb(new Error('outputs length must be 1'));
      }
      if (!opts.outputs[0].amount) return cb(new Error('amount is required'));
      if (!opts.relay.assetGuid) return cb(new Error('assetGuid is required'));
    } else if (opts.relay.cmd == 0x02) {
      if (!_.isArray(opts.outputs) || opts.outputs.length == 0) {
        return cb(new Error('outputs is required'));
      }
      if (opts.outputs.length != 1) {
        return cb(new Error('outputs length must be 1'));
      }
      if (!opts.outputs[0].amount) return cb(new Error('amount is required'));
      if (!opts.relay.assetGuid) return cb(new Error('assetGuid is required'));
      if (!opts.relay.sysAddr) return cb(new Error('sysAddr is required'));
    } else if (opts.relay.cmd == 0x03 || opts.relay.cmd == 0x04) {
      if (!opts.relay.txid) return cb(new Error('txid is required'));
    } else {
      return cb(new Error('relay cmd is invalid'));
    }

    const checkTxpAlreadyExists = (txProposalId, cb) => {
      if (!txProposalId) return cb();
      this.storage.fetchTx(this.walletId, txProposalId, cb);
    };

    this._runLocked(
      cb,
      cb => {
        let changeAddress, feePerKb, gasPrice, gasLimit, fee;
        this.getWallet({}, (err, wallet) => {
          if (err) return cb(err);
          if (!wallet.isComplete()) return cb(Errors.WALLET_NOT_COMPLETE);

          if (wallet.scanStatus == 'error') return cb(Errors.WALLET_NEED_SCAN);

          if (config.suspendedChains && config.suspendedChains.includes(wallet.coin)) {
            let Err = Errors.NETWORK_SUSPENDED;
            Err.message = Err.message.replace('$network', wallet.coin.toUpperCase());
            return cb(Err);
          }

          checkTxpAlreadyExists(opts.txProposalId, (err, txp) => {
            if (err) return cb(err);
            if (txp) return cb(null, txp);

            async.series(
              [
                next => {
                  if (ChainService.isUTXOCoin(wallet.coin)) return next();
                  this.getMainAddresses({ reverse: true, limit: 1 }, (err, mainAddr) => {
                    if (err) return next(err);
                    opts.from = mainAddr[0].address;
                    next();
                  });
                },
                next => {
                  this._canCreateTx((err, canCreate) => {
                    if (err) return next(err);
                    if (!canCreate) return next(Errors.TX_CANNOT_CREATE);
                    next();
                  });
                },
                next => {
                  if (opts.relay.cmd != 3 && opts.relay.cmd != 4) return next();
                  this.getSPVProof({ txid: opts.relay.txid }, function(err, result) {
                    if (err) return next(err);
                    opts.relay.nevmBlockNumber = result.nevmBlockNumber;
                    opts.relay.txBytes = result.txBytes;
                    opts.relay.txIndex = result.txIndex;
                    opts.relay.txSibling = result.txSibling;
                    opts.relay.syscoinBlockHeader = result.syscoinBlockHeader;
                    return next();
                  });
                },
                async next => {
                  if (opts.sendMax) return next();
                  try {
                    changeAddress = await ChainService.getChangeAddress(this, wallet, opts);
                  } catch (error) {
                    return next(error);
                  }
                  return next();
                },
                async next => {
                  if (_.isNumber(opts.fee) && !_.isEmpty(opts.inputs)) return next();

                  try {
                    ({ feePerKb, gasPrice, gasLimit, fee } = await ChainService.getFee(this, wallet, opts));
                  } catch (error) {
                    return next(error);
                  }
                  next();
                },
                async next => {
                  if (!opts.nonce) {
                    try {
                      opts.nonce = await ChainService.getTransactionCount(this, wallet, opts.from);
                    } catch (error) {
                      return next(error);
                    }
                  }
                  return next();
                },
                async next => {
                  opts.signingMethod = opts.signingMethod || 'ecdsa';
                  opts.coin = opts.coin || wallet.coin;

                  if (!['ecdsa', 'schnorr'].includes(opts.signingMethod)) {
                    return next(Errors.WRONG_SIGNING_METHOD);
                  }

                  //  schnorr only on BCH
                  if (opts.coin != 'bch' && opts.signingMethod == 'schnorr') return next(Errors.WRONG_SIGNING_METHOD);

                  return next();
                },
                next => {
                  let txOptsFee = fee;

                  if (!txOptsFee) {
                    const useInputFee = opts.inputs && !_.isNumber(opts.feePerKb);
                    const isNotUtxoCoin = !ChainService.isUTXOCoin(wallet.coin);
                    const shouldUseOptsFee = useInputFee || isNotUtxoCoin;

                    if (shouldUseOptsFee) {
                      txOptsFee = opts.fee;
                    }
                  }
                  // john 20220219
                  var txType;
                  var maxPriorityFeePerGas;
                  var maxFeePerGas;
                  if (opts.coin === 'eth') {
                    txType = opts.txType || 2;
                    maxPriorityFeePerGas = opts.maxPriorityFeePerGas || 1000000007;
                    maxFeePerGas = opts.maxFeePerGas || 1000000007;
                  }

                  const txOpts = {
                    id: opts.txProposalId,
                    walletId: this.walletId,
                    creatorId: this.copayerId,
                    coin: opts.coin,
                    chain: opts.chain ? opts.chain : ChainService.getChain(opts.coin),
                    network: wallet.network,
                    outputs: opts.outputs,
                    message: opts.message,
                    from: opts.from,
                    changeAddress,
                    feeLevel: opts.feeLevel,
                    feePerKb,
                    payProUrl: opts.payProUrl,
                    walletM: wallet.m,
                    walletN: wallet.n,
                    excludeUnconfirmedUtxos: !!opts.excludeUnconfirmedUtxos,
                    instantAcceptanceEscrow: opts.instantAcceptanceEscrow,
                    addressType: wallet.addressType,
                    customData: opts.customData,
                    inputs: opts.inputs,
                    version: opts.txpVersion,
                    fee: txOptsFee,
                    noShuffleOutputs: opts.noShuffleOutputs,
                    gasPrice,
                    nonce: opts.nonce,
                    gasLimit, // Backward compatibility for BWC < v7.1.1
                    data: opts.data, // Backward compatibility for BWC < v7.1.1
                    tokenAddress: opts.tokenAddress,
                    multisigContractAddress: opts.multisigContractAddress,
                    destinationTag: opts.destinationTag,
                    invoiceID: opts.invoiceID,
                    signingMethod: opts.signingMethod,
                    isTokenSwap: opts.isTokenSwap,
                    enableRBF: opts.enableRBF,
                    replaceTxByFee: opts.replaceTxByFee,
                    txExtends: opts.txExtends, // 20220219
                    txType,
                    maxPriorityFeePerGas,
                    maxFeePerGas,
                    accessList: opts.accessList || [],
                    tokenId: opts.tokenId, // 20220423
                    relay: opts.relay // 20220709
                  };
                  txp = TxProposal.create(txOpts);
                  next();
                },
                next => {
                  if (opts.relay.cmd != 1) return next();
                  this.getTokenAddressFromAssetGuid(txp, { web3Url: config.web3Url }, function(err, tokenAddress) {
                    if (err) return next(err);
                    txp.tokenAddress = tokenAddress;
                    return next();
                  });
                },
                next => {
                  return ChainService.selectTxInputs(this, txp, wallet, opts, next);
                },
                async next => {
                  if (!wallet.isZceCompatible(feePerKb) || !opts.instantAcceptanceEscrow) return next();
                  try {
                    opts.inputs = txp.inputs;
                    const escrowAddress = await ChainService.getChangeAddress(this, wallet, opts);
                    txp.escrowAddress = escrowAddress;
                  } catch (error) {
                    return next(error);
                  }
                  if (opts.dryRun) return next();
                  this._store(wallet, txp.escrowAddress, next, true);
                },
                next => {
                  if (!changeAddress || wallet.singleAddress || opts.dryRun || opts.changeAddress) return next();

                  this._store(wallet, txp.changeAddress, next, true);
                },
                next => {
                  if (opts.dryRun) return next();

                  if (txp.coin == 'bch' && txp.changeAddress) {
                    const format = opts.noCashAddr ? 'copay' : 'cashaddr';
                    txp.changeAddress.address = BCHAddressTranslator.translate(txp.changeAddress.address, format);
                  }

                  this.storage.storeTx(wallet.id, txp, next);
                }
              ],
              err => {
                if (err) return cb(err);

                if (txp.coin == 'bch') {
                  if (opts.returnOrigAddrOutputs) {
                    logger.info('Returning Orig BCH address outputs for compat');
                    txp.outputs = opts.origAddrOutputs;
                  }
                }
                return cb(null, txp);
              }
            );
          });
        });
      },
      10 * 1000
    );
  }

  getSPVProof(opts, cb) {
    this.logd('get spvproof');
    if (!opts.txid) {
      return cb(new Error('txid is required'));
    }
    if (opts.coin && opts.coin != 'eth') {
      return cb(new Error('coin is not supported'));
    }

    sjs.utils
      .fetchBackendSPVProof(syscoinjs.blockbookURL, opts.txid)
      .then(results => {
        if (results && results.result.length === 0) {
          return cb(new Error('Failed to retrieve SPV Proof'));
        } else {
          try {
            var result = JSON.parse(results.result);
            if (!result.transaction) {
              return cb(new Error('Failed to retrieve SPV Proof'));
            } else {
              if (!result.siblings) {
                return cb(new Error('no txsiblings'));
              }
              let merkleProof = bitcoinProof.getProof(result.siblings, result.index);
              for (let i = 0; i < merkleProof.sibling.length; i++) {
                merkleProof.sibling[i] = '0x' + merkleProof.sibling[i];
              }

              web3.eth
                .getBlock('0x' + result.nevm_blockhash)
                .then(nevmBlock => {
                  return cb(null, {
                    nevmBlockNumber: nevmBlock.number,
                    txBytes: '0x' + result.transaction,
                    txIndex: result.index,
                    txSibling: merkleProof.sibling,
                    syscoinBlockHeader: '0x' + result.header
                  });
                })
                .catch(e => {
                  return cb(new Error(e.message));
                });
            }
          } catch (e) {
            return cb(new Error(e.message));
          }
        }
      })
      .catch(e => {
        return cb(new Error(e.message));
      });
  }

  getTokenAddressFromAssetGuid(txp, opts, cb) {
    this.logd('get tokenAddress');
    if (!txp.relay.assetGuid) {
      return cb(new Error('assetGuid is required'));
    }
    if (!opts.web3Url) {
      return cb(new Error('web3Url is required'));
    }

    var erc20ManagerContract = txp.getERC20ManagerContract(opts);
    if (!erc20ManagerContract) {
      return cb(new Error('ERC20Manager Contract is not found'));
    }

    erc20ManagerContract.methods
      .assetRegistry(txp.relay.assetGuid)
      .call()
      .then(assetRegistry => {
        if (assetRegistry === '' || !assetRegistry) {
          return cb(new Error('assetGuid is unregistered'));
        }
        return cb(null, assetRegistry.erc20ContractAddress);
      })
      .catch(e => {
        return cb(new Error('assetGuid is unregistered'));
      });
  }

  getAsset(opts, cb) {
    this.logd('get asset');
    if (!opts.assetGuid) {
      return cb(new Error('assetGuid is required'));
    }
    if (opts.coin && opts.coin != 'vcl') {
      return cb(new Error('coin is not supported'));
    }

    sjs.utils
      .fetchBackendAsset(syscoinjs.blockbookURL, opts.assetGuid)
      .then(result => {
        if (result.assetGuid == null) {
          return cb(new Error('not found'));
        }
        try {
          if (result.symbol) {
            result.symbol = new Buffer(result.symbol, 'base64').toString();
          }
          if (result.pubData && result.pubData.desc) {
            result.pubData.desc = new Buffer(result.pubData.desc, 'base64').toString();
          }
          if (result.notaryKeyID) {
            result.notaryKeyID = new Bitcore_[opts.coin].Address(
              new Buffer(result.notaryKeyID, 'base64'),
              'livenet',
              'witnesspubkeyhash'
            ).toString();
          }
          if (result.notaryDetails && result.notaryDetails.endPoint) {
            result.notaryDetails.endPoint = new Buffer(result.notaryDetails.endPoint, 'base64').toString();
          }
          return cb(null, result);
        } catch (e) {
          return cb(null, result);
        }
      })
      .catch(e => {
        return cb(new Error(e.message));
      });
  }

  getTxType(tx) {
    if (tx.tokenType === 'SPTAssetActivate') {
      return 'SPT creation';
    }

    if (tx.tokenType === 'SPTAssetSend') {
      return 'SPT mint';
    }

    if (tx.tokenType === 'SPTAssetUpdate') {
      return 'SPT update';
    }

    return 'Transaction';
  }
}

function checkRequired(obj, args, cb?: (e: any) => void) {
  const missing = Utils.getMissingFields(obj, args);
  if (_.isEmpty(missing)) {
    return true;
  }

  if (_.isFunction(cb)) {
    return cb(new ClientError('Required argument: ' + _.first(missing) + ' missing.'));
  }

  return false;
}
