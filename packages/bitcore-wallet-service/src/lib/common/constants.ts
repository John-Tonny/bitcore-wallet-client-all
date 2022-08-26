'use strict';
import * as CWC from 'crypto-wallet-core';

module.exports = {
  COINS: {
    BTC: 'btc',
    BCH: 'bch',
    ETH: 'eth',
    XRP: 'xrp',
    DOGE: 'doge',
    LTC: 'ltc',
    VCL: 'vcl',
    USDC: 'usdc',
    PAX: 'pax',
    GUSD: 'gusd',
    BUSD: 'busd',
    DAI: 'dai',
    WBTC: 'wbtc',
    SHIB: 'shib'
  },

  ERC20: {
    USDC: 'usdc',
    PAX: 'pax',
    GUSD: 'gusd',
    BUSD: 'busd',
    DAI: 'dai',
    WBTC: 'wbtc',
    SHIB: 'shib'
  },

  UTXO_COINS: {
    BTC: 'btc',
    BCH: 'bch',
    DOGE: 'doge',
    LTC: 'ltc',
    VCL: 'vcl'
  },

  NETWORKS: {
    LIVENET: 'livenet',
    TESTNET: 'testnet'
  },

  ADDRESS_FORMATS: ['copay', 'cashaddr', 'legacy'],

  SCRIPT_TYPES: {
    P2SH: 'P2SH',
    P2WSH: 'P2WSH',
    P2PKH: 'P2PKH',
    P2WPKH: 'P2WPKH'
  },
  DERIVATION_STRATEGIES: {
    BIP44: 'BIP44',
    BIP45: 'BIP45'
  },

  PATHS: {
    SINGLE_ADDRESS: "m/0'/0",
    REQUEST_ELECTRUM_KEY: "m/0'",
    REQUEST_KEY: "m/1'/0",
    TXPROPOSAL_KEY: "m/1'/1",
    REQUEST_KEY_AUTH: 'm/2' // relative to BASE
  },

  BIP45_SHARED_INDEX: 0x80000000 - 1,

  TOKEN_OPTS: CWC.Constants.TOKEN_OPTS,

  // john
  COLLATERAL_COIN: parseInt(process.env.COLLATERAL_COIN) || 100000000000,
  MASTERNODE_MIN_CONFIRMATIONS: 15,

  TX_VERSION_MN_REGISTER: 80,
  TX_VERSION_MN_UPDATE_SERVICE: 81,
  TX_VERSION_MN_UPDATE_REGISTRAR: 82,
  TX_VERSION_MN_UPDATE_REVOKE: 83,
  TX_VERSION_MN_COINBASE: 84,
  TX_VERSION_MN_QUORUM_COMMITMENT: 85,

  TX_VERSION_ALLOCATION_BURN_TO_SYSCOIN: 128,
  TX_VERSION_SYSCOIN_BURN_TO_ALLOCATION: 129,
  TX_VERSION_ASSET_ACTIVATE: 130,
  TX_VERSION_ASSET_UPDATE: 131,
  TX_VERSION_ASSET_SEND: 132,
  TX_VERSION_ALLOCATION_MINT: 133,
  TX_VERSION_ALLOCATION_BURN_TO_NEVM: 134,
  TX_VERSION_ALLOCATION_SEND: 135
};
