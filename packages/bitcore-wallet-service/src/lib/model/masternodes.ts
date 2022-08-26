import _ from 'lodash';

const Uuid = require('uuid');

export interface IMasternode {
  createdOn: number;
  updatedOn: number;
  walletId: string;
  txid: string;
  masternodePrivKey: string;
  masternodePubKey: string;
  coin: string;
  network: string;
  address: string;
  payee: string;
  status: string;
  proTxHash: string;
  collateralBlock: number;
  lastpaidTime: number;
  lastpaidBlock: number;
  ownerAddr: string;
  voteAddr: string;
  payAddr: string;
  reward: number;
}

export class Masternodes {
  createdOn: number;
  updatedOn: number;
  walletId: string;
  txid: string;
  masternodePrivKey: string;
  masternodePubKey: string;
  coin: string;
  network: string;
  address: string;
  payee: string;
  status: string;
  proTxHash?: string;
  collateralBlock?: number;
  lastpaidTime?: number;
  lastpaidBlock?: number;
  ownerAddr: string;
  voteAddr: string;
  payAddr?: string;
  reward: number;

  static create(opts) {
    opts = opts || {};

    const x = new Masternodes();

    const now = Date.now();
    x.createdOn = Math.floor(now / 1000);
    x.updatedOn = Math.floor(now / 1000);
    x.walletId = opts.walletId;
    x.txid = opts.txid;
    x.address = opts.address;
    x.masternodePrivKey = opts.masternodePrivKey;
    x.masternodePubKey = opts.masternodePubKey;
    x.coin = opts.coin;
    x.network = opts.network;
    x.payee = opts.payee;
    x.status = opts.status;
    x.proTxHash = opts.proTxHash;
    x.collateralBlock = opts.collateralBlock;
    x.lastpaidTime = opts.lastpaidTime;
    x.lastpaidBlock = opts.lastpaidBlock;
    x.ownerAddr = opts.ownerAddr;
    x.voteAddr = opts.voteAddr;
    x.reward = opts.reward;
    x.payAddr = opts.payAddr;
    return x;
  }

  static fromObj(obj) {
    const x = new Masternodes();

    x.createdOn = obj.createdOn;
    x.updatedOn = obj.updatedOn;
    x.walletId = obj.walletId;
    x.txid = obj.txid;
    x.masternodePrivKey = obj.masternodePrivKey;
    x.masternodePubKey = obj.masternodePubKey;
    x.coin = obj.coin;
    x.network = obj.network;
    x.address = obj.address;
    x.payee = obj.payee;
    x.status = obj.status;
    x.proTxHash = obj.proTxHash;
    x.collateralBlock = obj.collateralBlock;
    x.lastpaidTime = obj.lastpaidTime;
    x.lastpaidBlock = obj.lastpaidBlock;
    x.ownerAddr = obj.ownerAddr;
    x.voteAddr = obj.voteAddr;
    x.payAddr = obj.payAddr;
    x.reward = obj.reward;
    return x;
  }

  static fromChain(obj) {
    const x = new Masternodes();
    x.txid = obj.txid;
    x.masternodePubKey = obj.pubkeyoperator;
    x.address = obj.address;
    x.payee = obj.collateraladdress;
    x.status = obj.status;
    x.proTxHash = obj.proTxHash;
    x.collateralBlock = obj.collateralblock;
    x.lastpaidTime = obj.lastpaidtime;
    x.lastpaidBlock = obj.lastpaidblock;
    x.ownerAddr = obj.owneraddress;
    x.voteAddr = obj.votingaddress;
    return x;
  }
}
