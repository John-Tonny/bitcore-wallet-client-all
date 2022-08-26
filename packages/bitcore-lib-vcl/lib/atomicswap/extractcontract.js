'use strict';

var _ = require('lodash');
var $ = require('../util/preconditions');
var errors = require('../errors');
var Base58Check = require('../encoding/base58check');
var Bech32 = require('../encoding/bech32');
var Networks = require('../networks');
var Hash = require('../crypto/hash');
var JSUtil = require('../util/js');
var PublicKey = require('../publickey');
var Opcode = require('../opcode');
var BufferReader = require('../encoding/bufferreader');
var Address = require('../address');
var Signature = require('../crypto/signature');
var Transaction = require('../transaction');
var AuditContract = require('./auditcontract');

const NETWORK = 'livenet';

function ExtractContract(rawTx) {
  if (!(this instanceof ExtractContract)) {
    return new ExtractContract(rawTx);
  }

  this.isAtomicSwap = false;

  if(!JSUtil.isHexa(rawTx)) {
    throw new TypeError('transaction must be string for hex');
  }

  let tx = new Transaction(rawTx);
  let s = new Script(tx.inputs[0]._scriptBuffer);
  if(s.chunks.length != 5 || s.chunks[2].buf.length != 32) {
    throw new TypeError('atomicswap signature invalid');
  }

  let cnt = AuditContract(s.chunks[4].buf.toString('hex'));
  if(!cnt.isAtomicSwap) return this; 
  this.isAtomicSwap = cnt.isAtomicSwap;

  if(cnt.secretHash != Hash.sha256(s.chunks[2].buf).toString('hex')) {
    return this;
  }
  let pubKey = new PublicKey(s.chunks[1].buf)
  let addr = Address.fromPublicKey(pubKey);
  this.signAddr = addr.toString();
  this.redeem = false;
  if(this.signAddr == cnt.recipientAddr) {
    this.redeem = true;
  }
  this.secret = s.chunks[2].buf.toString('hex');
  return this;
}

module.exports = ExtractContract

var Script = require('../script');
