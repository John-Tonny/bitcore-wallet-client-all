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

const NETWORK = 'livenet';

function AuditContract(contract,network) {
  if (!(this instanceof AuditContract)) {
    return new AuditContract(contract, network);
  }

  if(!JSUtil.isHexa(contract)) { 
    throw new TypeError('contract must be string for hex');
  }
 
  let s = new Script(Buffer.from(contract, 'hex'));
  this.isAtomicSwap = false;
  if (s.chunks.length != 20) {
    return this;
  }
  
  this.isAtomicSwap = false;
  
  if(s.chunks[0].opcodenum == Opcode.OP_IF &&
      s.chunks[1].opcodenum == Opcode.OP_SIZE &&
      canonicalPush(s.chunks[2]) &&
      s.chunks[3].opcodenum == Opcode.OP_EQUALVERIFY &&
      s.chunks[4].opcodenum == Opcode.OP_SHA256 &&
      s.chunks[5].opcodenum == Opcode.OP_DATA_32 &&
      s.chunks[6].opcodenum == Opcode.OP_EQUALVERIFY &&
      s.chunks[7].opcodenum == Opcode.OP_DUP &&
      s.chunks[8].opcodenum == Opcode.OP_HASH160 &&
      s.chunks[9].opcodenum == Opcode.OP_DATA_20 &&
      s.chunks[10].opcodenum == Opcode.OP_ELSE &&
      canonicalPush(s.chunks[11]) &&
      s.chunks[12].opcodenum == Opcode.OP_CHECKLOCKTIMEVERIFY &&
      s.chunks[13].opcodenum == Opcode.OP_DROP &&
      s.chunks[14].opcodenum == Opcode.OP_DUP &&
      s.chunks[15].opcodenum == Opcode.OP_HASH160 &&
      s.chunks[16].opcodenum == Opcode.OP_DATA_20 &&
      s.chunks[17].opcodenum == Opcode.OP_ENDIF &&
      s.chunks[18].opcodenum == Opcode.OP_EQUALVERIFY &&
      s.chunks[19].opcodenum == Opcode.OP_CHECKSIG){
    this.isAtomicSwap = true;
  }
  
  if(!this.isAtomicSwap){
    return this;
  }  
  
  if(s.chunks[5].buf.length != 32){
    return this;
  }
   
  this.secretHash = s.chunks[5].buf.toString('hex');
  this.recipientAddr = new Address(s.chunks[9].buf, network || NETWORK).toString();

  this.refundAddr = new Address(s.chunks[16].buf, network || NETWORK).toString();
  this.lockTime  = parseInt(new BufferReader(s.chunks[11].buf).readReverse().toString('hex'), 16);

  if(s.chunks[2].buf){
  }

  this.secretSize = parseInt(s.chunks[2].buf.toString('hex'), 16);
 
  let contractHash = Hash.sha256ripemd160(Buffer.from(contract, 'hex'));
  this.contractAddr = Address.fromScriptHash(contractHash, network || NETWORK , Address.PayToScriptHash).toString();
 
  this.amount = 0; 
  return this;
}

function canonicalPush(pop) {
  let opcode = pop.opcodenum;
  let data = pop.buf;
  let dataLen = data.length;
  if (opcode > Opcode.OP_16) {
    return true;
  }

  if (opcode < Opcode.OP_PUSHDATA1 && opcode > Opcode.OP_0 && (dataLen == 1 && data[0] <= 16)) {
    return false;
  }
  if (opcode == Opcode.OP_PUSHDATA1 && dataLen < Opcode.OP_PUSHDATA1) {
    return false;
  }
  if (opcode == Opcode.OP_PUSHDATA2 && dataLen <= 0xff) {
    return false;
  }
  if (opcode == Opcode.OP_PUSHDATA4 && dataLen <= 0xffff) {
    return false;
  }
  return true;
}

/**
 * Internal function used to split different kinds of arguments of the constructor
 * @param {*} data - The encoded data in various formats
 * @param {Network|String|number=} network - The network: 'livenet' or 'testnet'
 * @param {string=} type - The type of address: 'script' or 'pubkey'
 * @returns {Object} An "info" object with "type", "network", and "hashBuffer"
 */
AuditContract.prototype._classifyArguments = function(data, network, type) {
};


AuditContract.prototype.setRedeem = function(redeem) {
  this.redeem = redeem;
  return this;
};


module.exports = AuditContract

var Script = require('../script');
