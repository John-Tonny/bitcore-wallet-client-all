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

function CreateContract(secretHash, themAddr, meAddr, initiate, lockTime, network) {
  if (!(this instanceof CreateContract)) {
    return new CreateContract(secretHash, themAddr, meAddr, initiate, lockTime, network);
  }

  if(!JSUtil.isHexa(secretHash)) {
    throw new TypeError('secretHash must be string for hex');
  }
  if(secretHash.length != 64) {
    throw new TypeError('The length at secretHash must be 64');
  }
  
  let s = new Script();

  s.add(Opcode.OP_IF);  
  s.add(Opcode.OP_SIZE);
  s.add(Buffer.from('20', 'hex'));
  s.add(Opcode.OP_EQUALVERIFY);
    
  // Require initiator's secret to be known to redeem the output.
  s.add(Opcode.OP_SHA256)
  s.add(Buffer.from(secretHash, 'hex'))
  s.add(Opcode.OP_EQUALVERIFY)

  // Verify their signature is being used to redeem the output.  This
  // would normally end with OP_EQUALVERIFY OP_CHECKSIG but this has been
  // moved outside of the branch to save a couple bytes.
  s.add(Opcode.OP_DUP)
  s.add(Opcode.OP_HASH160)
  let themPkh = new Address(themAddr, network || NETWORK);
  s.add(themPkh.hashBuffer)

  s.add(Opcode.OP_ELSE) // Refund path

  // Verify locktime and drop it off the stack (which is not done by
  // CLTV).
  let locktime = parseInt(new Date().getTime()/1000) + 5*60; // 2 * 3600;
  if (initiate) {
    locktime += 5*60; //2*3600;
  }
  if (lockTime) {
    locktime = lockTime;  
  }
  locktime = Buffer.from(locktime.toString('16'),'hex');
  locktime = new BufferReader(locktime).readReverse();

  s.add(locktime)
  s.add(Opcode.OP_CHECKLOCKTIMEVERIFY)
  s.add(Opcode.OP_DROP)

  // Verify our signature is being used to redeem the output.  This would
  // normally end with OP_EQUALVERIFY OP_CHECKSIG but this has been moved
  // outside of the branch to save a couple bytes.
  s.add(Opcode.OP_DUP)
  s.add(Opcode.OP_HASH160)
  let mePkh = new Address(meAddr, network || NETWORK);
  s.add(mePkh.hashBuffer)

  s.add(Opcode.OP_ENDIF)
  // Complete the signature check.
  s.add(Opcode.OP_EQUALVERIFY);
  s.add(Opcode.OP_CHECKSIG);

  this.script = s;
  this.hex = s.toHex();  
  return this;
}

module.exports =  CreateContract

var Script = require('../script');
