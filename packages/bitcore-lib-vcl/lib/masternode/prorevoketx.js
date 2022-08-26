'use strict';

const loadBls = require("blssignatures");

const Uuid = require('uuid');

var $ = require('../util/preconditions');
var errors = require('../errors');
var Base58Check = require('../encoding/base58check');
var Bech32 = require('../encoding/bech32');
var Networks = require('../networks');
var Hash = require('../crypto/hash');
var JSUtil = require('../util/js');
var PrivateKey = require('../privatekey');
var PublicKey = require('../publickey');
var Opcode = require('../opcode');
var BufferReader = require('../encoding/bufferreader');
var BufferWriter = require('../encoding/bufferwriter');
var Address = require('../address');
var Signature = require('../crypto/signature');
var Script = require('../script');
var Message = require('../message');

const ADDRESS_TYPE = 'witnesspubkeyhash';
const NETWORK = 'livenet';
const CURRENT_VERSION = 1;
const LAST_SEASON = 5;


function ProRevokeTx(inputs, proTxHash, masternodePrivKey, reason, network) {
  if (!(this instanceof ProRevokeTx)) {
    return new ProRevokeTx(inputs, proTxHash, masternodePrivKey, reason, network);
  }
  this.version = CURRENT_VERSION;
  this.proTxHash = proTxHash;

  this.inputs = inputs;

  this.masternodePrivKey = masternodePrivKey;
  this.reason = reason || 0;

  this.sig = undefined;

  this.network = network || NETWORK;
}

ProRevokeTx.prototype.get_proTxHash = function(writer) {
  if (!writer) {
    writer = new BufferWriter();
  }
  var buf = new Buffer(this.proTxHash, 'hex');
  writer.writeReverse(buf);
  return writer;
}

ProRevokeTx.prototype.get_inputHash = function(writer) {
  if (!writer) {
    writer = new BufferWriter();
  }
  var writer1 = new BufferWriter();
  for(var i=0;i<this.inputs.length;i++) {
    var buf = new Buffer(this.inputs[i].txid, 'hex');
    writer1.writeReverse(buf);
    writer1.writeUInt32LE(this.inputs[i].vout);
    var hash = Hash.sha256sha256(writer1.toBuffer());
  }
  console.log("hash:", hash.toString('hex'));
  return writer.write(hash, 32);
}

ProRevokeTx.prototype.get_message = function(writer) {
  return  Hash.sha256sha256(writer.toBuffer());
}

ProRevokeTx.prototype.get_signMessage = async function(writer, sigMode) {
  var BLS = await loadBls();
  if (!writer) {
    writer = new BufferWriter();
  }
  if(!sigMode){
    writer.writeUInt8(0);
    return writer;
  }

  var privKey = BLS.PrivateKey.fromBytes(Buffer.from(this.masternodePrivKey, 'hex') ,false);
  var publicKey = privKey.get_g1();

  var msgHash = this.get_message(writer);

  try{
    var signature =  BLS.LegacySchemeMPL.sign(privKey, msgHash);

    const isValid = BLS.LegacySchemeMPL.verify(publicKey, msgHash, signature);
    if(!isValid){
      throw new TypeError('verify is invalid');
    }
    
    var arrSignature = signature.serialize(true);

    if(arrSignature.length != 96){
      throw new TypeError('singature length is invalid');
    }
    writer.write(arrSignature, 96);

    privKey.delete();
    publicKey.delete();
    signature.delete();

    return writer;
  }catch(error) {
    privKey.delete();
    publicKey.delete();
    signature.delete();
    throw new TypeError('sign is error');
  }
}

ProRevokeTx.prototype.getScript = async function(sigMode) {
  var writer = new BufferWriter();

  writer.writeUInt16LE(this.version);
  this.get_proTxHash(writer);
  writer.writeUInt16LE(this.reason); 
  this.get_inputHash(writer);

  this.get_signMessage(writer, sigMode);

  var n = writer.toBuffer().length;
  var writer1 = new BufferWriter();
  writer1.writeUInt8(Opcode.OP_RETURN);
  if (n < 253) {
    writer1.writeUInt8(Opcode.OP_PUSHDATA1);
    writer1.writeUInt8(n);
  } else {
    writer1.writeUInt8(Opcode.OP_PUSHDATA2);
    writer1.writeUInt16LE(n);
  }
  writer1.write(writer.toBuffer(), n);
  return writer1.toBuffer().toString('hex');
}

ProRevokeTx.prototype.set_sig = function(sig) {
  this.sig = sig.signature;
  return this;
}

ProRevokeTx.prototype.serialize = function(writer, bFull) {
  if (!writer) {
    writer = new BufferWriter();
  }

  writer.writeUInt16LE(this.version);
  this.get_proTxHash(writer);
  writer.writeUInt16LE(this.reason);
  this.get_inputHash(writer);

  if(this.sig && bFull){
    writer.write(Buffer.from(this.sig, 'hex'), 96);
  }

  return writer.toBuffer().toString('hex');
}

ProRevokeTx.prototype.getMessageHash = function() {
  var writer = new BufferWriter();
  var message = this.serialize(writer, false);

  var msgHash = Hash.sha256sha256(Buffer.from(message, 'hex'));

  var writer1 = new BufferWriter();
  writer1.writeReverse(msgHash);

  return writer1.toBuffer().toString('hex');
}

ProRevokeTx.prototype.getScript1 = function() {
  var writer = new BufferWriter();
  this.serialize(writer, true);

  var n = writer.toBuffer().length;
  var writer1 = new BufferWriter();
  writer1.writeUInt8(Opcode.OP_RETURN);
  if (n < 253) {
    writer1.writeUInt8(Opcode.OP_PUSHDATA1);
    writer1.writeUInt8(n);
  } else {
    writer1.writeUInt8(Opcode.OP_PUSHDATA2);
    writer1.writeUInt16LE(n);
  }
  writer1.write(writer.toBuffer(), n);
  return writer1.toBuffer().toString('hex');
}


module.exports = ProRevokeTx;

