'use strict';

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

function ProUpRegTx(inputs, proTxHash, ownerPrivKey, masternodePubKey, voteAddr, payAddr, network) {
  if (!(this instanceof ProUpRegTx)) {
    return new ProUpRegTx(inputs, proTxHash, ownerPrivKey, masternodePubKey, voteAddr, payAddr, network);
  }
  this.version = CURRENT_VERSION;
  this.proTxHash = proTxHash;
  this.mode = 0

  this.inputs = inputs;

  this.ownerPrivKey = ownerPrivKey;

  this.masternodePubKey = masternodePubKey;
  this.voteAddr = voteAddr;
  this.payAddr = payAddr;

  this.network = network || NETWORK;
}

ProUpRegTx.fromString = function(strHex, network, addressType) {

  var network = network || NETWORK;
  var addressType = addressType || ADDRESS_TYPE;

  if(!JSUtil.isHexa(strHex)) {
    throw new TypeError('proUpRegTx must be string for hex');
  }

  if(strHex.length != 456){
    throw new TypeError('The length at proUpRegTx must be 456');
  }

  var s = new Script(strHex);

  if (s.chunks.length != 2 || s.chunks[0].opcodenum != Opcode.OP_RETURN || s.chunks[1].len != 225) {
    throw new TypeError('proUpRegTx is invalid');
  }

  var reader = new BufferReader(s.chunks[1].buf);
  var version = reader.readUInt16LE();
  var proTxHash =  reader.readReverse(32).toString('hex');
  var mode = reader.readUInt16LE();

  var masternodePubKey = reader.read(48).toString('hex');
  var voteAddr = new Address(reader.read(20), network, addressType).toString();
  var prefix = reader.read(3);  
  var payAddr = new Address(reader.read(20), network, addressType).toString();

  return new ProUpRegTx(undefined, proTxHash, undefined, masternodePubKey, voteAddr, payAddr, network);
}

ProUpRegTx.prototype.get_proTxHash = function(writer) {
  if (!writer) {
    writer = new BufferWriter();
  }
  var buf = new Buffer(this.proTxHash, 'hex');
  writer.writeReverse(buf);
  return writer;
}

ProUpRegTx.prototype.get_inputHash = function(writer) {
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
  return writer.write(hash, 32);
}

ProUpRegTx.prototype.get_address = function(writer, address, mode) {
  if (!writer) {
    writer = new BufferWriter();
  }

  var addr = new Address(address, this.network || NETWORK);
  if(!addr || !addr.hashBuffer || addr.hashBuffer.length !=20 ){
    throw new TypeError('addr is invalid');
  }
  if(mode){
    writer.write(Buffer.from('160014', 'hex'), 3);
  }
  writer.write(addr.hashBuffer, 20); 
  return writer;
}

ProUpRegTx.prototype.get_message = function(writer) {
  return writer.toBuffer().toString('hex');
}

ProUpRegTx.prototype.get_signMessage = function(writer, sigMode) {
  if (!writer) {
    writer = new BufferWriter();
  }
  if(!sigMode){
    writer.writeUInt8(0);
    return writer;
  }

  var privKey = PrivateKey.fromWIF(this.ownerPrivKey);
  var msg = this.get_message(writer);
  var message = new Message(msg);
  var signature = message.sign2(privKey, true);
  
  var isValid = message.verify2(privKey.toAddress().toString(), signature); 
  if(!isValid){
    throw new TypeError('verify is invalid');
  }

  var buf = new Buffer(signature, 'base64');
  if(!buf || buf.length != 65){
    throw new TypeError('singature is invalid');
  }
  writer.writeUInt8(65);
  writer.write(buf, 65);
 
  return writer;
}

ProUpRegTx.prototype.getScript = function(sigMode) {
  var writer = new BufferWriter();

  writer.writeUInt16LE(this.version);
  this.get_proTxHash(writer);
  writer.writeUInt16LE(this.mode);
  
  writer.write(Buffer.from(this.masternodePubKey, 'hex'), 48);
  this.get_address(writer, this.voteAddr);
  this.get_address(writer, this.payAddr, true);
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

module.exports = ProUpRegTx;

