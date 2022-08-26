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

function ProRegTx(inputs, collateralId, collateralIndex, collateralPrivKey,  host, port, masternodePubKey, ownerAddr, voteAddr, payAddr, reward, network) {
  if (!(this instanceof ProRegTx)) {
    return new ProRegTx(inputs, collateralId, collateralIndex, collateralPrivKey,  host, port, masternodePubKey, ownerAddr, voteAddr, payAddr, reward, network);
  }
  this.version = CURRENT_VERSION;
  this.type = 0;
  this.mode = 0

  this.inputs = inputs;
  this.collateralId = collateralId;
  this.collateralIndex = collateralIndex;
  this.collateralPrivKey = collateralPrivKey;

  this.host = host;
  this.port = port;

  this.masternodePubKey = masternodePubKey;
  this.ownerAddr = ownerAddr;
  this.voteAddr = voteAddr;
  this.payAddr = payAddr;

  this.reward = reward || 0;

  this.network = network || NETWORK;
}

ProRegTx.prototype.get_collateral = function(writer) {
  if (!writer) {
    writer = new BufferWriter();
  }
  var buf = new Buffer(this.collateralId, 'hex');
  writer.writeReverse(buf);
  writer.writeUInt32LE(this.collateralIndex);
  return writer;
}

ProRegTx.prototype.get_inputHash = function(writer) {
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

ProRegTx.prototype.get_ip = function(writer) {
  if (!writer) {
    writer = new BufferWriter();
  }
  
  writer.write(Buffer.from('00000000000000000000ffff', 'hex'), 12);

  var ip = this.host.split('.');
  ip.forEach(v => ( writer.writeUInt8(v)));

  writer.writeUInt16BE(this.port);
  return writer;
}

ProRegTx.prototype.get_address = function(writer, address, mode) {
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

ProRegTx.prototype.get_message = function(writer) {
  var reward = this.reward * 100;
  var hash = Hash.sha256sha256(writer.toBuffer()).reverse().toString('hex');
  return this.payAddr + '|' +  reward.toString()  + '|' + this.ownerAddr  + '|' + this.voteAddr + '|' + hash;
}

ProRegTx.prototype.get_signMessage = function(writer, sigMode) {
  if (!writer) {
    writer = new BufferWriter();
  }
  if(!sigMode){
    writer.writeUInt8(0);
    return writer;
  }

  var privKey = PrivateKey.fromWIF(this.collateralPrivKey);
  var msg = this.get_message(writer);
  var message = new Message(msg); 
  var signature = message.sign(privKey, true);
  
  var isValid = message.verify(privKey.toAddress().toString(), signature); 
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

ProRegTx.prototype.getScript = function(sigMode) {
  var writer = new BufferWriter();

  writer.writeUInt16LE(this.version);
  writer.writeUInt16LE(this.type);
  writer.writeUInt16LE(this.mode);
  
  this.get_collateral(writer);
  this.get_ip(writer);
  
  this.get_address(writer, this.ownerAddr);
  writer.write(Buffer.from(this.masternodePubKey, 'hex'), 48);
  this.get_address(writer, this.voteAddr);
  writer.writeUInt16LE(this.reward * 100);
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

ProRegTx.fromString = function(strHex, network, addressType) {
 
  var network = network || NETWORK;
  var addressType = addressType || ADDRESS_TYPE;

  if(!JSUtil.isHexa(strHex)) {
    throw new TypeError('proRegTx must be string for hex');
  }

  if(strHex.length != 550){
    throw new TypeError('The length at proRegTx must be 550');
  }
  
  var s = new Script(strHex);
  
  if (s.chunks.length != 2 || s.chunks[0].opcodenum != Opcode.OP_RETURN || s.chunks[1].len != 271) {
    throw new TypeError('proRegTx is invalid');
  }

  var reader = new BufferReader(s.chunks[1].buf);
  var version = reader.readUInt16LE();
  var type = reader.readUInt16LE();
  var mode = reader.readUInt16LE();

  var collateralId =  reader.readReverse(32).toString('hex');
  var collateralIndex = reader.readUInt32LE();
  
  var ip = reader.read(16);
  var host = '';
  for( var i =0; i<4; i++) {
    if(i<3){
      host += ip[12+i] + '.';
    }else{
      host += ip[12+i];
    }
  }

  var port = reader.readUInt16BE();
  
  var ownerAddr = new Address(reader.read(20), network, addressType).toString();
  var masternodePubKey = reader.read(48).toString('hex');
  var voteAddr = new Address(reader.read(20), network, addressType).toString();

  var reward = reader.readUInt16LE();
  var payAddr = new Address(reader.read(23).slice(3, 23), network, addressType).toString();

  return new ProRegTx(undefined, collateralId, collateralIndex, undefined,  host, port, masternodePubKey, ownerAddr, voteAddr, payAddr, reward, network);
}

module.exports = ProRegTx;

