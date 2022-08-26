'use strict';
const Uuid = require('uuid');

const loadBls = require('blssignatures');

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

function ProUpServiceTx(inputs, proTxHash, host, port, masternodePrivKey, payAddr, network) {
  if (!(this instanceof ProUpServiceTx)) {
    return new ProUpServiceTx(inputs, proTxHash, host, port, masternodePrivKey, payAddr, network);
  }
  this.version = CURRENT_VERSION;
  this.proTxHash = proTxHash;

  this.inputs = inputs;
  
  this.host = host;
  this.port = port;

  this.masternodePrivKey = masternodePrivKey;
  this.payAddr = payAddr;
  this.sig = undefined;

  this.network = network || NETWORK;
}

ProUpServiceTx.fromString = function(strHex, network, addressType) {

  var network = network || NETWORK;
  var addressType = addressType || ADDRESS_TYPE;

  if(!JSUtil.isHexa(strHex)) {
    throw new TypeError('proUpServiceTx must be string for hex');
  }

  if(strHex.length != 368){
    throw new TypeError('The length at proUpServiceTx must be 368');
  }

  var s = new Script(strHex);

  if (s.chunks.length != 2 || s.chunks[0].opcodenum != Opcode.OP_RETURN || s.chunks[1].len != 181) {
    throw new TypeError('proUpServiceTx is invalid');
  }

  var reader = new BufferReader(s.chunks[1].buf);
  var version = reader.readUInt16LE();
  var proTxHash =  reader.readReverse(32).toString('hex');

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

  var payData = reader.read(20);
  var payAddr;
  if(payData[0]!=0){
    payAddr = new Address(payData, network, addressType).toString();
  }
  return new ProUpServiceTx(undefined, proTxHash, host , port , undefined, payAddr, network);
}


ProUpServiceTx.prototype.get_proTxHash = function(writer) {
  if (!writer) {
    writer = new BufferWriter();
  }
  var buf = new Buffer(this.proTxHash, 'hex');
  writer.writeReverse(buf);
  return writer;
}

ProUpServiceTx.prototype.get_inputHash = function(writer) {
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

ProUpServiceTx.prototype.get_ip = function(writer) {
  if (!writer) {
    writer = new BufferWriter();
  }

  writer.write(Buffer.from('00000000000000000000ffff', 'hex'), 12);

  var ip = this.host.split('.');
  ip.forEach(v => ( writer.writeUInt8(v)));

  writer.writeUInt16BE(this.port);
  return writer;
}

ProUpServiceTx.prototype.get_address = function(writer, address, mode) {
  if (!writer) {
    writer = new BufferWriter();
  }

  if(!address){
    writer.writeUInt8(0);
    return writer;
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

ProUpServiceTx.prototype.get_message = function(writer) {
  return  Hash.sha256sha256(writer.toBuffer());  
}

ProUpServiceTx.prototype.get_signMessage = async function(writer, sigMode) {
  var BLS = await loadBls();
  if (!writer) {
    writer = new BufferWriter();
  }
  if(!sigMode){
    writer.writeUInt8(0);
    return writer;
  }
  
  var privKey = BLS.PrivateKey.from_bytes(Buffer.from(this.masternodePrivKey, 'hex'), false);
  var publicKey = privKey.get_g1();

  var msgHash = this.get_message(writer);

  try{
    var signature = BLS.LegacySchemeMPL.sign(privKey, msgHash);
  
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

ProUpServiceTx.prototype.getScript = async function(sigMode) {
  var writer = new BufferWriter();

  writer.writeUInt16LE(this.version);
  this.get_proTxHash(writer);
  this.get_ip(writer);  
  this.get_address(writer, this.payAddr, true);
  this.get_inputHash(writer);

  await this.get_signMessage(writer, sigMode);

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

ProUpServiceTx.prototype.set_sig = function(sig) {
  this.sig = sig.signature;
  return this;
}

ProUpServiceTx.prototype.serialize = function(writer, bFull) {
  if (!writer) {
    writer = new BufferWriter();
  }

  writer.writeUInt16LE(this.version);
  this.get_proTxHash(writer);
  this.get_ip(writer);
  this.get_address(writer, this.payAddr, true);
  this.get_inputHash(writer);
  if(this.sig && bFull){
    writer.write(Buffer.from(this.sig, 'hex'), 96);
  }

  return writer.toBuffer().toString('hex');
}

ProUpServiceTx.prototype.getMessageHash = function() {
  var writer = new BufferWriter();
  var message = this.serialize(writer, false);

  var msgHash = Hash.sha256sha256(Buffer.from(message, 'hex'));

  var writer1 = new BufferWriter();
  writer1.writeReverse(msgHash);

  return writer1.toBuffer().toString('hex');
}

ProUpServiceTx.prototype.getScript1 = function() {
  var writer = new BufferWriter();
  var message = this.serialize(writer, true);

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

module.exports = ProUpServiceTx;

