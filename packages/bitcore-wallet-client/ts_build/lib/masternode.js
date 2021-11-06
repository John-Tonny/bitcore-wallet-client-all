'use strict';
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
var CWC = __importStar(require("crypto-wallet-core"));
var $ = require('preconditions').singleton();
var log = require('./log');
var Uuid = require('uuid');
var Errors = require('./errors');
var Bitcore = CWC.VircleLib;
var CLIENT_VERSION = 1000000;
var CLIENT_SENTINEL_VERSION = 1000000;
var CLIENT_MASTERNODE_VERSION = 1010191;
var Masternode = (function () {
    function Masternode(txid, vout, signPrivKey, pingHash, privKey, addr, port) {
        this.singMasternode = function () {
            var presult = '';
            presult += this.serialize_input();
            presult += this.hash_decode();
            var pingTime = this.get_now_time();
            presult += pingTime;
            presult += '01';
            presult += this.get_int32(Math.floor(CLIENT_SENTINEL_VERSION / 1000000));
            presult += this.get_int32(Math.floor(CLIENT_MASTERNODE_VERSION / 1000000));
            var pingMsg = new Bitcore.Message(presult);
            var pingKey = new Bitcore.PrivateKey(this.privKey);
            var pingSig = pingMsg.sign1(pingKey);
            var result = '';
            result += this.serialize_input();
            result += this.get_address();
            var signPubKey = this.signPrivKey.publicKey.toString('hex');
            result += this.get_varintNum(signPubKey.length / 2);
            result += signPubKey;
            var pubKey = pingKey.publicKey.toString('hex');
            result += this.get_varintNum(pubKey.length / 2);
            result += pubKey;
            var signTime = this.get_now_time();
            result += signTime;
            result += this.get_int32(31800);
            var msg = new Bitcore.Message(result);
            var sig = msg.sign1(this.signPrivKey);
            var sresult = '01';
            sresult += this.serialize_input();
            sresult += this.get_address();
            sresult += this.get_varintNum(signPubKey.length / 2);
            sresult += signPubKey;
            sresult += this.get_varintNum(pubKey.length / 2);
            sresult += pubKey;
            sresult += this.get_varintNum(sig.length / 2);
            sresult += sig;
            sresult += signTime;
            sresult += this.get_int32(31800);
            sresult += this.serialize_input();
            sresult += this.hash_decode();
            sresult += pingTime;
            sresult += this.get_varintNum(pingSig.length / 2);
            sresult += pingSig;
            sresult += '01';
            sresult += this.get_int32(CLIENT_SENTINEL_VERSION);
            sresult += this.get_int32(CLIENT_MASTERNODE_VERSION);
            var retrys = 0;
            sresult += this.get_int32(retrys);
            return sresult;
        };
        this.version = 1;
        this.id = Uuid.v4();
        this.txid = txid;
        this.vout = vout;
        this.signPrivKey = signPrivKey;
        this.pingHash = pingHash;
        this.privKey = privKey;
        this.addr = addr;
        this.port = port;
    }
    Masternode.prototype.serialize_input = function () {
        var buf = new Buffer(this.txid, 'hex');
        buf.reverse();
        var buf1 = new Buffer(4);
        buf1.writeUIntLE(this.vout, 0, 4);
        return buf.toString('hex') + buf1.toString('hex');
    };
    Masternode.prototype.hash_decode = function () {
        var buf = new Buffer(this.pingHash, 'hex');
        buf.reverse();
        return buf.toString('hex');
    };
    Masternode.prototype.get_address = function () {
        var _this = this;
        var result = '';
        result = '00000000000000000000ffff';
        var ip = this.addr.split('.');
        ip.forEach(function (v) { return (result += _this.get_int8(v)); });
        result += this.get_int16BE(this.port);
        return result;
    };
    Masternode.prototype.get_now_time = function () {
        var t1 = Math.floor(new Date().getTime() / 1000);
        return this.get_int64(t1);
    };
    Masternode.prototype.get_int64 = function (value) {
        var MAX_UINT32 = 0xffffffff;
        var buf = new Buffer(8);
        var high = parseInt((value / MAX_UINT32).toString());
        var low = (value % MAX_UINT32) - high;
        buf.writeUInt32LE(low, 0);
        buf.writeUInt32LE(high, 4);
        return buf.toString('hex');
    };
    Masternode.prototype.get_int32 = function (value) {
        var buf = new Buffer(4);
        buf.writeUIntLE(value, 0, 4);
        return buf.toString('hex');
    };
    Masternode.prototype.get_int16BE = function (value) {
        var buf = new Buffer(2);
        buf.writeUIntBE(value, 0, 2);
        return buf.toString('hex');
    };
    Masternode.prototype.get_int16 = function (value) {
        var buf = new Buffer(2);
        buf.writeUIntLE(value, 0, 2);
        return buf.toString('hex');
    };
    Masternode.prototype.get_int8 = function (value) {
        var buf = new Buffer(1);
        buf.writeUIntLE(value, 0, 1);
        return buf.toString('hex');
    };
    Masternode.prototype.get_varintNum = function (n) {
        var buf;
        if (n < 253) {
            buf = Buffer.alloc(1);
            buf.writeUInt8(n, 0);
        }
        else if (n < 0x10000) {
            buf = Buffer.alloc(1 + 2);
            buf.writeUInt8(253, 0);
            buf.writeUInt16LE(n, 1);
        }
        else if (n < 0x100000000) {
            buf = Buffer.alloc(1 + 4);
            buf.writeUInt8(254, 0);
            buf.writeUInt32LE(n, 1);
        }
        else {
            var MAX_UINT32 = 0xffffffff;
            buf = Buffer.alloc(1 + 8);
            buf.writeUInt8(255, 0);
            var high = parseInt((n / MAX_UINT32).toString());
            var low = (n % MAX_UINT32) - high;
            buf.writeUInt32LE(low, 1);
            buf.writeUInt32LE(high, 5);
        }
        return buf.toString('hex');
    };
    Masternode.FIELDS = [
        'version',
        'id',
        'txid',
        'vout',
        'signPrivKey',
        'pingHash',
        'privKey',
        'addr',
        'port'
    ];
    return Masternode;
}());
exports.Masternode = Masternode;
//# sourceMappingURL=masternode.js.map