'use strict';
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Masternode = void 0;
const CWC = __importStar(require("crypto-wallet-core"));
var $ = require('preconditions').singleton();
var log = require('./log');
const Uuid = require('uuid');
var Errors = require('./errors');
var Bitcore = CWC.BitcoreLibVcl;
const CLIENT_VERSION = 1000000;
const CLIENT_SENTINEL_VERSION = 1000000;
const CLIENT_MASTERNODE_VERSION = 1010191;
let Masternode = (() => {
    class Masternode {
        constructor(txid, vout, signPrivKey, pingHash, privKey, addr, port) {
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
        serialize_input() {
            var buf = new Buffer(this.txid, 'hex');
            buf.reverse();
            var buf1 = new Buffer(4);
            buf1.writeUIntLE(this.vout, 0, 4);
            return buf.toString('hex') + buf1.toString('hex');
        }
        hash_decode() {
            var buf = new Buffer(this.pingHash, 'hex');
            buf.reverse();
            return buf.toString('hex');
        }
        get_address() {
            var result = '';
            result = '00000000000000000000ffff';
            var ip = this.addr.split('.');
            ip.forEach(v => (result += this.get_int8(v)));
            result += this.get_int16BE(this.port);
            return result;
        }
        get_now_time() {
            var t1 = Math.floor(new Date().getTime() / 1000);
            return this.get_int64(t1);
        }
        get_int64(value) {
            const MAX_UINT32 = 0xffffffff;
            var buf = new Buffer(8);
            const high = parseInt((value / MAX_UINT32).toString());
            const low = (value % MAX_UINT32) - high;
            buf.writeUInt32LE(low, 0);
            buf.writeUInt32LE(high, 4);
            return buf.toString('hex');
        }
        get_int32(value) {
            var buf = new Buffer(4);
            buf.writeUIntLE(value, 0, 4);
            return buf.toString('hex');
        }
        get_int16BE(value) {
            var buf = new Buffer(2);
            buf.writeUIntBE(value, 0, 2);
            return buf.toString('hex');
        }
        get_int16(value) {
            var buf = new Buffer(2);
            buf.writeUIntLE(value, 0, 2);
            return buf.toString('hex');
        }
        get_int8(value) {
            var buf = new Buffer(1);
            buf.writeUIntLE(value, 0, 1);
            return buf.toString('hex');
        }
        get_varintNum(n) {
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
                const MAX_UINT32 = 0xffffffff;
                buf = Buffer.alloc(1 + 8);
                buf.writeUInt8(255, 0);
                const high = parseInt((n / MAX_UINT32).toString());
                const low = (n % MAX_UINT32) - high;
                buf.writeUInt32LE(low, 1);
                buf.writeUInt32LE(high, 5);
            }
            return buf.toString('hex');
        }
    }
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
})();
exports.Masternode = Masternode;
//# sourceMappingURL=masternode.js.map