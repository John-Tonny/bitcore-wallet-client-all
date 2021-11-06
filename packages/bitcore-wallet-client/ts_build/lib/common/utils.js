'use strict';
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
var crypto_wallet_core_1 = require("crypto-wallet-core");
var _ = __importStar(require("lodash"));
var constants_1 = require("./constants");
var defaults_1 = require("./defaults");
var $ = require('preconditions').singleton();
var sjcl = require('sjcl');
var Stringify = require('json-stable-stringify');
var Bitcore = crypto_wallet_core_1.VircleLib;
var Bitcore_ = {
    vcl: crypto_wallet_core_1.VircleLib
};
var PrivateKey = Bitcore.PrivateKey;
var PublicKey = Bitcore.PublicKey;
var crypto = Bitcore.crypto;
var SJCL = {};
var MAX_DECIMAL_ANY_COIN = 18;
var Utils = (function () {
    function Utils() {
    }
    Utils.getChain = function (coin) {
        var normalizedChain = coin.toUpperCase();
        if (constants_1.Constants.ERC20.includes(coin)) {
            normalizedChain = 'ETH';
        }
        return normalizedChain;
    };
    Utils.encryptMessage = function (message, encryptingKey) {
        var key = sjcl.codec.base64.toBits(encryptingKey);
        return sjcl.encrypt(key, message, _.defaults({
            ks: 128,
            iter: 1
        }, SJCL));
    };
    Utils.decryptMessage = function (cyphertextJson, encryptingKey) {
        if (!cyphertextJson)
            return;
        if (!encryptingKey)
            throw new Error('No key');
        var key = sjcl.codec.base64.toBits(encryptingKey);
        return sjcl.decrypt(key, cyphertextJson);
    };
    Utils.decryptMessageNoThrow = function (cyphertextJson, encryptingKey) {
        if (!encryptingKey)
            return '<ECANNOTDECRYPT>';
        if (!cyphertextJson)
            return '';
        var r = this.isJsonString(cyphertextJson);
        if (!r || !r.iv || !r.ct) {
            return cyphertextJson;
        }
        try {
            return this.decryptMessage(cyphertextJson, encryptingKey);
        }
        catch (e) {
            return '<ECANNOTDECRYPT>';
        }
    };
    Utils.isJsonString = function (str) {
        var r;
        try {
            r = JSON.parse(str);
        }
        catch (e) {
            return false;
        }
        return r;
    };
    Utils.hashMessage = function (text) {
        $.checkArgument(text);
        var buf = Buffer.from(text);
        var ret = crypto.Hash.sha256sha256(buf);
        ret = new Bitcore.encoding.BufferReader(ret).readReverse();
        return ret;
    };
    Utils.signMessage = function (message, privKey) {
        $.checkArgument(message);
        var priv = new PrivateKey(privKey);
        var flattenedMessage = _.isArray(message) ? _.join(message) : message;
        var hash = this.hashMessage(flattenedMessage);
        return crypto.ECDSA.sign(hash, priv, 'little').toString();
    };
    Utils.verifyMessage = function (message, signature, pubKey) {
        $.checkArgument(message);
        $.checkArgument(pubKey);
        if (!signature)
            return false;
        var pub = new PublicKey(pubKey);
        var flattenedMessage = _.isArray(message) ? _.join(message) : message;
        var hash = this.hashMessage(flattenedMessage);
        try {
            var sig = new crypto.Signature.fromString(signature);
            return crypto.ECDSA.verify(hash, sig, pub, 'little');
        }
        catch (e) {
            return false;
        }
    };
    Utils.privateKeyToAESKey = function (privKey) {
        $.checkArgument(privKey && _.isString(privKey));
        $.checkArgument(Bitcore.PrivateKey.isValid(privKey), 'The private key received is invalid');
        var pk = Bitcore.PrivateKey.fromString(privKey);
        return Bitcore.crypto.Hash.sha256(pk.toBuffer())
            .slice(0, 16)
            .toString('base64');
    };
    Utils.getCopayerHash = function (name, xPubKey, requestPubKey) {
        return [name, xPubKey, requestPubKey].join('|');
    };
    Utils.getProposalHash = function (proposalHeader) {
        if (arguments.length > 1) {
            return this.getOldHash.apply(this, arguments);
        }
        return Stringify(proposalHeader);
    };
    Utils.getOldHash = function (toAddress, amount, message, payProUrl) {
        return [toAddress, amount, message || '', payProUrl || ''].join('|');
    };
    Utils.parseDerivationPath = function (path) {
        var pathIndex = /m\/([0-9]*)\/([0-9]*)/;
        var _a = path.match(pathIndex), _input = _a[0], changeIndex = _a[1], addressIndex = _a[2];
        var isChange = Number.parseInt(changeIndex) > 0;
        return { _input: _input, addressIndex: addressIndex, isChange: isChange };
    };
    Utils.deriveAddress = function (scriptType, publicKeyRing, path, m, network, coin) {
        $.checkArgument(_.includes(_.values(constants_1.Constants.SCRIPT_TYPES), scriptType));
        coin = coin || 'vcl';
        var chain = this.getChain(coin).toLowerCase();
        var bitcore = Bitcore_[chain];
        var publicKeys = _.map(publicKeyRing, function (item) {
            var xpub = new bitcore.HDPublicKey(item.xPubKey);
            return xpub.deriveChild(path).publicKey;
        });
        var bitcoreAddress;
        switch (scriptType) {
            case constants_1.Constants.SCRIPT_TYPES.P2WSH:
                var nestedWitness = false;
                bitcoreAddress = bitcore.Address.createMultisig(publicKeys, m, network, nestedWitness, 'witnessscripthash');
                break;
            case constants_1.Constants.SCRIPT_TYPES.P2SH:
                bitcoreAddress = bitcore.Address.createMultisig(publicKeys, m, network);
                break;
            case constants_1.Constants.SCRIPT_TYPES.P2WPKH:
                bitcoreAddress = bitcore.Address.fromPublicKey(publicKeys[0], network, 'witnesspubkeyhash');
                break;
            case constants_1.Constants.SCRIPT_TYPES.P2PKH:
                $.checkState(_.isArray(publicKeys) && publicKeys.length == 1);
                if (constants_1.Constants.UTXO_COINS.includes(coin)) {
                    bitcoreAddress = bitcore.Address.fromPublicKey(publicKeys[0], network);
                }
                else {
                    var _a = this.parseDerivationPath(path), addressIndex = _a.addressIndex, isChange = _a.isChange;
                    var xPubKey = publicKeyRing[0].xPubKey;
                    bitcoreAddress = crypto_wallet_core_1.Deriver.deriveAddress(chain.toUpperCase(), network, xPubKey, addressIndex, isChange);
                }
                break;
        }
        return {
            address: bitcoreAddress.toString(true),
            path: path,
            publicKeys: _.invokeMap(publicKeys, 'toString')
        };
    };
    Utils.xPubToCopayerId = function (coin, xpub) {
        var chain = this.getChain(coin).toLowerCase();
        var str = chain == 'btc' || chain == 'vcl' ? xpub : chain + xpub;
        var hash = sjcl.hash.sha256.hash(str);
        return sjcl.codec.hex.fromBits(hash);
    };
    Utils.signRequestPubKey = function (requestPubKey, xPrivKey) {
        var priv = new Bitcore.HDPrivateKey(xPrivKey).deriveChild(constants_1.Constants.PATHS.REQUEST_KEY_AUTH).privateKey;
        return this.signMessage(requestPubKey, priv);
    };
    Utils.verifyRequestPubKey = function (requestPubKey, signature, xPubKey) {
        var pub = new Bitcore.HDPublicKey(xPubKey).deriveChild(constants_1.Constants.PATHS.REQUEST_KEY_AUTH).publicKey;
        return this.verifyMessage(requestPubKey, signature, pub.toString());
    };
    Utils.formatAmount = function (satoshis, unit, opts) {
        $.shouldBeNumber(satoshis);
        $.checkArgument(_.includes(_.keys(constants_1.Constants.UNITS), unit));
        var clipDecimals = function (number, decimals) {
            var str = number.toString();
            if (str.indexOf('e') >= 0) {
                str = number.toFixed(MAX_DECIMAL_ANY_COIN);
            }
            var x = str.split('.');
            var d = (x[1] || '0').substring(0, decimals);
            var ret = parseFloat(x[0] + '.' + d);
            return ret;
        };
        var addSeparators = function (nStr, thousands, decimal, minDecimals) {
            nStr = nStr.replace('.', decimal);
            var x = nStr.split(decimal);
            var x0 = x[0];
            var x1 = x[1];
            x1 = _.dropRightWhile(x1, function (n, i) {
                return n == '0' && i >= minDecimals;
            }).join('');
            var x2 = x.length > 1 ? decimal + x1 : '';
            x0 = x0.replace(/\B(?=(\d{3})+(?!\d))/g, thousands);
            return x0 + x2;
        };
        opts = opts || {};
        var u = constants_1.Constants.UNITS[unit];
        var precision = opts.fullPrecision ? 'full' : 'short';
        var amount = clipDecimals(satoshis / u.toSatoshis, u[precision].maxDecimals).toFixed(u[precision].maxDecimals);
        return addSeparators(amount, opts.thousandsSeparator || ',', opts.decimalSeparator || '.', u[precision].minDecimals);
    };
    Utils.buildTx = function (txp) {
        var coin = txp.coin || 'vcl';
        if (constants_1.Constants.UTXO_COINS.includes(coin)) {
            var bitcore = Bitcore_[coin];
            var t = new bitcore.Transaction();
            t.setAtomicSwap(txp.atomicswap);
            if (txp.version >= 4) {
                t.setVersion(2);
            }
            else {
                t.setVersion(1);
            }
            $.checkState(_.includes(_.values(constants_1.Constants.SCRIPT_TYPES), txp.addressType));
            switch (txp.addressType) {
                case constants_1.Constants.SCRIPT_TYPES.P2WSH:
                case constants_1.Constants.SCRIPT_TYPES.P2SH:
                    _.each(txp.inputs, function (i) {
                        t.from(i, i.publicKeys, txp.requiredSignatures);
                    });
                    break;
                case constants_1.Constants.SCRIPT_TYPES.P2WPKH:
                case constants_1.Constants.SCRIPT_TYPES.P2PKH:
                    t.from(txp.inputs);
                    break;
            }
            if (txp.toAddress && txp.amount && !txp.outputs) {
                t.to(txp.toAddress, txp.amount);
            }
            else if (txp.outputs) {
                _.each(txp.outputs, function (o) {
                    $.checkState(o.script || o.toAddress, 'Output should have either toAddress or script specified');
                    if (o.script) {
                        t.addOutput(new bitcore.Transaction.Output({
                            script: o.script,
                            satoshis: o.amount
                        }));
                    }
                    else {
                        t.to(o.toAddress, o.amount);
                    }
                });
            }
            t.fee(txp.fee);
            if (txp.changeAddress) {
                t.change(txp.changeAddress.address);
            }
            if (t.outputs.length > 1) {
                var outputOrder = _.reject(txp.outputOrder, function (order) {
                    return order >= t.outputs.length;
                });
                $.checkState(t.outputs.length == outputOrder.length);
                t.sortOutputs(function (outputs) {
                    return _.map(outputOrder, function (i) {
                        return outputs[i];
                    });
                });
            }
            var totalInputs = _.reduce(txp.inputs, function (memo, i) {
                return +i.satoshis + memo;
            }, 0);
            var totalOutputs = _.reduce(t.outputs, function (memo, o) {
                return +o.satoshis + memo;
            }, 0);
            $.checkState(totalInputs - totalOutputs >= 0);
            $.checkState(totalInputs - totalOutputs <= defaults_1.Defaults.MAX_TX_FEE);
            return t;
        }
        else {
            var data = txp.data, destinationTag = txp.destinationTag, outputs = txp.outputs, payProUrl = txp.payProUrl, tokenAddress = txp.tokenAddress;
            var recipients = outputs.map(function (output) {
                return {
                    amount: output.amount,
                    address: output.toAddress,
                    data: output.data,
                    gasLimit: output.gasLimit
                };
            });
            if (data) {
                recipients[0].data = data;
            }
            var unsignedTxs_1 = [];
            var isERC20 = tokenAddress && !payProUrl;
            var chain = isERC20 ? 'ERC20' : this.getChain(coin);
            for (var index = 0; index < recipients.length; index++) {
                var rawTx = crypto_wallet_core_1.Transactions.create(__assign(__assign(__assign({}, txp), recipients[index]), { tag: destinationTag ? Number(destinationTag) : undefined, chain: chain, nonce: Number(txp.nonce) + Number(index), recipients: [recipients[index]] }));
                unsignedTxs_1.push(rawTx);
            }
            return { uncheckedSerialize: function () { return unsignedTxs_1; } };
        }
    };
    Utils.isPrivateKey = function (privKey) {
        try {
            var privkey = new PrivateKey(privKey);
            return true;
        }
        catch (e) {
            return false;
        }
    };
    return Utils;
}());
exports.Utils = Utils;
//# sourceMappingURL=utils.js.map