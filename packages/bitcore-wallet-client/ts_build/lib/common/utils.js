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
exports.Utils = void 0;
const crypto_wallet_core_1 = require("crypto-wallet-core");
const _ = __importStar(require("lodash"));
const constants_1 = require("./constants");
const defaults_1 = require("./defaults");
const $ = require('preconditions').singleton();
const sjcl = require('sjcl');
const Stringify = require('json-stable-stringify');
const Bitcore_ = {
    btc: crypto_wallet_core_1.BitcoreLib,
    bch: crypto_wallet_core_1.BitcoreLibCash,
    eth: crypto_wallet_core_1.BitcoreLib,
    xrp: crypto_wallet_core_1.BitcoreLib,
    doge: crypto_wallet_core_1.BitcoreLibDoge,
    ltc: crypto_wallet_core_1.BitcoreLibLtc,
    vcl: crypto_wallet_core_1.BitcoreLibVcl
};
let SJCL = {};
const MAX_DECIMAL_ANY_COIN = 18;
class Utils {
    static getChain(coin) {
        let normalizedChain = coin.toUpperCase();
        if (constants_1.Constants.ERC20.includes(coin.toLowerCase()) ||
            !constants_1.Constants.COINS.includes(coin.toLowerCase())) {
            normalizedChain = 'ETH';
        }
        return normalizedChain;
    }
    static encryptMessage(message, encryptingKey) {
        var key = sjcl.codec.base64.toBits(encryptingKey);
        return sjcl.encrypt(key, message, _.defaults({
            ks: 128,
            iter: 1
        }, SJCL));
    }
    static decryptMessage(cyphertextJson, encryptingKey) {
        if (!cyphertextJson)
            return;
        if (!encryptingKey)
            throw new Error('No key');
        var key = sjcl.codec.base64.toBits(encryptingKey);
        return sjcl.decrypt(key, cyphertextJson);
    }
    static decryptMessageNoThrow(cyphertextJson, encryptingKey) {
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
    }
    static isJsonString(str) {
        var r;
        try {
            r = JSON.parse(str);
        }
        catch (e) {
            return false;
        }
        return r;
    }
    static hashMessage(text, coin) {
        $.checkArgument(text);
        coin = coin || 'vcl';
        var buf = Buffer.from(text);
        var ret = Bitcore_[coin].crypto.Hash.sha256sha256(buf);
        ret = new Bitcore_[coin].encoding.BufferReader(ret).readReverse();
        return ret;
    }
    static signMessage(message, privKey, coin) {
        $.checkArgument(message);
        coin = coin || 'vcl';
        var priv = new Bitcore_[coin].PrivateKey(privKey);
        const flattenedMessage = _.isArray(message) ? _.join(message) : message;
        var hash = this.hashMessage(flattenedMessage, coin);
        return Bitcore_[coin].crypto.ECDSA.sign(hash, priv, 'little').toString();
    }
    static verifyMessage(message, signature, pubKey, coin) {
        $.checkArgument(message);
        $.checkArgument(pubKey);
        coin = coin || 'vcl';
        if (!signature)
            return false;
        var pub = new Bitcore_[coin].PublicKey(pubKey);
        const flattenedMessage = _.isArray(message) ? _.join(message) : message;
        const hash = this.hashMessage(flattenedMessage, coin);
        try {
            var sig = new Bitcore_[coin].crypto.Signature.fromString(signature);
            return Bitcore_[coin].crypto.ECDSA.verify(hash, sig, pub, 'little');
        }
        catch (e) {
            return false;
        }
    }
    static privateKeyToAESKey(privKey, coin) {
        coin = coin || 'vcl';
        $.checkArgument(privKey && _.isString(privKey));
        $.checkArgument(Bitcore_[coin].PrivateKey.isValid(privKey), 'The private key received is invalid');
        var pk = Bitcore_[coin].PrivateKey.fromString(privKey);
        return Bitcore_[coin].crypto.Hash.sha256(pk.toBuffer())
            .slice(0, 16)
            .toString('base64');
    }
    static getCopayerHash(name, xPubKey, requestPubKey) {
        return [name, xPubKey, requestPubKey].join('|');
    }
    static getProposalHash(proposalHeader) {
        if (arguments.length > 1) {
            return this.getOldHash.apply(this, arguments);
        }
        return Stringify(proposalHeader);
    }
    static getOldHash(toAddress, amount, message, payProUrl) {
        return [toAddress, amount, message || '', payProUrl || ''].join('|');
    }
    static parseDerivationPath(path) {
        const pathIndex = /m\/([0-9]*)\/([0-9]*)/;
        const [_input, changeIndex, addressIndex] = path.match(pathIndex);
        const isChange = Number.parseInt(changeIndex) > 0;
        return { _input, addressIndex, isChange };
    }
    static deriveAddress(scriptType, publicKeyRing, path, m, network, coin, escrowInputs) {
        $.checkArgument(_.includes(_.values(constants_1.Constants.SCRIPT_TYPES), scriptType));
        coin = coin || 'vcl';
        const chain = this.getChain(coin).toLowerCase();
        var bitcore = Bitcore_[chain];
        var publicKeys = _.map(publicKeyRing, item => {
            var xpub = new bitcore.HDPublicKey(item.xPubKey);
            return xpub.deriveChild(path).publicKey;
        });
        var bitcoreAddress;
        switch (scriptType) {
            case constants_1.Constants.SCRIPT_TYPES.P2WSH:
                const nestedWitness = false;
                bitcoreAddress = bitcore.Address.createMultisig(publicKeys, m, network, nestedWitness, 'witnessscripthash');
                break;
            case constants_1.Constants.SCRIPT_TYPES.P2SH:
                if (escrowInputs) {
                    var xpub = new bitcore.HDPublicKey(publicKeyRing[0].xPubKey);
                    const inputPublicKeys = escrowInputs.map(input => xpub.deriveChild(input.path).publicKey);
                    bitcoreAddress = bitcore.Address.createEscrow(inputPublicKeys, publicKeys[0], network);
                    publicKeys = [publicKeys[0], ...inputPublicKeys];
                }
                else {
                    bitcoreAddress = bitcore.Address.createMultisig(publicKeys, m, network);
                }
                break;
            case constants_1.Constants.SCRIPT_TYPES.P2WPKH:
                bitcoreAddress = bitcore.Address.fromPublicKey(publicKeys[0], network, 'witnesspubkeyhash');
                break;
            case constants_1.Constants.SCRIPT_TYPES.P2PKH:
                $.checkState(_.isArray(publicKeys) && publicKeys.length == 1, 'publicKeys array undefined');
                if (constants_1.Constants.UTXO_COINS.includes(coin)) {
                    bitcoreAddress = bitcore.Address.fromPublicKey(publicKeys[0], network);
                }
                else {
                    const { addressIndex, isChange } = this.parseDerivationPath(path);
                    const [{ xPubKey }] = publicKeyRing;
                    bitcoreAddress = crypto_wallet_core_1.Deriver.deriveAddress(chain.toUpperCase(), network, xPubKey, addressIndex, isChange);
                }
                break;
        }
        return {
            address: bitcoreAddress.toString(true),
            path,
            publicKeys: _.invokeMap(publicKeys, 'toString')
        };
    }
    static xPubToCopayerId(coin, xpub) {
        const chain = this.getChain(coin).toLowerCase();
        var str = chain == 'btc' || chain == 'vcl' ? xpub : chain + xpub;
        var hash = sjcl.hash.sha256.hash(str);
        return sjcl.codec.hex.fromBits(hash);
    }
    static signRequestPubKey(requestPubKey, xPrivKey, coin) {
        coin = coin || 'vcl';
        var priv = new Bitcore_[coin].HDPrivateKey(xPrivKey).deriveChild(constants_1.Constants.PATHS.REQUEST_KEY_AUTH).privateKey;
        return this.signMessage(requestPubKey, priv, coin);
    }
    static verifyRequestPubKey(requestPubKey, signature, xPubKey, coin) {
        coin = coin || 'vcl';
        var pub = new Bitcore_[coin].HDPublicKey(xPubKey).deriveChild(constants_1.Constants.PATHS.REQUEST_KEY_AUTH).publicKey;
        return this.verifyMessage(requestPubKey, signature, pub.toString(), coin);
    }
    static formatAmount(satoshis, unit, opts) {
        $.shouldBeNumber(satoshis);
        var clipDecimals = (number, decimals) => {
            let str = number.toString();
            if (str.indexOf('e') >= 0) {
                str = number.toFixed(MAX_DECIMAL_ANY_COIN);
            }
            var x = str.split('.');
            var d = (x[1] || '0').substring(0, decimals);
            const ret = parseFloat(x[0] + '.' + d);
            return ret;
        };
        var addSeparators = (nStr, thousands, decimal, minDecimals) => {
            nStr = nStr.replace('.', decimal);
            var x = nStr.split(decimal);
            var x0 = x[0];
            var x1 = x[1];
            x1 = _.dropRightWhile(x1, (n, i) => {
                return n == '0' && i >= minDecimals;
            }).join('');
            var x2 = x.length > 1 ? decimal + x1 : '';
            x0 = x0.replace(/\B(?=(\d{3})+(?!\d))/g, thousands);
            return x0 + x2;
        };
        opts = opts || {};
        var u = constants_1.Constants.UNITS[unit];
        var precision = opts.fullPrecision ? 'full' : 'short';
        var decimals = opts.decimals ? opts.decimals[precision] : u[precision];
        var toSatoshis = opts.toSatoshis ? opts.toSatoshis : u.toSatoshis;
        var amount = clipDecimals(satoshis / toSatoshis, decimals.maxDecimals).toFixed(decimals.maxDecimals);
        return addSeparators(amount, opts.thousandsSeparator || ',', opts.decimalSeparator || '.', decimals.minDecimals);
    }
    static buildTx(txp) {
        var coin = txp.coin || 'vcl';
        if (constants_1.Constants.UTXO_COINS.includes(coin)) {
            var bitcore = Bitcore_[coin];
            var t = new bitcore.Transaction();
            t.setAtomicSwap(txp.atomicswap);
            if (txp.version >= 3) {
                t.setVersion(2);
            }
            else {
                t.setVersion(1);
            }
            if (txp.txExtends && txp.txExtends.version) {
                t.setVersion(txp.txExtends.version);
            }
            else if (txp.asset && txp.asset.version) {
                t.setVersion(txp.asset.version);
            }
            $.checkState(_.includes(_.values(constants_1.Constants.SCRIPT_TYPES), txp.addressType), 'Failed state: addressType not in SCRIPT_TYPES');
            switch (txp.addressType) {
                case constants_1.Constants.SCRIPT_TYPES.P2WSH:
                case constants_1.Constants.SCRIPT_TYPES.P2SH:
                    _.each(txp.inputs, i => {
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
                _.each(txp.outputs, o => {
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
            if (!txp.asset || !txp.asset.version) {
                t.fee(txp.fee);
                if (txp.instantAcceptanceEscrow && txp.escrowAddress) {
                    t.escrow(txp.escrowAddress.address, txp.instantAcceptanceEscrow + txp.fee);
                }
                if (txp.changeAddress) {
                    t.change(txp.changeAddress.address);
                }
                if (txp.enableRBF)
                    t.enableRBF();
                if (t.outputs.length > 1) {
                    var outputOrder = _.reject(txp.outputOrder, order => {
                        return order >= t.outputs.length;
                    });
                    $.checkState(t.outputs.length == outputOrder.length, 'Failed state: t.ouputs.length == outputOrder.length at buildTx()');
                    t.sortOutputs(outputs => {
                        return _.map(outputOrder, i => {
                            return outputs[i];
                        });
                    });
                }
            }
            var totalInputs = _.reduce(txp.inputs, (memo, i) => {
                return +i.satoshis + memo;
            }, 0);
            var totalOutputs = _.reduce(t.outputs, (memo, o) => {
                return +o.satoshis + memo;
            }, 0);
            $.checkState(totalInputs - totalOutputs >= 0, 'Failed state: totalInputs - totalOutputs >= 0 at buildTx');
            $.checkState(totalInputs - totalOutputs <= defaults_1.Defaults.MAX_TX_FEE(coin), 'Failed state: totalInputs - totalOutputs <= Defaults.MAX_TX_FEE(coin) at buildTx');
            if (txp.asset && txp.asset.version) {
                t.fee(totalInputs - totalOutputs);
            }
            return t;
        }
        else {
            const { data, destinationTag, outputs, payProUrl, tokenAddress, multisigContractAddress, isTokenSwap, tokenId } = txp;
            const recipients = outputs.map(output => {
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
            const unsignedTxs = [];
            const isERC20 = tokenAddress && !payProUrl && !isTokenSwap;
            const isERC721 = tokenAddress && tokenId;
            const isETHMULTISIG = multisigContractAddress;
            var chain;
            if (!txp.relay || !txp.relay.cmd) {
                chain = isETHMULTISIG
                    ? 'ETHMULTISIG'
                    : isERC721
                        ? 'ERC721'
                        : isERC20
                            ? 'ERC20'
                            : txp.chain
                                ? txp.chain.toUpperCase()
                                : this.getChain(coin);
                for (let index = 0; index < recipients.length; index++) {
                    const rawTx = crypto_wallet_core_1.Transactions.create(Object.assign(Object.assign(Object.assign({}, txp), recipients[index]), { tag: destinationTag ? Number(destinationTag) : undefined, chain, nonce: Number(txp.nonce) + Number(index), recipients: [recipients[index]] }));
                    unsignedTxs.push(rawTx);
                }
            }
            if (txp.coin == 'eth' && txp.relay.cmd == 1) {
                chain = 'RELAY';
                txp.chain = chain;
                for (let index = 0; index < recipients.length; index++) {
                    var rawTx = crypto_wallet_core_1.Transactions.get(Object.assign({}, txp)).createApprove(Object.assign(Object.assign(Object.assign({}, txp), recipients[index]), { tag: destinationTag ? Number(destinationTag) : undefined, chain, nonce: Number(txp.nonce) + Number(index), recipients: [recipients[index]] }));
                    unsignedTxs.push(rawTx);
                }
                txp.chain = 'ETH';
            }
            else if (txp.coin == 'eth' && txp.relay.cmd == 2) {
                chain = 'RELAY';
                txp.chain = chain;
                for (let index = 0; index < recipients.length; index++) {
                    var rawTx = crypto_wallet_core_1.Transactions.get(Object.assign({}, txp)).createFreezeBurnERC20(Object.assign(Object.assign(Object.assign({}, txp), recipients[index]), { tag: destinationTag ? Number(destinationTag) : undefined, chain, nonce: Number(txp.nonce) + Number(index), recipients: [recipients[index]] }));
                    unsignedTxs.push(rawTx);
                }
                txp.chain = 'ETH';
            }
            else if (txp.coin == 'eth' && txp.relay.cmd == 3) {
                chain = 'RELAY';
                txp.chain = chain;
                var rawTx = crypto_wallet_core_1.Transactions.get(Object.assign({}, txp)).createRelayTx(Object.assign(Object.assign({}, txp), { tag: destinationTag ? Number(destinationTag) : undefined, chain, nonce: Number(txp.nonce) }));
                unsignedTxs.push(rawTx);
                txp.chain = 'ETH';
            }
            else if (txp.coin == 'eth' && txp.relay.cmd == 4) {
                chain = 'RELAY';
                txp.chain = chain;
                var rawTx = crypto_wallet_core_1.Transactions.get(Object.assign({}, txp)).createRelayAssetTx(Object.assign(Object.assign({}, txp), { tag: destinationTag ? Number(destinationTag) : undefined, chain, nonce: Number(txp.nonce) }));
                unsignedTxs.push(rawTx);
                txp.chain = 'ETH';
            }
            else {
                throw new Error('relay cmd is invalid');
            }
            return { uncheckedSerialize: () => unsignedTxs };
        }
    }
    static isPrivateKey(privKey, coin) {
        coin = coin || 'vcl';
        try {
            var privkey = new Bitcore_[coin].PrivateKey(privKey);
            return true;
        }
        catch (e) {
            return false;
        }
    }
}
exports.Utils = Utils;
//# sourceMappingURL=utils.js.map