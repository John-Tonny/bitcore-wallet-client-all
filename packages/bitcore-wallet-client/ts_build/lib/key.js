'use strict';
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
var $ = require('preconditions').singleton();
var _ = __importStar(require("lodash"));
var common_1 = require("./common");
var credentials_1 = require("./credentials");
var crypto_wallet_core_1 = require("crypto-wallet-core");
var Bitcore = crypto_wallet_core_1.VircleLib;
var Mnemonic = require('bitcore-mnemonic');
var sjcl = require('sjcl');
var log = require('./log');
var async = require('async');
var Uuid = require('uuid');
var Errors = require('./errors');
var wordsForLang = {
    en: Mnemonic.Words.ENGLISH,
    es: Mnemonic.Words.SPANISH,
    ja: Mnemonic.Words.JAPANESE,
    zh: Mnemonic.Words.CHINESE,
    fr: Mnemonic.Words.FRENCH,
    it: Mnemonic.Words.ITALIAN
};
var NETWORK = 'livenet';
var Key = (function () {
    function Key() {
        this.toObj = function () {
            var self = this;
            var x = {};
            _.each(Key.FIELDS, function (k) {
                x[k] = self[k];
            });
            return x;
        };
        this.getPrivateKey = function (password, rootPath, path, coin) {
            var derived = {};
            coin = coin || 'vcl';
            var derived = this.derive(password, rootPath, coin);
            var xpriv = new Bitcore.HDPrivateKey(derived);
            if (!derived[path]) {
                return xpriv.deriveChild(path).privateKey;
            }
            return null;
        };
        this.getPrivateKeyofWif = function (password, rootPath, path, coin, network) {
            var derived = {};
            coin = coin || 'vcl';
            network = network || NETWORK;
            var derived = this.derive(password, rootPath, coin);
            var xPrivKey = new Bitcore.HDPrivateKey(derived);
            if (network == 'testnet') {
                var x = derived.toObject();
                x.network = 'testnet';
                delete x.xprivkey;
                delete x.checksum;
                x.privateKey = _.padStart(x.privateKey, 64, '0');
                xPrivKey = new Bitcore.HDPrivateKey(x);
            }
            if (!derived[path]) {
                return xPrivKey.deriveChild(path).privateKey.toWIF();
            }
            return null;
        };
        this.isValidAddress = function (password, rootPath, coin, queryAddress, start, stop) {
            var privs = [];
            var derived = {};
            coin = coin || 'vcl';
            var derived = this.derive(password, rootPath, coin);
            var xpriv = new Bitcore.HDPrivateKey(derived);
            start = start || 0;
            stop = stop || start + 100;
            var privKey;
            for (var i = start; i < stop; i++) {
                var path = 'm/0/' + i.toString();
                if (!derived[path]) {
                    privKey = xpriv.deriveChild(path).privateKey;
                    var address = privKey.publicKey.toAddress().toString();
                    if (address === queryAddress) {
                        return true;
                    }
                }
            }
            return false;
        };
        this.isPrivKeyEncrypted = function () {
            return !!this.xPrivKeyEncrypted && !this.xPrivKey;
        };
        this.checkPassword = function (password) {
            if (this.isPrivKeyEncrypted()) {
                try {
                    sjcl.decrypt(password, this.xPrivKeyEncrypted);
                }
                catch (ex) {
                    return false;
                }
                return true;
            }
            return null;
        };
        this.get = function (password) {
            var keys = {};
            var fingerPrintUpdated = false;
            if (this.isPrivKeyEncrypted()) {
                $.checkArgument(password, 'Private keys are encrypted, a password is needed');
                try {
                    keys.xPrivKey = sjcl.decrypt(password, this.xPrivKeyEncrypted);
                    if (!this.fingerPrint) {
                        var xpriv = new Bitcore.HDPrivateKey(keys.xPrivKey);
                        this.fingerPrint = xpriv.fingerPrint.toString('hex');
                        fingerPrintUpdated = true;
                    }
                    if (this.mnemonicEncrypted) {
                        keys.mnemonic = sjcl.decrypt(password, this.mnemonicEncrypted);
                    }
                }
                catch (ex) {
                    throw new Error('Could not decrypt');
                }
            }
            else {
                keys.xPrivKey = this.xPrivKey;
                keys.mnemonic = this.mnemonic;
                if (fingerPrintUpdated) {
                    keys.fingerPrintUpdated = true;
                }
            }
            return keys;
        };
        this.encrypt = function (password, opts) {
            if (this.xPrivKeyEncrypted)
                throw new Error('Private key already encrypted');
            if (!this.xPrivKey)
                throw new Error('No private key to encrypt');
            this.xPrivKeyEncrypted = sjcl.encrypt(password, this.xPrivKey, opts);
            if (!this.xPrivKeyEncrypted)
                throw new Error('Could not encrypt');
            if (this.mnemonic)
                this.mnemonicEncrypted = sjcl.encrypt(password, this.mnemonic, opts);
            delete this.xPrivKey;
            delete this.mnemonic;
        };
        this.decrypt = function (password) {
            if (!this.xPrivKeyEncrypted)
                throw new Error('Private key is not encrypted');
            try {
                this.xPrivKey = sjcl.decrypt(password, this.xPrivKeyEncrypted);
                if (this.mnemonicEncrypted) {
                    this.mnemonic = sjcl.decrypt(password, this.mnemonicEncrypted);
                }
                delete this.xPrivKeyEncrypted;
                delete this.mnemonicEncrypted;
            }
            catch (ex) {
                log.error('error decrypting:', ex);
                throw new Error('Could not decrypt');
            }
        };
        this.derive = function (password, path) {
            $.checkArgument(path, 'no path at derive()');
            var xPrivKey = new Bitcore.HDPrivateKey(this.get(password).xPrivKey, NETWORK);
            var deriveFn = this.compliantDerivation
                ? _.bind(xPrivKey.deriveChild, xPrivKey)
                : _.bind(xPrivKey.deriveNonCompliantChild, xPrivKey);
            return deriveFn(path);
        };
        this.createCredentials = function (password, opts) {
            opts = opts || {};
            if (password)
                $.shouldBeString(password, 'provide password');
            this._checkCoin(opts.coin);
            this._checkNetwork(opts.network);
            $.shouldBeNumber(opts.account, 'Invalid account');
            $.shouldBeNumber(opts.n, 'Invalid n');
            $.shouldBeUndefined(opts.useLegacyCoinType);
            $.shouldBeUndefined(opts.useLegacyPurpose);
            var path = this.getBaseAddressDerivationPath(opts);
            var xPrivKey = this.derive(password, path);
            var requestKey = common_1.Constants.PATHS.REQUEST_KEY;
            if (this.useforElectrum) {
                requestKey = common_1.Constants.PATHS.REQUEST_ELECTRUM_KEY;
                if (this.useSegwit) {
                    requestKey = common_1.Constants.PATHS.REQUEST_SEGWIT_ELECTRUM_KEY;
                }
            }
            var requestPrivKey = this.derive(password, requestKey).privateKey.toString();
            if (opts.network == 'testnet') {
                var x = xPrivKey.toObject();
                x.network = 'testnet';
                delete x.xprivkey;
                delete x.checksum;
                x.privateKey = _.padStart(x.privateKey, 64, '0');
                xPrivKey = new Bitcore.HDPrivateKey(x);
            }
            return credentials_1.Credentials.fromDerivedKey({
                xPubKey: xPrivKey.hdPublicKey.toString(),
                coin: opts.coin,
                network: opts.network,
                account: opts.account,
                n: opts.n,
                rootPath: path,
                keyId: this.id,
                requestPrivKey: requestPrivKey,
                addressType: opts.addressType,
                walletPrivKey: opts.walletPrivKey
            });
        };
        this.createAccess = function (password, opts) {
            opts = opts || {};
            $.shouldBeString(opts.path);
            var requestPrivKey = new Bitcore.PrivateKey(opts.requestPrivKey || null);
            var requestPubKey = requestPrivKey.toPublicKey().toString();
            var xPriv = this.derive(password, opts.path);
            var signature = common_1.Utils.signRequestPubKey(requestPubKey, xPriv);
            requestPrivKey = requestPrivKey.toString();
            return {
                signature: signature,
                requestPrivKey: requestPrivKey
            };
        };
        this.sign = function (rootPath, txp, password, cb) {
            $.shouldBeString(rootPath);
            if (this.isPrivKeyEncrypted() && !password) {
                return cb(new Errors.ENCRYPTED_PRIVATE_KEY());
            }
            var privs = [];
            var derived = {};
            var derived = this.derive(password, rootPath);
            var xpriv = new Bitcore.HDPrivateKey(derived);
            var t = common_1.Utils.buildTx(txp);
            if (txp.atomicswap && txp.atomicswap.isAtomicSwap && txp.atomicswap.redeem != undefined) {
                t.inputs[0].output.setScript(txp.atomicswap.contract);
                if (!txp.atomicswap.redeem) {
                    t.lockUntilDate(txp.atomicswap.lockTime);
                }
                else {
                    t.nLockTime = txp.atomicswap.lockTime;
                }
            }
            if (common_1.Constants.UTXO_COINS.includes(txp.coin)) {
                _.each(txp.inputs, function (i) {
                    $.checkState(i.path, 'Input derivation path not available (signing transaction)');
                    if (!derived[i.path]) {
                        derived[i.path] = xpriv.deriveChild(i.path).privateKey;
                        privs.push(derived[i.path]);
                    }
                });
                var signatures = _.map(privs, function (priv, i) {
                    return t.getSignatures(priv, undefined, txp.signingMethod);
                });
                signatures = _.map(_.sortBy(_.flatten(signatures), 'inputIndex'), function (s) {
                    return s.signature.toDER(txp.signingMethod).toString('hex');
                });
                return signatures;
            }
            else {
                var tx = t.uncheckedSerialize();
                tx = typeof tx === 'string' ? [tx] : tx;
                var chain = common_1.Utils.getChain(txp.coin);
                var txArray = _.isArray(tx) ? tx : [tx];
                var isChange = false;
                var addressIndex = 0;
                var _a = crypto_wallet_core_1.Deriver.derivePrivateKey(chain, txp.network, derived, addressIndex, isChange), privKey = _a.privKey, pubKey = _a.pubKey;
                var signatures_1 = [];
                for (var _i = 0, txArray_1 = txArray; _i < txArray_1.length; _i++) {
                    var rawTx = txArray_1[_i];
                    var signed = crypto_wallet_core_1.Transactions.getSignature({
                        chain: chain,
                        tx: rawTx,
                        key: { privKey: privKey, pubKey: pubKey }
                    });
                    signatures_1.push(signed);
                }
                return signatures_1;
            }
        };
        this.signAtomicSwap = function (privKey, txp, cb) {
            var t = common_1.Utils.buildTx(txp);
            t.inputs[0].output.setScript(txp.contract);
            t.lockUntilDate(txp.lockTime);
            var privs = [];
            if (common_1.Constants.UTXO_COINS.includes(txp.coin)) {
                privs.push(new Bitcore.PrivateKey(privKey));
                var signatures = _.map(privs, function (priv, i) {
                    return t.getSignatures(priv, undefined, txp.signingMethod);
                });
                signatures = _.map(_.sortBy(_.flatten(signatures), 'inputIndex'), function (s) {
                    return s.signature.toDER(txp.signingMethod).toString('hex');
                });
                return signatures;
            }
        };
        this.version = 1;
        this.use0forBCH = false;
        this.useforElectrum = false;
        this.useSegwit = false;
        this.useMulti = false;
        this.use44forMultisig = false;
        this.compliantDerivation = true;
        this.id = Uuid.v4();
    }
    Key.match = function (a, b) {
        return a.id == b.id;
    };
    Key.prototype._checkCoin = function (coin) {
        if (!_.includes(common_1.Constants.COINS, coin))
            throw new Error('Invalid coin');
    };
    Key.prototype._checkNetwork = function (network) {
        if (!_.includes(['livenet', 'testnet'], network))
            throw new Error('Invalid network');
    };
    Key.prototype.getBaseAddressDerivationPath = function (opts) {
        $.checkArgument(opts, 'Need to provide options');
        $.checkArgument(opts.n >= 1, 'n need to be >=1');
        var purpose = opts.n == 1 || this.use44forMultisig ? '44' : '48';
        var coinCode = '0';
        if (opts.network == 'testnet' && common_1.Constants.UTXO_COINS.includes(opts.coin)) {
            coinCode = '1';
        }
        else if (opts.coin == 'bch') {
            if (this.use0forBCH) {
                coinCode = '0';
            }
            else {
                coinCode = '145';
            }
        }
        else if (opts.coin == 'btc') {
            coinCode = '0';
        }
        else if (opts.coin == 'eth') {
            coinCode = '60';
        }
        else if (opts.coin == 'vcl') {
            coinCode = '57';
        }
        else if (opts.coin == 'xrp') {
            coinCode = '144';
        }
        else {
            throw new Error('unknown coin: ' + opts.coin);
        }
        if (this.useforElectrum) {
            if (this.useSegwit) {
                if (opts.n == 1) {
                    return "m/0'";
                }
                return "m/1'";
            }
            return 'm';
        }
        return 'm/' + purpose + "'/" + coinCode + "'/" + opts.account + "'";
    };
    Key.FIELDS = [
        'xPrivKey',
        'xPrivKeyEncrypted',
        'mnemonic',
        'mnemonicEncrypted',
        'mnemonicHasPassphrase',
        'fingerPrint',
        'compliantDerivation',
        'BIP45',
        'use0forBCH',
        'useforElectrum',
        'useSegwit',
        'useMulti',
        'use44forMultisig',
        'version',
        'id'
    ];
    Key.create = function (opts) {
        opts = opts || {};
        if (opts.language && !wordsForLang[opts.language])
            throw new Error('Unsupported language');
        var m = new Mnemonic(wordsForLang[opts.language]);
        while (!Mnemonic.isValid(m.toString())) {
            m = new Mnemonic(wordsForLang[opts.language]);
        }
        var x = new Key();
        var xpriv = m.toHDPrivateKey(opts.passphrase, NETWORK);
        x.xPrivKey = xpriv.toString();
        x.fingerPrint = xpriv.fingerPrint.toString('hex');
        x.mnemonic = m.phrase;
        x.mnemonicHasPassphrase = !!opts.passphrase;
        x.use0forBCH = opts.useLegacyCoinType;
        x.useforElectrum = opts.useLegacyElectrumCoinType;
        x.useSegwit = opts.userSegwit;
        x.useMulti = opts.useMulti;
        x.use44forMultisig = opts.useLegacyPurpose;
        x.compliantDerivation = !opts.nonCompliantDerivation;
        return x;
    };
    Key.fromMnemonic = function (words, opts) {
        $.checkArgument(words);
        if (opts)
            $.shouldBeObject(opts);
        opts = opts || {};
        var m = new Mnemonic(words, null, opts.useMulti);
        var x = new Key();
        var xpriv = m.toHDPrivateKey(opts.passphrase, NETWORK, opts.useMulti);
        x.xPrivKey = xpriv.toString();
        x.fingerPrint = xpriv.fingerPrint.toString('hex');
        x.mnemonic = words;
        x.mnemonicHasPassphrase = !!opts.passphrase;
        x.use0forBCH = opts.useLegacyCoinType;
        x.useforElectrum = m.useElectrum;
        x.useSegwit = m.useSegwit;
        x.useMulti = opts.useMulti;
        x.use44forMultisig = opts.useLegacyPurpose;
        x.compliantDerivation = !opts.nonCompliantDerivation;
        return x;
    };
    Key.fromExtendedPrivateKey = function (xPriv, opts) {
        $.checkArgument(xPriv);
        opts = opts || {};
        var xpriv;
        try {
            xpriv = new Bitcore.HDPrivateKey(xPriv);
        }
        catch (e) {
            throw new Error('Invalid argument');
        }
        var x = new Key();
        x.xPrivKey = xpriv.toString();
        x.fingerPrint = xpriv.fingerPrint.toString('hex');
        x.mnemonic = null;
        x.mnemonicHasPassphrase = null;
        x.use44forMultisig = opts.useLegacyPurpose;
        x.use0forBCH = opts.useLegacyCoinType;
        x.useforElectrum = opts.useLegacyElectrumCoinType;
        x.useSegwit = opts.useNativeSegwit;
        x.compliantDerivation = !opts.nonCompliantDerivation;
        return x;
    };
    Key.fromObj = function (obj) {
        $.shouldBeObject(obj);
        var x = new Key();
        if (obj.version != x.version) {
            throw new Error('Bad Key version');
        }
        _.each(Key.FIELDS, function (k) {
            x[k] = obj[k];
        });
        $.checkState(x.xPrivKey || x.xPrivKeyEncrypted, 'invalid input');
        return x;
    };
    return Key;
}());
exports.Key = Key;
//# sourceMappingURL=key.js.map