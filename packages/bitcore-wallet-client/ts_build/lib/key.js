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
exports.Key = void 0;
var $ = require('preconditions').singleton();
const crypto_wallet_core_1 = require("crypto-wallet-core");
const _ = __importStar(require("lodash"));
require("source-map-support/register");
const common_1 = require("./common");
const credentials_1 = require("./credentials");
const Bitcore_ = {
    btc: crypto_wallet_core_1.BitcoreLib,
    bch: crypto_wallet_core_1.BitcoreLibCash,
    eth: crypto_wallet_core_1.BitcoreLib,
    xrp: crypto_wallet_core_1.BitcoreLib,
    doge: crypto_wallet_core_1.BitcoreLibDoge,
    ltc: crypto_wallet_core_1.BitcoreLibLtc,
    vcl: crypto_wallet_core_1.BitcoreLibVcl
};
var Mnemonic = require('bitcore-mnemonic');
var sjcl = require('sjcl');
var log = require('./log');
const async = require('async');
const Uuid = require('uuid');
var Errors = require('./errors');
const wordsForLang = {
    en: Mnemonic.Words.ENGLISH,
    es: Mnemonic.Words.SPANISH,
    ja: Mnemonic.Words.JAPANESE,
    zh: Mnemonic.Words.CHINESE,
    fr: Mnemonic.Words.FRENCH,
    it: Mnemonic.Words.ITALIAN
};
const NETWORK = 'livenet';
class Key {
    constructor(opts = { seedType: 'new' }) {
        this.toObj = function () {
            const ret = {
                xPrivKey: this.xPrivKey,
                xPrivKeyEncrypted: this.xPrivKeyEncrypted,
                mnemonic: this.mnemonic,
                mnemonicEncrypted: this.mnemonicEncrypted,
                version: this.version,
                mnemonicHasPassphrase: this.mnemonicHasPassphrase,
                fingerPrint: this.fingerPrint,
                compliantDerivation: this.compliantDerivation,
                BIP45: this.BIP45,
                use0forBCH: this.use0forBCH,
                use44forMultisig: this.use44forMultisig,
                id: this.id
            };
            return _.clone(ret);
        };
        this.getPrivateKey = function (password, rootPath, path, coin) {
            var derived = {};
            coin = coin || 'vcl';
            var derived = this.derive(password, rootPath, coin);
            var xpriv = new Bitcore_[coin].HDPrivateKey(derived);
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
            var xPrivKey = new Bitcore_[coin].HDPrivateKey(derived);
            if (network == 'testnet') {
                var x = derived.toObject();
                x.network = 'testnet';
                delete x.xprivkey;
                delete x.checksum;
                x.privateKey = _.padStart(x.privateKey, 64, '0');
                xPrivKey = new Bitcore_[coin].HDPrivateKey(x);
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
            var xpriv = new Bitcore_[coin].HDPrivateKey(derived);
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
            let keys = {};
            let fingerPrintUpdated = false;
            if (this.isPrivKeyEncrypted()) {
                $.checkArgument(password, 'Private keys are encrypted, a password is needed');
                try {
                    keys.xPrivKey = sjcl.decrypt(password, this.xPrivKeyEncrypted);
                    if (!this.fingerPrint) {
                        let xpriv = new Bitcore_[this.coin].HDPrivateKey(keys.xPrivKey);
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
            keys.mnemonicHasPassphrase = this.mnemonicHasPassphrase || false;
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
            this.xPrivKey = null;
            this.mnemonic = null;
        };
        this.decrypt = function (password) {
            if (!this.xPrivKeyEncrypted)
                throw new Error('Private key is not encrypted');
            try {
                this.xPrivKey = sjcl.decrypt(password, this.xPrivKeyEncrypted);
                if (this.mnemonicEncrypted) {
                    this.mnemonic = sjcl.decrypt(password, this.mnemonicEncrypted);
                }
                this.xPrivKeyEncrypted = null;
                this.mnemonicEncrypted = null;
            }
            catch (ex) {
                log.error('error decrypting:', ex);
                throw new Error('Could not decrypt');
            }
        };
        this.derive = function (password, path, coin) {
            coin = coin || this.coin;
            $.checkArgument(path, 'no path at derive()');
            var xPrivKey = new Bitcore_[coin].HDPrivateKey(this.get(password).xPrivKey, NETWORK);
            var deriveFn = this.compliantDerivation
                ? _.bind(xPrivKey.deriveChild, xPrivKey)
                : _.bind(xPrivKey.deriveNonCompliantChild, xPrivKey);
            return deriveFn(path);
        };
        this._checkCoin = function (coin) {
            if (!_.includes(common_1.Constants.COINS, coin))
                throw new Error('Invalid coin');
        };
        this._checkNetwork = function (network) {
            if (!_.includes(['livenet', 'testnet'], network))
                throw new Error('Invalid network');
        };
        this.getBaseAddressDerivationPath = function (opts) {
            $.checkArgument(opts, 'Need to provide options');
            $.checkArgument(opts.n >= 1, 'n need to be >=1');
            let purpose = opts.n == 1 || this.use44forMultisig ? '44' : '48';
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
            else if (opts.coin == 'doge') {
                coinCode = '3';
            }
            else if (opts.coin == 'ltc') {
                coinCode = '2';
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
        this.createCredentials = function (password, opts) {
            opts = opts || {};
            if (password)
                $.shouldBeString(password, 'provide password');
            this._checkNetwork(opts.network);
            $.shouldBeNumber(opts.account, 'Invalid account');
            $.shouldBeNumber(opts.n, 'Invalid n');
            $.shouldBeUndefined(opts.useLegacyCoinType);
            $.shouldBeUndefined(opts.useLegacyPurpose);
            let path = this.getBaseAddressDerivationPath(opts);
            let xPrivKey = this.derive(password, path);
            let requestKey = common_1.Constants.PATHS.REQUEST_KEY;
            if (this.useforElectrum) {
                requestKey = common_1.Constants.PATHS.REQUEST_ELECTRUM_KEY;
                if (this.useSegwit) {
                    requestKey = common_1.Constants.PATHS.REQUEST_SEGWIT_ELECTRUM_KEY;
                }
            }
            let requestPrivKey = this.derive(password, requestKey).privateKey.toString();
            if (opts.network == 'testnet') {
                let x = xPrivKey.toObject();
                x.network = 'testnet';
                delete x.xprivkey;
                delete x.checksum;
                x.privateKey = _.padStart(x.privateKey, 64, '0');
                xPrivKey = new Bitcore_[this.coin].HDPrivateKey(x);
            }
            return credentials_1.Credentials.fromDerivedKey({
                xPubKey: xPrivKey.hdPublicKey.toString(),
                coin: opts.coin,
                network: opts.network,
                account: opts.account,
                n: opts.n,
                rootPath: path,
                keyId: this.id,
                requestPrivKey,
                addressType: opts.addressType,
                walletPrivKey: opts.walletPrivKey
            });
        };
        this.createAccess = function (password, opts) {
            opts = opts || {};
            $.shouldBeString(opts.path);
            var requestPrivKey = new Bitcore_[this.coin].PrivateKey(opts.requestPrivKey || null);
            var requestPubKey = requestPrivKey.toPublicKey().toString();
            var xPriv = this.derive(password, opts.path);
            var signature = common_1.Utils.signRequestPubKey(requestPubKey, xPriv, this.coin);
            requestPrivKey = requestPrivKey.toString();
            return {
                signature,
                requestPrivKey
            };
        };
        this.sign1 = function (rootPath, txp, password, cb) {
            $.shouldBeString(rootPath);
            if (this.isPrivKeyEncrypted() && !password) {
                return cb(new Errors.ENCRYPTED_PRIVATE_KEY());
            }
            var privs = [];
            var derived = {};
            var derived = this.derive(password, rootPath, txp.coin);
            var xpriv = new Bitcore_[txp.coin].HDPrivateKey(derived);
            _.each(txp.inputs, function (i) {
                $.checkState(i.path, 'Input derivation path not available (signing transaction)');
                if (!derived[i.path]) {
                    derived[i.path] = xpriv.deriveChild(i.path).privateKey;
                    privs.push(derived[i.path]);
                }
            });
            var signatures = _.map(privs, function (priv, i) {
                return txp.getSignatures(priv, undefined, txp.signingMethod);
            });
            signatures = _.map(_.sortBy(_.flatten(signatures), 'inputIndex'), function (s) {
                return s.signature.toDER(txp.signingMethod).toString('hex');
            });
            return signatures;
        };
        this.sign = function (rootPath, txp, password, cb) {
            $.shouldBeString(rootPath);
            if (this.isPrivKeyEncrypted() && !password) {
                return cb(new Errors.ENCRYPTED_PRIVATE_KEY());
            }
            var privs = [];
            var derived = {};
            var derived = this.derive(password, rootPath, txp.coin);
            var xpriv = new Bitcore_[txp.coin].HDPrivateKey(derived);
            var t = common_1.Utils.buildTx(txp);
            if (txp.atomicswap &&
                txp.atomicswap.isAtomicSwap &&
                txp.atomicswap.redeem != undefined) {
                t.inputs[0].output.setScript(txp.atomicswap.contract);
                if (!txp.atomicswap.redeem) {
                    t.lockUntilDate(txp.atomicswap.lockTime);
                }
                else {
                    t.nLockTime = txp.atomicswap.lockTime;
                }
            }
            if (txp.txExtends && txp.txExtends.version && txp.txExtends.outScripts) {
                for (var i = 0; i < t.outputs.length; i++) {
                    if (t.outputs[i]._satoshis == 0) {
                        t.outputs[i].setScript(txp.txExtends.outScripts);
                        break;
                    }
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
                let tx = t.uncheckedSerialize();
                tx = typeof tx === 'string' ? [tx] : tx;
                const chain = txp.chain
                    ? txp.chain.toUpperCase()
                    : common_1.Utils.getChain(txp.coin);
                const txArray = _.isArray(tx) ? tx : [tx];
                const isChange = false;
                const addressIndex = 0;
                const { privKey, pubKey } = crypto_wallet_core_1.Deriver.derivePrivateKey(chain, txp.network, derived, addressIndex, isChange);
                let signatures = [];
                for (const rawTx of txArray) {
                    const signed = crypto_wallet_core_1.Transactions.getSignature({
                        chain,
                        tx: rawTx,
                        key: { privKey, pubKey }
                    });
                    signatures.push(signed);
                }
                return signatures;
            }
        };
        this.signAtomicSwap = function (privKey, txp, cb) {
            var t = common_1.Utils.buildTx(txp);
            t.inputs[0].output.setScript(txp.contract);
            t.lockUntilDate(txp.lockTime);
            var privs = [];
            if (common_1.Constants.UTXO_COINS.includes(txp.coin)) {
                privs.push(new Bitcore_[txp.coin].PrivateKey(privKey));
                var signatures = _.map(privs, function (priv, i) {
                    return t.getSignatures(priv, undefined, txp.signingMethod);
                });
                signatures = _.map(_.sortBy(_.flatten(signatures), 'inputIndex'), function (s) {
                    return s.signature.toDER(txp.signingMethod).toString('hex');
                });
                return signatures;
            }
        };
        this.coin = opts.coin || 'vcl';
        this.version = 1;
        this.id = Uuid.v4();
        this.use0forBCH = opts.useLegacyCoinType;
        this.useforElectrum = false;
        this.useSegwit = false;
        this.useMulti = false;
        this.use44forMultisig = opts.useLegacyPurpose;
        this.compliantDerivation = !opts.nonCompliantDerivation;
        let x = opts.seedData;
        switch (opts.seedType) {
            case 'new':
                if (opts.language && !wordsForLang[opts.language])
                    throw new Error('Unsupported language');
                let m = new Mnemonic(wordsForLang[opts.language]);
                while (!Mnemonic.isValid(m.toString())) {
                    m = new Mnemonic(wordsForLang[opts.language]);
                }
                this.setFromMnemonic(m, opts);
                break;
            case 'mnemonic':
                $.checkArgument(x, 'Need to provide opts.seedData');
                $.checkArgument(_.isString(x), 'sourceData need to be a string');
                this.useMulti = opts.useMulti || false;
                var mm = new Mnemonic(x, '', this.useMulti);
                this.setFromMnemonic(mm, opts);
                this.useforElectrum = mm.useElectrum;
                break;
            case 'extendedPrivateKey':
                $.checkArgument(x, 'Need to provide opts.seedData');
                let xpriv;
                try {
                    xpriv = new Bitcore_[this.coin].HDPrivateKey(x);
                }
                catch (e) {
                    throw new Error('Invalid argument');
                }
                this.fingerPrint = xpriv.fingerPrint.toString('hex');
                if (opts.password) {
                    this.xPrivKeyEncrypted = sjcl.encrypt(opts.password, xpriv.toString(), opts);
                    if (!this.xPrivKeyEncrypted)
                        throw new Error('Could not encrypt');
                }
                else {
                    this.xPrivKey = xpriv.toString();
                }
                this.mnemonic = null;
                this.mnemonicHasPassphrase = null;
                break;
            case 'object':
                $.shouldBeObject(x, 'Need to provide an object at opts.seedData');
                $.shouldBeUndefined(opts.password, 'opts.password not allowed when source is object');
                if (this.version != x.version) {
                    throw new Error('Bad Key version');
                }
                this.xPrivKey = x.xPrivKey;
                this.xPrivKeyEncrypted = x.xPrivKeyEncrypted;
                this.mnemonic = x.mnemonic;
                this.mnemonicEncrypted = x.mnemonicEncrypted;
                this.mnemonicHasPassphrase = x.mnemonicHasPassphrase;
                this.version = x.version;
                this.fingerPrint = x.fingerPrint;
                this.compliantDerivation = x.compliantDerivation;
                this.BIP45 = x.BIP45;
                this.id = x.id;
                this.use0forBCH = x.use0forBCH;
                this.use44forMultisig = x.use44forMultisig;
                $.checkState(this.xPrivKey || this.xPrivKeyEncrypted, 'Failed state:  #xPrivKey || #xPrivKeyEncrypted at Key constructor');
                break;
            case 'objectV1':
                this.use0forBCH = false;
                this.use44forMultisig = false;
                this.compliantDerivation = true;
                this.id = Uuid.v4();
                if (!_.isUndefined(x.compliantDerivation))
                    this.compliantDerivation = x.compliantDerivation;
                if (!_.isUndefined(x.id))
                    this.id = x.id;
                this.xPrivKey = x.xPrivKey;
                this.xPrivKeyEncrypted = x.xPrivKeyEncrypted;
                this.mnemonic = x.mnemonic;
                this.mnemonicEncrypted = x.mnemonicEncrypted;
                this.mnemonicHasPassphrase = x.mnemonicHasPassphrase;
                this.version = x.version || 1;
                this.fingerPrint = x.fingerPrint;
                this.use44forMultisig = x.n > 1 ? true : false;
                this.use0forBCH = x.use145forBCH
                    ? false
                    : x.coin == 'bch'
                        ? true
                        : false;
                this.BIP45 = x.derivationStrategy == 'BIP45';
                break;
            default:
                throw new Error('Unknown seed source: ' + opts.seedType);
        }
    }
    static match(a, b) {
        return a.id == b.id || a.fingerPrint == b.fingerPrint;
    }
    setFromMnemonic(m, opts) {
        const xpriv = m.toHDPrivateKey(opts.passphrase, NETWORK);
        this.fingerPrint = xpriv.fingerPrint.toString('hex');
        if (opts.password) {
            this.xPrivKeyEncrypted = sjcl.encrypt(opts.password, xpriv.toString(), opts.sjclOpts);
            if (!this.xPrivKeyEncrypted)
                throw new Error('Could not encrypt');
            this.mnemonicEncrypted = sjcl.encrypt(opts.password, m.phrase, opts.sjclOpts);
            if (!this.mnemonicEncrypted)
                throw new Error('Could not encrypt');
        }
        else {
            this.xPrivKey = xpriv.toString();
            this.mnemonic = m.phrase;
            this.mnemonicHasPassphrase = !!opts.passphrase;
        }
    }
}
exports.Key = Key;
//# sourceMappingURL=key.js.map