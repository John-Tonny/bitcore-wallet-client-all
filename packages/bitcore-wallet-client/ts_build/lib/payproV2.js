'use strict';
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
var superagent = require('superagent');
var query = require('querystring');
var url = require('url');
var Errors = require('./errors');
var dfltTrustedKeys = require('../util/JsonPaymentProtocolKeys.js');
var Bitcore = require('crypto-wallet-core').VircleLib;
var _ = require('lodash');
var sha256 = Bitcore.crypto.Hash.sha256;
var BN = Bitcore.crypto.BN;
var Bitcore_ = {
    vcl: require('crypto-wallet-core').VircleLib
};
var MAX_FEE_PER_KB = {
    btc: 10000 * 1000,
    bch: 10000 * 1000,
    eth: 50000000000,
    vcl: 10000 * 1000,
    xrp: 50000000000
};
var NetworkMap;
(function (NetworkMap) {
    NetworkMap["main"] = "livenet";
    NetworkMap["test"] = "testnet";
    NetworkMap["regtest"] = "testnet";
})(NetworkMap = exports.NetworkMap || (exports.NetworkMap = {}));
var PayProV2 = (function () {
    function PayProV2(requestOptions, trustedKeys) {
        if (requestOptions === void 0) { requestOptions = {}; }
        if (trustedKeys === void 0) { trustedKeys = dfltTrustedKeys; }
        PayProV2.options = Object.assign({}, { agent: false }, requestOptions);
        PayProV2.trustedKeys = trustedKeys;
        if (!PayProV2.trustedKeys || !Object.keys(PayProV2.trustedKeys).length) {
            throw new Error('Invalid constructor, no trusted keys added to agent');
        }
    }
    PayProV2._asyncRequest = function (options) {
        return __awaiter(this, void 0, void 0, function () {
            var _this = this;
            return __generator(this, function (_a) {
                return [2, new Promise(function (resolve, reject) {
                        var requestOptions = Object.assign({}, PayProV2.options, options);
                        requestOptions.headers = Object.assign({}, PayProV2.options.headers, options.headers);
                        var r = _this.request[requestOptions.method](requestOptions.url);
                        _.each(requestOptions.headers, function (v, k) {
                            if (v)
                                r.set(k, v);
                        });
                        r.agent(requestOptions.agent);
                        if (requestOptions.args) {
                            if (requestOptions.method == 'post' || requestOptions.method == 'put') {
                                r.send(requestOptions.args);
                            }
                            else {
                                r.query(requestOptions.args);
                            }
                        }
                        r.end(function (err, res) {
                            if (err) {
                                if (res && res.statusCode !== 200) {
                                    if ((res.statusCode == 400 || res.statusCode == 422) && res.body && res.body.msg) {
                                        return reject(_this.getError(res.body.msg));
                                    }
                                    else if (res.statusCode == 404) {
                                        return reject(new Errors.INVOICE_NOT_AVAILABLE());
                                    }
                                    else if (res.statusCode == 504) {
                                        return reject(new Errors.REQUEST_TIMEOUT());
                                    }
                                    else if (res.statusCode == 500 && res.body && res.body.msg) {
                                        return reject(new Error(res.body.msg));
                                    }
                                    else {
                                        return reject(new Errors.INVALID_REQUEST());
                                    }
                                }
                                return reject(err);
                            }
                            return resolve({
                                rawBody: res.text,
                                headers: res.headers
                            });
                        });
                    })];
            });
        });
    };
    PayProV2.getError = function (errMsg) {
        switch (true) {
            case errMsg.includes('Invoice no longer accepting payments'):
                return new Errors.INVOICE_EXPIRED();
            case errMsg.includes('We were unable to parse your payment.'):
                return new Errors.UNABLE_TO_PARSE_PAYMENT();
            case errMsg.includes('Request must include exactly one'):
                return new Errors.NO_TRASACTION();
            case errMsg.includes('Your transaction was an in an invalid format'):
                return new Errors.INVALID_TX_FORMAT();
            case errMsg.includes('We were unable to parse the transaction you sent'):
                return new Errors.UNABLE_TO_PARSE_TX();
            case errMsg.includes('The transaction you sent does not have any output to the bitcoin address on the invoice'):
                return new Errors.WRONG_ADDRESS();
            case errMsg.includes('The amount on the transaction (X BTC) does'):
                return new Errors.WRONG_AMOUNT();
            case errMsg.includes('Transaction fee (X sat/kb) is below'):
                return new Errors.NOT_ENOUGH_FEE();
            case errMsg.includes('This invoice is priced in BTC, not BCH.'):
                return new Errors.BTC_NOT_BCH();
            case errMsg.includes('	One or more input transactions for your transaction were not found on the blockchain.'):
                return new Errors.INPUT_NOT_FOUND();
            case errMsg.includes('The PayPro request has timed out. Please connect to the internet or try again later.'):
                return new Errors.REQUEST_TIMEOUT();
            case errMsg.includes('One or more input transactions for your transactions are not yet confirmed in at least one block.'):
                return new Errors.UNCONFIRMED_INPUTS_NOT_ACCEPTED();
            default:
                return new Error(errMsg);
        }
    };
    PayProV2.getPaymentOptions = function (_a) {
        var paymentUrl = _a.paymentUrl, _b = _a.unsafeBypassValidation, unsafeBypassValidation = _b === void 0 ? false : _b;
        return __awaiter(this, void 0, void 0, function () {
            var paymentUrlObject, uriQuery, _c, rawBody, headers;
            return __generator(this, function (_d) {
                switch (_d.label) {
                    case 0:
                        paymentUrlObject = url.parse(paymentUrl);
                        if (paymentUrlObject.protocol !== 'http:' && paymentUrlObject.protocol !== 'https:') {
                            uriQuery = query.decode(paymentUrlObject.query);
                            if (!uriQuery.r) {
                                throw new Error('Invalid payment protocol url');
                            }
                            else {
                                paymentUrl = uriQuery.r;
                            }
                        }
                        return [4, PayProV2._asyncRequest({
                                method: 'get',
                                url: paymentUrl,
                                headers: {
                                    Accept: 'application/payment-options',
                                    'x-paypro-version': 2,
                                    Connection: 'Keep-Alive',
                                    'Keep-Alive': 'timeout=30, max=10'
                                }
                            })];
                    case 1:
                        _c = _d.sent(), rawBody = _c.rawBody, headers = _c.headers;
                        return [4, this.verifyResponse(paymentUrl, rawBody, headers, unsafeBypassValidation)];
                    case 2: return [2, _d.sent()];
                }
            });
        });
    };
    PayProV2.selectPaymentOption = function (_a) {
        var paymentUrl = _a.paymentUrl, chain = _a.chain, currency = _a.currency, _b = _a.unsafeBypassValidation, unsafeBypassValidation = _b === void 0 ? false : _b;
        return __awaiter(this, void 0, void 0, function () {
            var _c, rawBody, headers;
            return __generator(this, function (_d) {
                switch (_d.label) {
                    case 0: return [4, PayProV2._asyncRequest({
                            url: paymentUrl,
                            method: 'post',
                            headers: {
                                'Content-Type': 'application/payment-request',
                                'x-paypro-version': 2,
                                Connection: 'Keep-Alive',
                                'Keep-Alive': 'timeout=30, max=10'
                            },
                            args: JSON.stringify({
                                chain: chain,
                                currency: currency
                            })
                        })];
                    case 1:
                        _c = _d.sent(), rawBody = _c.rawBody, headers = _c.headers;
                        return [4, PayProV2.verifyResponse(paymentUrl, rawBody, headers, unsafeBypassValidation)];
                    case 2: return [2, _d.sent()];
                }
            });
        });
    };
    PayProV2.verifyUnsignedPayment = function (_a) {
        var paymentUrl = _a.paymentUrl, chain = _a.chain, currency = _a.currency, unsignedTransactions = _a.unsignedTransactions, _b = _a.unsafeBypassValidation, unsafeBypassValidation = _b === void 0 ? false : _b;
        return __awaiter(this, void 0, void 0, function () {
            var _c, rawBody, headers;
            return __generator(this, function (_d) {
                switch (_d.label) {
                    case 0: return [4, PayProV2._asyncRequest({
                            url: paymentUrl,
                            method: 'post',
                            headers: {
                                'Content-Type': 'application/payment-verification',
                                'x-paypro-version': 2,
                                Connection: 'Keep-Alive',
                                'Keep-Alive': 'timeout=30, max=10'
                            },
                            args: JSON.stringify({
                                chain: chain,
                                currency: currency,
                                transactions: unsignedTransactions
                            })
                        })];
                    case 1:
                        _c = _d.sent(), rawBody = _c.rawBody, headers = _c.headers;
                        return [4, this.verifyResponse(paymentUrl, rawBody, headers, unsafeBypassValidation)];
                    case 2: return [2, _d.sent()];
                }
            });
        });
    };
    PayProV2.sendSignedPayment = function (_a) {
        var paymentUrl = _a.paymentUrl, chain = _a.chain, currency = _a.currency, signedTransactions = _a.signedTransactions, _b = _a.unsafeBypassValidation, unsafeBypassValidation = _b === void 0 ? false : _b, bpPartner = _a.bpPartner;
        return __awaiter(this, void 0, void 0, function () {
            var _c, rawBody, headers;
            return __generator(this, function (_d) {
                switch (_d.label) {
                    case 0: return [4, this._asyncRequest({
                            url: paymentUrl,
                            method: 'post',
                            headers: {
                                'Content-Type': 'application/payment',
                                'x-paypro-version': 2,
                                BP_PARTNER: bpPartner.bp_partner,
                                BP_PARTNER_VERSION: bpPartner.bp_partner_version,
                                Connection: 'Keep-Alive',
                                'Keep-Alive': 'timeout=30, max=10'
                            },
                            args: JSON.stringify({
                                chain: chain,
                                currency: currency,
                                transactions: signedTransactions
                            })
                        })];
                    case 1:
                        _c = _d.sent(), rawBody = _c.rawBody, headers = _c.headers;
                        return [4, this.verifyResponse(paymentUrl, rawBody, headers, unsafeBypassValidation)];
                    case 2: return [2, _d.sent()];
                }
            });
        });
    };
    PayProV2.verifyResponse = function (requestUrl, rawBody, headers, unsafeBypassValidation) {
        return __awaiter(this, void 0, void 0, function () {
            var responseData, payProDetails, hash, signature, signatureType, identity, host, keyData, actualHash, hashbuf, sigbuf, s_r, s_s, pub, sig, valid;
            return __generator(this, function (_a) {
                if (!requestUrl) {
                    throw new Error('Parameter requestUrl is required');
                }
                if (!rawBody) {
                    throw new Error('Parameter rawBody is required');
                }
                if (!headers) {
                    throw new Error('Parameter headers is required');
                }
                try {
                    responseData = JSON.parse(rawBody);
                }
                catch (e) {
                    throw new Error('Invalid JSON in response body');
                }
                try {
                    payProDetails = this.processResponse(responseData);
                }
                catch (e) {
                    throw e;
                }
                if (unsafeBypassValidation) {
                    return [2, payProDetails];
                }
                hash = headers.digest.split('=')[1];
                signature = headers.signature;
                signatureType = headers['x-signature-type'];
                identity = headers['x-identity'];
                try {
                    host = url.parse(requestUrl).hostname;
                }
                catch (e) { }
                if (!host) {
                    throw new Error('Invalid requestUrl');
                }
                if (!signatureType) {
                    throw new Error('Response missing x-signature-type header');
                }
                if (typeof signatureType !== 'string') {
                    throw new Error('Invalid x-signature-type header');
                }
                if (signatureType !== 'ecc') {
                    throw new Error("Unknown signature type " + signatureType);
                }
                if (!signature) {
                    throw new Error('Response missing signature header');
                }
                if (typeof signature !== 'string') {
                    throw new Error('Invalid signature header');
                }
                if (!identity) {
                    throw new Error('Response missing x-identity header');
                }
                if (typeof identity !== 'string') {
                    throw new Error('Invalid identity header');
                }
                if (!PayProV2.trustedKeys[identity]) {
                    throw new Error("Response signed by unknown key (" + identity + "), unable to validate");
                }
                keyData = PayProV2.trustedKeys[identity];
                actualHash = sha256(Buffer.from(rawBody, 'utf8')).toString('hex');
                if (hash !== actualHash) {
                    throw new Error("Response body hash does not match digest header. Actual: " + actualHash + " Expected: " + hash);
                }
                if (!keyData.domains.includes(host)) {
                    throw new Error("The key on the response (" + identity + ") is not trusted for domain " + host);
                }
                hashbuf = Buffer.from(hash, 'hex');
                sigbuf = Buffer.from(signature, 'hex');
                s_r = BN.fromBuffer(sigbuf.slice(0, 32));
                s_s = BN.fromBuffer(sigbuf.slice(32));
                pub = Bitcore.PublicKey.fromString(keyData.publicKey);
                sig = new Bitcore.crypto.Signature(s_r, s_s);
                valid = Bitcore.crypto.ECDSA.verify(hashbuf, sig, pub);
                if (!valid) {
                    throw new Error('Response signature invalid');
                }
                return [2, payProDetails];
            });
        });
    };
    PayProV2.processResponse = function (responseData) {
        var payProDetails = {
            payProUrl: responseData.paymentUrl,
            memo: responseData.memo
        };
        payProDetails.verified = true;
        if (responseData.paymentOptions) {
            payProDetails.paymentOptions = responseData.paymentOptions;
            payProDetails.paymentOptions.forEach(function (option) {
                option.network = NetworkMap[option.network];
            });
        }
        if (responseData.network) {
            payProDetails.network = NetworkMap[responseData.network];
        }
        if (responseData.chain) {
            payProDetails.coin = responseData.chain.toLowerCase();
        }
        if (responseData.expires) {
            try {
                payProDetails.expires = new Date(responseData.expires).toISOString();
            }
            catch (e) {
                throw new Error('Bad expiration');
            }
        }
        if (responseData.instructions) {
            payProDetails.instructions = responseData.instructions;
            payProDetails.instructions.forEach(function (output) {
                output.toAddress = output.to || output.outputs[0].address;
                output.amount = output.value !== undefined ? output.value : output.outputs[0].amount;
            });
            var _a = responseData.instructions[0], requiredFeeRate = _a.requiredFeeRate, gasPrice = _a.gasPrice;
            payProDetails.requiredFeeRate = requiredFeeRate || gasPrice;
            if (payProDetails.requiredFeeRate) {
                if (payProDetails.requiredFeeRate > MAX_FEE_PER_KB[payProDetails.coin]) {
                    throw new Error('Fee rate too high:' + payProDetails.requiredFeeRate);
                }
            }
        }
        return payProDetails;
    };
    PayProV2.options = {
        headers: {},
        args: '',
        agent: false
    };
    PayProV2.request = superagent;
    PayProV2.trustedKeys = dfltTrustedKeys;
    return PayProV2;
}());
exports.PayProV2 = PayProV2;
//# sourceMappingURL=payproV2.js.map