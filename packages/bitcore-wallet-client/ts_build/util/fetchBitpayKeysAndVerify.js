var crypto = require('crypto');
var bs58 = require('bs58');
var kbpgp = require('kbpgp');
var request = require('request-promise');
var bitpayPgpKeys = {};
var githubPgpKeys = {};
var importedPgpKeys = {};
var signatureCount = 0;
var eccPayload;
var parsedEccPayload;
var eccKeysHash;
var keyRequests = [];
keyRequests.push((function () {
    console.log('Fetching keys from github.com/bitpay/pgp-keys...');
    return request({
        method: 'GET',
        url: 'https://api.github.com/repos/bitpay/pgp-keys/contents/keys',
        headers: {
            'user-agent': 'BitPay Key-Check Utility'
        },
        json: true
    }).then(function (pgpKeyFiles) {
        var fileDataPromises = [];
        pgpKeyFiles.forEach(function (file) {
            fileDataPromises.push((function () {
                return request({
                    method: 'GET',
                    url: file.download_url,
                    headers: {
                        'user-agent': 'BitPay Key-Check Utility'
                    }
                }).then(function (body) {
                    var hash = crypto
                        .createHash('sha256')
                        .update(body)
                        .digest('hex');
                    githubPgpKeys[hash] = body;
                    return Promise.resolve();
                });
            })());
        });
        return Promise.all(fileDataPromises);
    });
})());
keyRequests.push((function () {
    console.log('Fetching keys from bitpay.com/pgp-keys...');
    return request({
        method: 'GET',
        url: 'https://bitpay.com/pgp-keys.json',
        headers: {
            'user-agent': 'BitPay Key-Check Utility'
        },
        json: true
    }).then(function (body) {
        body.pgpKeys.forEach(function (key) {
            var hash = crypto
                .createHash('sha256')
                .update(key.publicKey)
                .digest('hex');
            bitpayPgpKeys[hash] = key.publicKey;
        });
        return Promise.resolve();
    });
})());
Promise.all(keyRequests)
    .then(function () {
    if (Object.keys(githubPgpKeys).length !== Object.keys(bitpayPgpKeys).length) {
        console.log('Warning: Different number of keys returned by key lists');
    }
    var bitpayOnlyKeys = Object.keys(bitpayPgpKeys).filter(function (keyHash) {
        return !githubPgpKeys[keyHash];
    });
    var githubOnlyKeys = Object.keys(githubPgpKeys).filter(function (keyHash) {
        return !bitpayPgpKeys[keyHash];
    });
    if (bitpayOnlyKeys.length) {
        console.log('BitPay returned some keys which are not present in github');
        Object.keys(bitpayOnlyKeys).forEach(function (keyHash) {
            console.log("Hash " + keyHash + " Key: " + bitpayOnlyKeys[keyHash]);
        });
    }
    if (githubOnlyKeys.length) {
        console.log('GitHub returned some keys which are not present in BitPay');
        Object.keys(githubOnlyKeys).forEach(function (keyHash) {
            console.log("Hash " + keyHash + " Key: " + githubOnlyKeys[keyHash]);
        });
    }
    if (!githubOnlyKeys.length && !bitpayOnlyKeys.length) {
        console.log("Both sites returned " + Object.keys(githubPgpKeys).length + " keys. Key lists from both are identical.");
        return Promise.resolve();
    }
    else {
        return Promise.reject('Aborting signature checks due to key mismatch');
    }
})
    .then(function () {
    console.log('Importing PGP keys for later use...');
    return Promise.all(Object.values(bitpayPgpKeys).map(function (pgpKeyString) {
        return new Promise(function (resolve, reject) {
            kbpgp.KeyManager.import_from_armored_pgp({ armored: pgpKeyString }, function (err, km) {
                if (err) {
                    return reject(err);
                }
                importedPgpKeys[km.pgp
                    .key(km.pgp.primary)
                    .get_fingerprint()
                    .toString('hex')] = km;
                return resolve();
            });
        });
    }));
})
    .then(function () {
    console.log('Fetching current ECC keys from bitpay.com/signingKeys/paymentProtocol.json');
    return request({
        method: 'GET',
        url: 'https://bitpay.com/signingKeys/paymentProtocol.json',
        headers: {
            'user-agent': 'BitPay Key-Check Utility'
        }
    }).then(function (rawEccPayload) {
        if (rawEccPayload.indexOf('rate limit') !== -1) {
            return Promise.reject('Rate limited by BitPay');
        }
        eccPayload = rawEccPayload;
        parsedEccPayload = JSON.parse(rawEccPayload);
        eccKeysHash = crypto
            .createHash('sha256')
            .update(rawEccPayload)
            .digest('hex');
        return Promise.resolve();
    });
})
    .then(function () {
    console.log("Fetching signatures for ECC payload with hash " + eccKeysHash);
    return request({
        method: 'GET',
        url: "https://bitpay.com/signatures/" + eccKeysHash + ".json",
        headers: {
            'user-agent': 'BitPay Key-Check Utility'
        },
        json: true
    }).then(function (signatureData) {
        console.log('Verifying each signature is valid and comes from the set of PGP keys retrieved earlier');
        Promise.all(signatureData.signatures.map(function (signature) {
            return new Promise(function (resolve, reject) {
                var pgpKey = importedPgpKeys[signature.identifier];
                if (!pgpKey) {
                    return reject("PGP key " + signature.identifier + " missing for signature");
                }
                var armoredSignature = Buffer.from(signature.signature, 'hex').toString();
                kbpgp.unbox({ armored: armoredSignature, data: Buffer.from(eccPayload), keyfetch: pgpKey }, function (err, result) {
                    if (err) {
                        return reject("Unable to verify signature from " + signature.identifier + " " + err);
                    }
                    signatureCount++;
                    console.log("Good signature from " + signature.identifier + " (" + pgpKey.get_userids()[0].get_username() + ")");
                    return Promise.resolve();
                });
            });
        }));
    });
})
    .then(function () {
    if (signatureCount >= Object.keys(bitpayPgpKeys).length / 2) {
        console.log("----\nThe following ECC key set has been verified against signatures from " + signatureCount + " of the " + Object.keys(bitpayPgpKeys).length + " published BitPay PGP keys.");
        console.log(eccPayload);
        var keyMap_1 = {};
        console.log('----\nValid keymap for use in bitcoinRpc example:');
        parsedEccPayload.publicKeys.forEach(function (pubkey) {
            var a = crypto
                .createHash('sha256')
                .update(pubkey, 'hex')
                .digest();
            var b = crypto
                .createHash('rmd160')
                .update(a)
                .digest('hex');
            var c = '00' + b;
            var d = crypto
                .createHash('sha256')
                .update(c, 'hex')
                .digest();
            var e = crypto
                .createHash('sha256')
                .update(d)
                .digest('hex');
            var pubKeyHash = bs58.encode(Buffer.from(c + e.substr(0, 8), 'hex'));
            keyMap_1[pubKeyHash] = {
                owner: parsedEccPayload.owner,
                networks: ['main'],
                domains: parsedEccPayload.domains,
                publicKey: pubkey
            };
            keyMap_1['mh65MN7drqmwpCRZcEeBEE9ceQCQ95HtZc'] = {
                owner: 'BitPay (TESTNET ONLY - DO NOT TRUST FOR ACTUAL BITCOIN)',
                networks: ['test'],
                domains: ['test.bitpay.com'],
                publicKey: '03159069584176096f1c89763488b94dbc8d5e1fa7bf91f50b42f4befe4e45295a'
            };
        });
        console.log(keyMap_1);
        var fs = require('fs');
        fs.writeFileSync('JsonPaymentProtocolKeys.js', 'module.exports = ' + JSON.stringify(keyMap_1, null, 2));
    }
    else {
        return Promise.reject("Insufficient good signatures " + signatureCount + " for a proper validity check");
    }
})
    .catch(function (err) {
    console.log("Error encountered " + err);
});
process.on('unhandledRejection', console.log);
//# sourceMappingURL=fetchBitpayKeysAndVerify.js.map