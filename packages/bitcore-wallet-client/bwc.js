var errorSpec = [
    {
        name: 'INVALID_BACKUP',
        message: 'Invalid Backup.'
    },
    {
        name: 'OBSOLETE_BACKUP',
        message: 'Wallet backup is obsolete.'
    },
    {
        name: 'WALLET_DOES_NOT_EXIST',
        message: 'Wallet does not exist.'
    },
    {
        name: 'MISSING_PRIVATE_KEY',
        message: 'Missing private keys to sign.'
    },
    {
        name: 'ENCRYPTED_PRIVATE_KEY',
        message: 'Private key is encrypted, cannot sign transaction.'
    },
    {
        name: 'SERVER_COMPROMISED',
        message: 'Server response could not be verified.'
    },
    {
        name: 'COULD_NOT_BUILD_TRANSACTION',
        message: 'Could not build the transaction.'
    },
    {
        name: 'INSUFFICIENT_FUNDS',
        message: 'Insufficient funds.'
    },
    {
        name: 'CONNECTION_ERROR',
        message: 'Wallet service connection error.'
    },
    {
        name: 'MAINTENANCE_ERROR',
        message: 'Wallet service is under maintenance.'
    },
    {
        name: 'NOT_FOUND',
        message: 'Wallet service not found.'
    },
    {
        name: 'ECONNRESET_ERROR',
        message: 'ECONNRESET, body: {0}'
    },
    {
        name: 'WALLET_ALREADY_EXISTS',
        message: 'Wallet already exists.'
    },
    {
        name: 'COPAYER_IN_WALLET',
        message: 'Copayer in wallet.'
    },
    {
        name: 'WALLET_FULL',
        message: 'Wallet is full.'
    },
    {
        name: 'WALLET_NOT_FOUND',
        message: 'Wallet not found.'
    },
    {
        name: 'INSUFFICIENT_FUNDS_FOR_FEE',
        message: 'Insufficient funds for fee.'
    },
    {
        name: 'INSUFFICIENT_ETH_FEE',
        message: 'Your linked ETH wallet does not have enough ETH for fee.'
    },
    {
        name: 'LOCKED_FUNDS',
        message: 'Locked funds.'
    },
    {
        name: 'LOCKED_ETH_FEE',
        message: 'Your ETH linked wallet funds are locked by pending spend proposals.'
    },
    {
        name: 'DUST_AMOUNT',
        message: 'Amount below dust threshold.'
    },
    {
        name: 'COPAYER_VOTED',
        message: 'Copayer already voted on this transaction proposal.'
    },
    {
        name: 'NOT_AUTHORIZED',
        message: 'Not authorized.'
    },
    {
        name: 'UNAVAILABLE_UTXOS',
        message: 'Unavailable unspent outputs.'
    },
    {
        name: 'TX_NOT_FOUND',
        message: 'Transaction proposal not found.'
    },
    {
        name: 'MAIN_ADDRESS_GAP_REACHED',
        message: 'Maximum number of consecutive addresses without activity reached.'
    },
    {
        name: 'COPAYER_REGISTERED',
        message: 'Copayer already register on server.'
    },
    {
        name: 'INPUT_NOT_FOUND',
        message: "We could not find one or more inputs for your transaction on the blockchain. Make sure you're not trying to use unconfirmed change."
    },
    {
        name: 'UNCONFIRMED_INPUTS_NOT_ACCEPTED',
        message: 'Can not pay this invoice using unconfirmed inputs.'
    },
    {
        name: 'INVOICE_NOT_AVAILABLE',
        message: 'The invoice is no available.'
    },
    {
        name: 'INVOICE_EXPIRED',
        message: 'The invoice is no longer receiving payments.'
    },
    {
        name: 'UNABLE_TO_PARSE_PAYMENT',
        message: 'We were unable to parse your payment. Please try again or contact your wallet provider.'
    },
    {
        name: 'NO_TRASACTION',
        message: 'Your request did not include a transaction. Please try again or contact your wallet provider.'
    },
    {
        name: 'INVALID_TX_FORMAT',
        message: 'Your transaction was an in an invalid format, it must be a hexadecimal string. Contact your wallet provider.'
    },
    {
        name: 'UNABLE_TO_PARSE_TX',
        message: 'We were unable to parse the transaction you sent. Please try again or contact your wallet provider.'
    },
    {
        name: 'WRONG_ADDRESS',
        message: 'The transaction you sent does not have any output to the address on the invoice'
    },
    {
        name: 'WRONG_AMOUNT',
        message: 'The amount on the transaction does not match the amount requested. This payment will not be accepted.'
    },
    {
        name: 'NOT_ENOUGH_FEE',
        message: 'Transaction fee is below the current minimum threshold.'
    },
    {
        name: 'BTC_NOT_BCH',
        message: 'This invoice is priced in BTC, not BCH. Please try with a BTC wallet instead.'
    },
    {
        name: 'REQUEST_TIMEOUT',
        message: 'The PayPro request has timed out. Please connect to the internet or try again later.'
    },
    {
        name: 'INVALID_REQUEST',
        message: 'The PayPro request was invalid. Please try again later.'
    }
];
module.exports = errorSpec;
module.exports = {
    '1DbY94wCcLRM1Y6RGFg457JyqBbsYxzfiN': {
        owner: 'BitPay, Inc.',
        networks: ['main'],
        domains: ['bitpay.com'],
        publicKey: '03218884b9a42334195ec32344d487ef291fda4b6e712a7858e9836c2d326e0c08'
    },
    mh65MN7drqmwpCRZcEeBEE9ceQCQ95HtZc: {
        owner: 'BitPay (TESTNET ONLY - DO NOT TRUST FOR ACTUAL BITCOIN)',
        networks: ['test'],
        domains: ['test.bitpay.com'],
        publicKey: '03159069584176096f1c89763488b94dbc8d5e1fa7bf91f50b42f4befe4e45295a'
    },
    mjnih84Sb1dqvzA66GdUikT7k78WaZbRHv: {
        owner: 'BitPay Staging (TESTNET ONLY - DO NOT TRUST FOR ACTUAL BITCOIN)',
        networks: ['test'],
        domains: ['staging.bitpay.com'],
        publicKey: '02ed6fa908e51886dee9d39cae10c220d7e6ae08f634581c5aea019b5a7d9f590e'
    },
    '1GA2vgw5byxqTpAUHEyyh7ahXnHU1FDDAy': {
        owner: 'BitPay, Inc.',
        networks: ['main'],
        domains: ['bitpay.com'],
        publicKey: '027ffb2cc626a97bc3b449ae3b28b0acf07bc900bba8912d60ca12ad2b616cbe72'
    },
    '1EMqSoDzMdBuuvM2RUnup3FnDeo6wuHxEg': {
        owner: 'BitPay, Inc.',
        networks: ['main'],
        domains: ['bitpay.com'],
        publicKey: '03a29de86e138106a329bc6db085f02d8e19f59249204dfd5cc797fcb36b8ed93c'
    },
    '1G3ZYxgZDS2ne4zoB8qMyotPz91y3K4bsz': {
        owner: 'BitPay, Inc.',
        networks: ['main'],
        domains: ['bitpay.com'],
        publicKey: '022ba5469ec10a1d12911a5ca39c45bd0de24db83145507ffaf1fb6a3ca047f717'
    },
    '12YuH4QkhUufzs1zTaENznrDYaougbuQoR': {
        owner: 'BitPay, Inc.',
        networks: ['main'],
        domains: ['bitpay.com'],
        publicKey: '03065b167ac14111efdbf7708708ecf44d22ed0e97af3c656a183162dabf5a59bf'
    },
    '1743vPQpyWYmLr1Mo65434a9sSHgfgJH55': {
        owner: 'BitPay, Inc.',
        networks: ['main'],
        domains: ['bitpay.com'],
        publicKey: '03dc0f18eadf553705ab87421d264204a9fcb8a7984997e07a867cbf55972908eb'
    },
    '1D4eAr6bZtVRtfXu5FJjhWr6KhULNSsmfu': {
        owner: 'BitPay, Inc.',
        networks: ['main'],
        domains: ['bitpay.com'],
        publicKey: '02cab72d4d5d0c9ede7617562e42c485dcfb34db52fd0e6a3de62462040ac1ce90'
    },
    '1CuGG993rBS8sAnxZabyNVtLdMVd8DPmvy': {
        owner: 'BitPay, Inc.',
        networks: ['main'],
        domains: ['bitpay.com'],
        publicKey: '02e184ad56dee82bbaf290144f24b7ab8e508f6c26e9181c8501c8219a7e1999b1'
    },
    '1K3FR4SGgBpkNyWKUsPgcjBDA1T1GbeGg4': {
        owner: 'BitPay, Inc.',
        networks: ['main'],
        domains: ['bitpay.com'],
        publicKey: '027b7d555a3444936ddb200ca640f41aa8c89851fbbb13521b5aaa32d75df57cc8'
    },
    '1JGrtQUkTSs12VbgoWk8j5sBCLzzCD54aa': {
        owner: 'BitPay, Inc.',
        networks: ['main'],
        domains: ['bitpay.com'],
        publicKey: '03c3872f9c42c1c2fca77a77727f3b180cdc811754f6b560d298f1ce63c78df484'
    },
    '1FP6EdPNHx7CAXhfrEgro12SiJpCj2q3aV': {
        owner: 'BitPay, Inc.',
        networks: ['main'],
        domains: ['bitpay.com'],
        publicKey: '02527a9029fbb09ec9a02471e03296932d20544d3935fa492e2f74a1f79a0c48f6'
    },
    '1CBGdUHFw1DZzXifiksUpi4QzLuYbhAuv8': {
        owner: 'BitPay, Inc.',
        networks: ['main'],
        domains: ['bitpay.com'],
        publicKey: '03adbd79e63b046cc25c70b2c1f428a410e1ca46f88fb6c387f2883090b9fa0367'
    },
    '1PBMNQnp2sMfHsPSDXsbmY8xQti1615sdc': {
        owner: 'BitPay, Inc.',
        networks: ['main'],
        domains: ['bitpay.com'],
        publicKey: '02c9f1fbf8afa5a9b6a22a6c442b184e7e72a8b173c4a06beb11a5b700f024b06e'
    },
    '1FbNGMJv8LXBXzSs1SRWZVUy5kCRw3M7zc': {
        owner: 'BitPay, Inc.',
        networks: ['main'],
        domains: ['bitpay.com'],
        publicKey: '0386126eaa4f7bc816ea0c5841cdd1086704167c126e03c17dbd5fc899469091bb'
    },
    '1D6YCE9PZPoxPtQZuCed9bFrgzooKxGEEC': {
        owner: 'BitPay, Inc.',
        networks: ['main'],
        domains: ['bitpay.com'],
        publicKey: '03271e4ea488ed0d1294dce6f3554c5d6f9cb068a847f500f2ea392148402499f1'
    }
};
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
//# sourceMappingURL=bwc.js.map