'use strict';

var vclcore = module.exports;

// module information
vclcore.version = 'v' + require('./package.json').version;
vclcore.versionGuard = function(version) {
  if (version !== undefined) {
    var message = 'More than one instance of vclcore-lib found. ' +
      'Please make sure to require vclcore-lib and check that submodules do' +
      ' not also include their own vclcore-lib dependency.';
    throw new Error(message);
  }
};
vclcore.versionGuard(global._vclcore);
global._vclcore = vclcore.version;

// crypto
vclcore.crypto = {};
vclcore.crypto.BN = require('./lib/crypto/bn');
vclcore.crypto.ECDSA = require('./lib/crypto/ecdsa');
vclcore.crypto.Hash = require('./lib/crypto/hash');
vclcore.crypto.Random = require('./lib/crypto/random');
vclcore.crypto.Point = require('./lib/crypto/point');
vclcore.crypto.Signature = require('./lib/crypto/signature');

// encoding
vclcore.encoding = {};
vclcore.encoding.Base58 = require('./lib/encoding/base58');
vclcore.encoding.Base58Check = require('./lib/encoding/base58check');
vclcore.encoding.BufferReader = require('./lib/encoding/bufferreader');
vclcore.encoding.BufferWriter = require('./lib/encoding/bufferwriter');
vclcore.encoding.Varint = require('./lib/encoding/varint');

// utilities
vclcore.util = {};
vclcore.util.buffer = require('./lib/util/buffer');
vclcore.util.js = require('./lib/util/js');
vclcore.util.preconditions = require('./lib/util/preconditions');

// errors thrown by the library
vclcore.errors = require('./lib/errors');

// main bitcoin library
vclcore.Address = require('./lib/address');
vclcore.Block = require('./lib/block');
vclcore.MerkleBlock = require('./lib/block/merkleblock');
vclcore.BlockHeader = require('./lib/block/blockheader');
vclcore.HDPrivateKey = require('./lib/hdprivatekey.js');
vclcore.HDPublicKey = require('./lib/hdpublickey.js');
vclcore.Message = require('./lib/message');
vclcore.Networks = require('./lib/networks');
vclcore.Opcode = require('./lib/opcode');
vclcore.PrivateKey = require('./lib/privatekey');
vclcore.PublicKey = require('./lib/publickey');
vclcore.Script = require('./lib/script');
vclcore.Transaction = require('./lib/transaction');
vclcore.URI = require('./lib/uri');
vclcore.Unit = require('./lib/unit');

vclcore.atomicswap = {};
vclcore.atomicswap.CreateContract = require('./lib/atomicswap/createcontract');
vclcore.atomicswap.AuditContract = require('./lib/atomicswap/auditcontract');
vclcore.atomicswap.RedeemContract = require('./lib/atomicswap/redeemcontract');
vclcore.atomicswap.RefundContract = require('./lib/atomicswap/refundcontract');
vclcore.atomicswap.ExtractContract = require('./lib/atomicswap/extractcontract');

vclcore.masternode = {};
vclcore.masternode.ProRegTx = require('./lib/masternode/proregtx');
vclcore.masternode.ProUpRegTx = require('./lib/masternode/proupregtx');
vclcore.masternode.ProUpServiceTx = require('./lib/masternode/proupservicetx');
vclcore.masternode.ProRevokeTx = require('./lib/masternode/prorevoketx');


// dependencies, subject to change
vclcore.deps = {};
vclcore.deps.bnjs = require('bn.js');
vclcore.deps.bs58 = require('bs58');
vclcore.deps.Buffer = Buffer;
vclcore.deps.elliptic = require('elliptic');
vclcore.deps._ = require('lodash');

// Internal usage, exposed for testing/advanced tweaking
vclcore.Transaction.sighash = require('./lib/transaction/sighash');
