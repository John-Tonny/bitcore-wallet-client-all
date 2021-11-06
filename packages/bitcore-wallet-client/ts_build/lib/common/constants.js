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
exports.Constants = {
    SCRIPT_TYPES: {
        P2SH: 'P2SH',
        P2PKH: 'P2PKH',
        P2WPKH: 'P2WPKH',
        P2WSH: 'P2WSH'
    },
    DERIVATION_STRATEGIES: {
        BIP44: 'BIP44',
        BIP45: 'BIP45',
        BIP48: 'BIP48'
    },
    PATHS: {
        SINGLE_ADDRESS: 'm/0/0',
        REQUEST_ELECTRUM_KEY: "m/0'",
        REQUEST_SEGWIT_ELECTRUM_KEY: 'm',
        REQUEST_KEY: "m/1'/0",
        REQUEST_KEY_AUTH: 'm/2'
    },
    BIP45_SHARED_INDEX: 0x80000000 - 1,
    COINS: ['btc', 'bch', 'eth', 'vcl', 'xrp', 'usdc', 'pax', 'gusd', 'busd'],
    ERC20: ['usdc', 'pax', 'gusd', 'busd'],
    UTXO_COINS: ['btc', 'bch', 'vcl'],
    TOKEN_OPTS: CWC.Constants.TOKEN_OPTS,
    UNITS: CWC.Constants.UNITS
};
//# sourceMappingURL=constants.js.map