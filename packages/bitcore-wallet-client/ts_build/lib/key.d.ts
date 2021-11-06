export declare class Key {
    version: number;
    use0forBCH: boolean;
    useforElectrum: boolean;
    useSegwit: boolean;
    useMulti: boolean;
    use44forMultisig: boolean;
    compliantDerivation: boolean;
    id: any;
    static FIELDS: string[];
    constructor();
    static match(a: any, b: any): boolean;
    static create: (opts: any) => any;
    static fromMnemonic: (words: any, opts: any) => any;
    static fromExtendedPrivateKey: (xPriv: any, opts: any) => any;
    static fromObj: (obj: any) => any;
    toObj: () => {};
    getPrivateKey: (password: any, rootPath: any, path: any, coin: any) => any;
    getPrivateKeyofWif: (password: any, rootPath: any, path: any, coin: any, network: any) => any;
    isValidAddress: (password: any, rootPath: any, coin: any, queryAddress: any, start: any, stop: any) => boolean;
    isPrivKeyEncrypted: () => boolean;
    checkPassword: (password: any) => boolean;
    get: (password: any) => any;
    encrypt: (password: any, opts: any) => void;
    decrypt: (password: any) => void;
    derive: (password: any, path: any) => any;
    _checkCoin(coin: any): void;
    _checkNetwork(network: any): void;
    getBaseAddressDerivationPath(opts: any): string;
    createCredentials: (password: any, opts: any) => any;
    createAccess: (password: any, opts: any) => {
        signature: any;
        requestPrivKey: any;
    };
    sign: (rootPath: any, txp: any, password: any, cb: any) => any;
    signAtomicSwap: (privKey: any, txp: any, cb: any) => any[];
}
//# sourceMappingURL=key.d.ts.map