export declare class Masternode {
    version: number;
    id: any;
    txid: string;
    vout: number;
    signPrivKey: string;
    pingHash: string;
    privKey: string;
    addr: string;
    port: number;
    static FIELDS: string[];
    constructor(txid: any, vout: any, signPrivKey: any, pingHash: any, privKey: any, addr: any, port: any);
    serialize_input(): string;
    hash_decode(): string;
    get_address(): string;
    get_now_time(): string;
    get_int64(value: any): string;
    get_int32(value: any): string;
    get_int16BE(value: any): string;
    get_int16(value: any): string;
    get_int8(value: any): string;
    get_varintNum(n: any): any;
    singMasternode: () => string;
}
//# sourceMappingURL=masternode.d.ts.map