import { BCHTxProvider } from './bch';
import { BTCTxProvider } from './btc';
import { DOGETxProvider } from './doge';
import { ERC20TxProvider } from './erc20';
import { ERC721TxProvider } from './erc721';
import { ETHTxProvider } from './eth';
import { ETHMULTISIGTxProvider } from './eth-multisig';
import { LTCTxProvider } from './ltc';
import { RelayTxProvider } from './relay'; // john 20220709
import { VCLTxProvider } from './vcl';
import { XRPTxProvider } from './xrp';

const providers = {
  BTC: new BTCTxProvider(),
  BCH: new BCHTxProvider(),
  ETH: new ETHTxProvider(),
  ERC20: new ERC20TxProvider(),
  ERC721: new ERC721TxProvider(),
  RELAY: new RelayTxProvider(),
  ETHMULTISIG: new ETHMULTISIGTxProvider(),
  XRP: new XRPTxProvider(),
  DOGE: new DOGETxProvider(),
  LTC: new LTCTxProvider(),
  VCL: new VCLTxProvider()
};

export class TransactionsProxy {
  get({ chain }) {
    return providers[chain];
  }

  create(params) {
    return this.get(params).create(params);
  }

  sign(params): string {
    return this.get(params).sign(params);
  }

  getSignature(params): string {
    return this.get(params).getSignature(params);
  }

  applySignature(params) {
    return this.get(params).applySignature(params);
  }

  getHash(params) {
    return this.get(params).getHash(params);
  }
}

export default new TransactionsProxy();
