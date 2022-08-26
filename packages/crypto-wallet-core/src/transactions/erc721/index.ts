import Web3 from 'web3';
import { AbiItem } from 'web3-utils';
import { ETHTxProvider } from '../eth';
import { ERC721Abi } from './abi';
const { toBN } = Web3.utils;

export class ERC721TxProvider extends ETHTxProvider {
  getERC721Contract(tokenContractAddress: string) {
    const web3 = new Web3();
    const contract = new web3.eth.Contract(ERC721Abi as AbiItem[], tokenContractAddress);
    return contract;
  }

  create(params: {
    recipients: Array<{ address: string; amount: string }>;
    nonce: number;
    gasPrice: number;
    data: string;
    gasLimit: number;
    network: string;
    chainId?: number;
    tokenAddress: string;
    tokenId: number;
    from: string;
  }) {
    const { from, tokenAddress, tokenId } = params;
    const data = this.encodeData(params);
    const recipients = [{ address: tokenAddress, amount: '0' }];
    const newParams = { ...params, recipients, data };
    return super.create(newParams);
  }

  encodeData(params: {
    recipients: Array<{ address: string; amount: string }>;
    tokenAddress: string;
    tokenId: number;
    from: string;
  }) {
    const { recipients, tokenAddress, tokenId, from } = params;
    const [{ address }] = params.recipients;
    const tokenIdStr = Number(tokenId).toLocaleString('en', { useGrouping: false });
    const data = this.getERC721Contract(tokenAddress)
      .methods.safeTransferFrom(from, address, tokenIdStr)
      .encodeABI();
    return data;
  }
}
