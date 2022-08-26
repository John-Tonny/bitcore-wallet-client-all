import Web3 from 'web3';
import { AbiItem } from 'web3-utils';
import { ERC20Abi } from '../erc20/abi';
import { ETHTxProvider } from '../eth';
import { ERC20ManagerAbi, ERC20ManagerAddr, RelayAbi, RelayAddr } from './abi';
const { toBN } = Web3.utils;

export class RelayTxProvider extends ETHTxProvider {
  getWeb3(web3Url) {
    if (web3Url) {
      return new Web3(web3Url);
    }
    return new Web3();
  }

  getRelayContract(web3Url) {
    const web3 = this.getWeb3(web3Url);
    const contract = new web3.eth.Contract(RelayAbi as AbiItem[], RelayAddr);
    return contract;
  }

  getERC20ManagerContract(web3Url) {
    const web3 = this.getWeb3(web3Url);
    const contract = new web3.eth.Contract(ERC20ManagerAbi as AbiItem[], ERC20ManagerAddr);
    return contract;
  }

  getERC20Contract(tokenContractAddress: string, web3Url: string) {
    const web3 = this.getWeb3(web3Url);
    const contract = new web3.eth.Contract(ERC20Abi as AbiItem[], tokenContractAddress);
    return contract;
  }

  createRelayAssetTx(params: {
    nonce: number;
    gasPrice: number;
    data: string;
    gasLimit: number;
    network: string;
    relay: {
      nevmBlockNumber: number;
      txBytes: string;
      txIndex: number;
      txSibling: Array<string>;
      syscoinBlockHeader: string;
    };
    chainId?: number;
  }) {
    const data = this.encodeRelayAssetTx(params);
    const recipients = [{ address: RelayAddr, amount: '0' }];
    const newParams = { ...params, recipients, data };
    return super.create(newParams);
  }

  encodeRelayAssetTx(params: {
    relay: {
      nevmBlockNumber: number;
      txBytes: string;
      txIndex: number;
      txSibling: Array<string>;
      syscoinBlockHeader: string;
    };
  }) {
    const { relay } = params;
    const { nevmBlockNumber, txBytes, txIndex, txSibling, syscoinBlockHeader } = params.relay;
    const data = this.getRelayContract(undefined)
      .methods.relayAssetTx(nevmBlockNumber, txBytes, txIndex, txSibling, syscoinBlockHeader)
      .encodeABI();
    return data;
  }

  createRelayTx(params: {
    nonce: number;
    gasPrice: number;
    data: string;
    gasLimit: number;
    network: string;
    relay: {
      nevmBlockNumber: number;
      txBytes: string;
      txIndex: number;
      txSibling: Array<string>;
      syscoinBlockHeader: string;
    };
    chainId?: number;
  }) {
    const data = this.encodeRelayTx(params);
    const recipients = [{ address: RelayAddr, amount: '0' }];
    const newParams = { ...params, recipients, data };
    return super.create(newParams);
  }
  encodeRelayTx(params: {
    relay: {
      nevmBlockNumber: number;
      txBytes: string;
      txIndex: number;
      txSibling: Array<string>;
      syscoinBlockHeader: string;
    };
  }) {
    const { relay } = params;
    const { nevmBlockNumber, txBytes, txIndex, txSibling, syscoinBlockHeader } = params.relay;
    const data = this.getRelayContract(undefined)
      .methods.relayTx(nevmBlockNumber, txBytes, txIndex, txSibling, syscoinBlockHeader)
      .encodeABI();
    return data;
  }

  createFreezeBurnERC20(params: {
    recipients: Array<{ amount: string }>;
    nonce: number;
    gasPrice: number;
    data: string;
    gasLimit: number;
    network: string;
    relay: { assetGuid: string; sysAddr: string };
    chainId?: number;
  }) {
    const data = this.encodeFreezeBurnERC20(params);
    const recipients = [{ address: ERC20ManagerAddr, amount: '0' }];
    const newParams = { ...params, recipients, data };
    return super.create(newParams);
  }
  encodeFreezeBurnERC20(params: {
    recipients: Array<{ amount: string }>;
    relay: { assetGuid: string; sysAddr: string };
  }) {
    const { recipients, relay } = params;
    const [{ amount }] = params.recipients;
    const { assetGuid, sysAddr } = params.relay;
    const data = this.getERC20ManagerContract(undefined)
      .methods.freezeBurnERC20(amount, assetGuid, sysAddr)
      .encodeABI();
    return data;
  }

  createApprove(params: {
    recipients: Array<{ address: string; amount: string }>;
    nonce: number;
    gasPrice: number;
    data: string;
    gasLimit: number;
    tokenAddress: string;
    network: string;
    chainId?: number;
    contractAddress?: string;
  }) {
    const { tokenAddress, contractAddress } = params;
    const data = this.encodeApprove(params);
    const recipients = [{ address: contractAddress || tokenAddress, amount: '0' }];
    const newParams = { ...params, recipients, data };
    return super.create(newParams);
  }

  encodeApprove(params: {
    recipients: Array<{ address: string; amount: string }>;
    tokenAddress: string;
    contractAddress?: string;
  }) {
    const { tokenAddress, recipients, contractAddress } = params;
    const [{ amount }] = params.recipients;
    const amountStr = Number(amount).toLocaleString('en', { useGrouping: false });
    const data = this.getERC20Contract(tokenAddress, undefined)
      .methods.approve(ERC20ManagerAddr, amountStr)
      .encodeABI();
    return data;
  }
}
