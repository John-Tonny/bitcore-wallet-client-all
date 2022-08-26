export { RelayAbi, ERC20ManagerAbi, RelayAddr, ERC20ManagerAddr };

const RelayAddr = process.env.RELAY || '0x62aa89614d2ec79dc7Db2A0e84026bBD02b3d7fD';
const RelayAbi = [
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: 'bytes32',
        name: 'txHash',
        type: 'bytes32'
      },
      {
        indexed: false,
        internalType: 'uint256',
        name: 'returnCode',
        type: 'uint256'
      }
    ],
    name: 'RelayTransaction',
    type: 'event'
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: 'bytes32',
        name: 'txHash',
        type: 'bytes32'
      },
      {
        indexed: false,
        internalType: 'uint256',
        name: 'returnCode',
        type: 'uint256'
      }
    ],
    name: 'VerifyTransaction',
    type: 'event'
  },
  {
    inputs: [
      { internalType: 'bytes', name: 'input', type: 'bytes' },
      { internalType: 'uint256', name: 'pos', type: 'uint256' }
    ],
    name: 'bytesToUint32Flipped',
    outputs: [{ internalType: 'uint32', name: 'result', type: 'uint32' }],
    stateMutability: 'pure',
    type: 'function',
    constant: true
  },
  {
    inputs: [
      { internalType: 'uint256', name: '_txHash', type: 'uint256' },
      { internalType: 'uint256', name: '_txIndex', type: 'uint256' },
      {
        internalType: 'uint256[]',
        name: '_siblings',
        type: 'uint256[]'
      }
    ],
    name: 'computeMerkle',
    outputs: [{ internalType: 'uint256', name: '', type: 'uint256' }],
    stateMutability: 'pure',
    type: 'function',
    constant: true
  },
  {
    inputs: [{ internalType: 'uint256', name: '_input', type: 'uint256' }],
    name: 'flip32Bytes',
    outputs: [{ internalType: 'uint256', name: 'result', type: 'uint256' }],
    stateMutability: 'pure',
    type: 'function',
    constant: true
  },
  {
    inputs: [
      { internalType: 'bytes', name: 'data', type: 'bytes' },
      { internalType: 'uint256', name: 'pos', type: 'uint256' },
      { internalType: 'uint256', name: 'bits', type: 'uint256' }
    ],
    name: 'getBytesLE',
    outputs: [{ internalType: 'uint256', name: 'result', type: 'uint256' }],
    stateMutability: 'pure',
    type: 'function',
    constant: true
  },
  {
    inputs: [
      { internalType: 'bytes', name: 'txBytes', type: 'bytes' },
      { internalType: 'uint256', name: 'pos', type: 'uint256' }
    ],
    name: 'parseCompactSize',
    outputs: [
      { internalType: 'uint256', name: '', type: 'uint256' },
      { internalType: 'uint256', name: '', type: 'uint256' }
    ],
    stateMutability: 'pure',
    type: 'function',
    constant: true
  },
  {
    inputs: [
      { internalType: 'bytes', name: 'txBytes', type: 'bytes' },
      { internalType: 'uint256', name: 'pos', type: 'uint256' },
      { internalType: 'uint256', name: 'max', type: 'uint256' }
    ],
    name: 'parseVarInt',
    outputs: [
      { internalType: 'uint256', name: '', type: 'uint256' },
      { internalType: 'uint256', name: '', type: 'uint256' }
    ],
    stateMutability: 'pure',
    type: 'function',
    constant: true
  },
  {
    inputs: [],
    name: 'syscoinERC20Manager',
    outputs: [
      {
        internalType: 'contract SyscoinTransactionProcessorI',
        name: '',
        type: 'address'
      }
    ],
    stateMutability: 'view',
    type: 'function',
    constant: true
  },
  {
    inputs: [
      {
        internalType: 'address',
        name: '_syscoinERC20Manager',
        type: 'address'
      }
    ],
    name: 'init',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function'
  },
  {
    inputs: [
      { internalType: 'bytes', name: 'input', type: 'bytes' },
      { internalType: 'uint256', name: 'pos', type: 'uint256' }
    ],
    name: 'bytesToUint32',
    outputs: [{ internalType: 'uint32', name: 'result', type: 'uint32' }],
    stateMutability: 'pure',
    type: 'function',
    constant: true
  },
  {
    inputs: [
      { internalType: 'bytes', name: 'txBytes', type: 'bytes' },
      { internalType: 'uint256', name: 'opIndex', type: 'uint256' },
      { internalType: 'uint256', name: 'pos', type: 'uint256' }
    ],
    name: 'scanBurnTx',
    outputs: [
      { internalType: 'uint256', name: '', type: 'uint256' },
      { internalType: 'address', name: '', type: 'address' },
      { internalType: 'uint32', name: '', type: 'uint32' }
    ],
    stateMutability: 'pure',
    type: 'function',
    constant: true
  },
  {
    inputs: [
      { internalType: 'bytes', name: 'txBytes', type: 'bytes' },
      { internalType: 'uint256', name: 'pos', type: 'uint256' }
    ],
    name: 'getOpReturnPos',
    outputs: [
      { internalType: 'uint256', name: '', type: 'uint256' },
      { internalType: 'uint256', name: '', type: 'uint256' }
    ],
    stateMutability: 'pure',
    type: 'function',
    constant: true
  },
  {
    inputs: [{ internalType: 'bytes', name: 'txBytes', type: 'bytes' }],
    name: 'parseAssetTx',
    outputs: [
      { internalType: 'uint256', name: 'errorCode', type: 'uint256' },
      { internalType: 'uint32', name: 'assetGuid', type: 'uint32' },
      {
        internalType: 'address',
        name: 'erc20Address',
        type: 'address'
      },
      { internalType: 'uint8', name: 'precision', type: 'uint8' }
    ],
    stateMutability: 'pure',
    type: 'function',
    constant: true
  },
  {
    inputs: [
      { internalType: 'bytes', name: 'txBytes', type: 'bytes' },
      { internalType: 'uint256', name: 'pos', type: 'uint256' }
    ],
    name: 'scanAssetTx',
    outputs: [
      { internalType: 'uint32', name: '', type: 'uint32' },
      { internalType: 'address', name: '', type: 'address' },
      { internalType: 'uint8', name: '', type: 'uint8' }
    ],
    stateMutability: 'pure',
    type: 'function',
    constant: true
  },
  {
    inputs: [
      { internalType: 'uint64', name: '_blockNumber', type: 'uint64' },
      { internalType: 'bytes', name: '_txBytes', type: 'bytes' },
      { internalType: 'uint256', name: '_txIndex', type: 'uint256' },
      {
        internalType: 'uint256[]',
        name: '_txSiblings',
        type: 'uint256[]'
      },
      {
        internalType: 'bytes',
        name: '_syscoinBlockHeader',
        type: 'bytes'
      }
    ],
    name: 'relayTx',
    outputs: [{ internalType: 'uint256', name: '', type: 'uint256' }],
    stateMutability: 'nonpayable',
    type: 'function'
  },
  {
    inputs: [
      { internalType: 'uint64', name: '_blockNumber', type: 'uint64' },
      { internalType: 'bytes', name: '_txBytes', type: 'bytes' },
      { internalType: 'uint256', name: '_txIndex', type: 'uint256' },
      {
        internalType: 'uint256[]',
        name: '_txSiblings',
        type: 'uint256[]'
      },
      {
        internalType: 'bytes',
        name: '_syscoinBlockHeader',
        type: 'bytes'
      }
    ],
    name: 'relayAssetTx',
    outputs: [{ internalType: 'uint256', name: '', type: 'uint256' }],
    stateMutability: 'nonpayable',
    type: 'function'
  },
  {
    inputs: [{ internalType: 'bytes', name: 'txBytes', type: 'bytes' }],
    name: 'parseBurnTx',
    outputs: [
      { internalType: 'uint256', name: 'errorCode', type: 'uint256' },
      {
        internalType: 'uint256',
        name: 'output_value',
        type: 'uint256'
      },
      {
        internalType: 'address',
        name: 'destinationAddress',
        type: 'address'
      },
      { internalType: 'uint32', name: 'assetGuid', type: 'uint32' }
    ],
    stateMutability: 'pure',
    type: 'function',
    constant: true
  },
  {
    inputs: [{ internalType: 'bytes', name: '_dataBytes', type: 'bytes' }],
    name: 'dblSha',
    outputs: [{ internalType: 'uint256', name: '', type: 'uint256' }],
    stateMutability: 'pure',
    type: 'function',
    constant: true
  },
  {
    inputs: [{ internalType: 'bytes', name: '_dataBytes', type: 'bytes' }],
    name: 'dblShaFlip',
    outputs: [{ internalType: 'uint256', name: '', type: 'uint256' }],
    stateMutability: 'pure',
    type: 'function',
    constant: true
  },
  {
    inputs: [{ internalType: 'bytes', name: '_blockHeader', type: 'bytes' }],
    name: 'getHeaderMerkleRoot',
    outputs: [{ internalType: 'uint256', name: '', type: 'uint256' }],
    stateMutability: 'pure',
    type: 'function',
    constant: true
  },
  {
    inputs: [{ internalType: 'uint64', name: '_blockNumber', type: 'uint64' }],
    name: 'getSysBlockHash',
    outputs: [{ internalType: 'uint256', name: '', type: 'uint256' }],
    stateMutability: 'view',
    type: 'function',
    constant: true
  }
];

const ERC20ManagerAddr = process.env.ERC20Manager || '0xeEc8C8875dC98FfB5da5CD2e83102Aab962C96C3';
const ERC20ManagerAbi = [
  {
    inputs: [
      {
        internalType: 'address',
        name: '_trustedRelayerContract',
        type: 'address'
      },
      { internalType: 'uint32', name: '_sysxGuid', type: 'uint32' },
      {
        internalType: 'address',
        name: '_erc20ContractAddress',
        type: 'address'
      }
    ],
    stateMutability: 'nonpayable',
    type: 'constructor'
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: 'string',
        name: 'msg',
        type: 'string'
      },
      {
        indexed: false,
        internalType: 'address',
        name: 'addr',
        type: 'address'
      }
    ],
    name: 'TestEvent',
    type: 'event'
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: 'uint32',
        name: 'assetGuid',
        type: 'uint32'
      },
      {
        indexed: false,
        internalType: 'address',
        name: 'freezer',
        type: 'address'
      },
      {
        indexed: false,
        internalType: 'uint256',
        name: 'value',
        type: 'uint256'
      },
      {
        indexed: false,
        internalType: 'uint256',
        name: 'precisions',
        type: 'uint256'
      }
    ],
    name: 'TokenFreeze',
    type: 'event'
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: 'uint32',
        name: 'assetGuid',
        type: 'uint32'
      },
      {
        indexed: false,
        internalType: 'address',
        name: 'erc20ContractAddress',
        type: 'address'
      }
    ],
    name: 'TokenRegistry',
    type: 'event'
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: 'uint32',
        name: 'assetGuid',
        type: 'uint32'
      },
      {
        indexed: false,
        internalType: 'address',
        name: 'receipient',
        type: 'address'
      },
      {
        indexed: false,
        internalType: 'uint256',
        name: 'value',
        type: 'uint256'
      }
    ],
    name: 'TokenUnfreeze',
    type: 'event'
  },
  {
    inputs: [{ internalType: 'uint32', name: '', type: 'uint32' }],
    name: 'assetBalances',
    outputs: [{ internalType: 'uint256', name: '', type: 'uint256' }],
    stateMutability: 'view',
    type: 'function'
  },
  {
    inputs: [{ internalType: 'uint32', name: '', type: 'uint32' }],
    name: 'assetRegistry',
    outputs: [
      {
        internalType: 'address',
        name: 'erc20ContractAddress',
        type: 'address'
      },
      { internalType: 'uint64', name: 'height', type: 'uint64' },
      { internalType: 'uint8', name: 'precision', type: 'uint8' }
    ],
    stateMutability: 'view',
    type: 'function'
  },
  {
    inputs: [],
    name: 'trustedRelayerContract',
    outputs: [{ internalType: 'address', name: '', type: 'address' }],
    stateMutability: 'view',
    type: 'function'
  },
  {
    inputs: [{ internalType: 'uint256', name: 'txHash', type: 'uint256' }],
    name: 'wasSyscoinTxProcessed',
    outputs: [{ internalType: 'bool', name: '', type: 'bool' }],
    stateMutability: 'view',
    type: 'function'
  },
  {
    inputs: [
      { internalType: 'uint256', name: 'txHash', type: 'uint256' },
      { internalType: 'uint256', name: 'value', type: 'uint256' },
      {
        internalType: 'address',
        name: 'destinationAddress',
        type: 'address'
      },
      { internalType: 'uint32', name: 'assetGuid', type: 'uint32' }
    ],
    name: 'processTransaction',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function'
  },
  {
    inputs: [
      { internalType: 'uint256', name: '_txHash', type: 'uint256' },
      { internalType: 'uint32', name: '_assetGuid', type: 'uint32' },
      { internalType: 'uint64', name: '_height', type: 'uint64' },
      {
        internalType: 'address',
        name: '_erc20ContractAddress',
        type: 'address'
      },
      { internalType: 'uint8', name: '_precision', type: 'uint8' }
    ],
    name: 'processAsset',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function'
  },
  {
    inputs: [
      { internalType: 'uint256', name: 'value', type: 'uint256' },
      { internalType: 'uint32', name: 'assetGuid', type: 'uint32' },
      {
        internalType: 'string',
        name: 'syscoinAddress',
        type: 'string'
      }
    ],
    name: 'freezeBurnERC20',
    outputs: [{ internalType: 'bool', name: '', type: 'bool' }],
    stateMutability: 'payable',
    type: 'function'
  }
];
