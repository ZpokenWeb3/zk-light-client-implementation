import Web3 from 'web3';
import {encode} from 'bs58';
import {base58toHex} from "./near-helper";

const web3 = new Web3(process.env.SEPOLIA_RPC || 'http://127.0.0.1:8545/');

const contractAddress =
  process.env.NEAR_BLOCK_VERIFIER_CONTRACT || '0x4ed7c70F96B99c776995fB64377f0d4aB3B0e1C1';
const contractABI = [
  {
    "inputs": [],
    "name": "EnforcedPause",
    "type": "error"
  },
  {
    "inputs": [],
    "name": "ExpectedPause",
    "type": "error"
  },
  {
    "inputs": [],
    "name": "InvalidInitialization",
    "type": "error"
  },
  {
    "inputs": [],
    "name": "NotInitializing",
    "type": "error"
  },
  {
    "inputs": [
      {
        "internalType": "address",
        "name": "owner",
        "type": "address"
      }
    ],
    "name": "OwnableInvalidOwner",
    "type": "error"
  },
  {
    "inputs": [
      {
        "internalType": "address",
        "name": "account",
        "type": "address"
      }
    ],
    "name": "OwnableUnauthorizedAccount",
    "type": "error"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": false,
        "internalType": "uint64",
        "name": "version",
        "type": "uint64"
      }
    ],
    "name": "Initialized",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "internalType": "address",
        "name": "previousOwner",
        "type": "address"
      },
      {
        "indexed": true,
        "internalType": "address",
        "name": "newOwner",
        "type": "address"
      }
    ],
    "name": "OwnershipTransferred",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": false,
        "internalType": "address",
        "name": "account",
        "type": "address"
      }
    ],
    "name": "Paused",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "internalType": "bytes",
        "name": "input",
        "type": "bytes"
      },
      {
        "indexed": false,
        "internalType": "bytes",
        "name": "proof",
        "type": "bytes"
      }
    ],
    "name": "ProofVerifiedAndSaved",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": false,
        "internalType": "address",
        "name": "account",
        "type": "address"
      }
    ],
    "name": "Unpaused",
    "type": "event"
  },
  {
    "inputs": [
      {
        "internalType": "uint64",
        "name": "height",
        "type": "uint64"
      }
    ],
    "name": "getEpochHashesByHeight",
    "outputs": [
      {
        "internalType": "bytes32",
        "name": "previousHash",
        "type": "bytes32"
      },
      {
        "internalType": "bytes32",
        "name": "currentHash",
        "type": "bytes32"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "getLatestCheckpoint",
    "outputs": [
      {
        "internalType": "uint64",
        "name": "",
        "type": "uint64"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "getVerifier",
    "outputs": [
      {
        "internalType": "contract IRiscZeroVerifier",
        "name": "",
        "type": "address"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "address",
        "name": "verifier",
        "type": "address"
      },
      {
        "internalType": "uint64",
        "name": "height",
        "type": "uint64"
      },
      {
        "internalType": "bytes32",
        "name": "previousHash",
        "type": "bytes32"
      },
      {
        "internalType": "bytes32",
        "name": "currentHash",
        "type": "bytes32"
      },
      {
        "internalType": "bytes32",
        "name": "imageID",
        "type": "bytes32"
      }
    ],
    "name": "initialize",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "bytes",
        "name": "input",
        "type": "bytes"
      }
    ],
    "name": "isProofed",
    "outputs": [
      {
        "internalType": "bool",
        "name": "",
        "type": "bool"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "bytes32",
        "name": "hash",
        "type": "bytes32"
      }
    ],
    "name": "isProofedHash",
    "outputs": [
      {
        "internalType": "bool",
        "name": "",
        "type": "bool"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "owner",
    "outputs": [
      {
        "internalType": "address",
        "name": "",
        "type": "address"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "pause",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "paused",
    "outputs": [
      {
        "internalType": "bool",
        "name": "",
        "type": "bool"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "renounceOwnership",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "bytes32",
        "name": "previousHash",
        "type": "bytes32"
      },
      {
        "internalType": "bytes32",
        "name": "currentHash",
        "type": "bytes32"
      },
      {
        "internalType": "uint64",
        "name": "height",
        "type": "uint64"
      }
    ],
    "name": "saveEpochHashesAndSetCheckpoint",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "bytes32",
        "name": "imageID",
        "type": "bytes32"
      }
    ],
    "name": "setImageID",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "address",
        "name": "verifier",
        "type": "address"
      }
    ],
    "name": "setVerifier",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "address",
        "name": "newOwner",
        "type": "address"
      }
    ],
    "name": "transferOwnership",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "unpause",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "bytes",
        "name": "journal",
        "type": "bytes"
      },
      {
        "internalType": "bytes",
        "name": "proof",
        "type": "bytes"
      }
    ],
    "name": "verifyAndSaveProof",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  }
];
const contract = new web3.eth.Contract(contractABI, contractAddress);

const privateKey = process.env.PRIVATE_KEY as string;

const web3Account = web3.eth.accounts.privateKeyToAccount('0x' + privateKey);

export const getLatestCheckpointFromContract = async (): Promise<number> => {
  try {
    const heightCheckpoint = await contract.methods.getLatestCheckpoint().call();
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-expect-error
    return parseInt(heightCheckpoint);
  } catch (error) {
    console.error('Error calling getLatestCheckpoint:', error);
    throw error;
  }
}

export const getEpochHashesByHeight = async (height: number): Promise<{ previousHashSaved: string, currentHashSaved: string }> => {
  try {
    const result = await contract.methods.getEpochHashesByHeight(height).call();

    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-expect-error
    const { previousHash, currentHash } = result;

    const previousHashBase58 = hexToBase58(previousHash);
    const currentHashBase58 = hexToBase58(currentHash);

    console.log('Previous Hash:', previousHashBase58);
    console.log('Current Hash:', currentHashBase58);

    return {
      previousHashSaved: previousHashBase58,
      currentHashSaved: currentHashBase58,
    };
  } catch (error) {
    console.error('Error calling getEpochHashesByHeight:', error);
    throw error;
  }
};

export const saveEpochHashesAndSetCheckpoint = async (previousHash: string, currentHash: string, height: number) => {
  try {
    const previousHashHex = '0x' + base58toHex(previousHash);
    const currentHashHex = '0x' + base58toHex(currentHash);
    const signedTx = await web3.eth.accounts.signTransaction(
        {
          from: web3Account.address,
          to: contractAddress,
          gas: await contract.methods
              .saveEpochHashesAndSetCheckpoint(previousHashHex, currentHashHex, height)
              .estimateGas({ from: web3Account.address }),
          gasPrice: await web3.eth.getGasPrice(),
          nonce: '0x' + (await web3.eth.getTransactionCount(web3Account.address)).toString(16),
          data: contract.methods.saveEpochHashesAndSetCheckpoint(previousHashHex, currentHashHex, height).encodeABI(),
        },
        privateKey,
    );
    const receipt = await web3.eth.sendSignedTransaction(signedTx.rawTransaction as string);
    console.log('Epoch saving transaction successful, receipt:', receipt);
  } catch (error) {
    console.error('Error calling saveEpochHashesAndSetCheckpoint:', error);
    throw error;
  }
};

export const hexToBase58 = (hex: string): string => {
  const buffer = Buffer.from(hex.replace(/^0x/, ''), 'hex');
  return encode(buffer);
};


export const executeProofSaving = async (input: string, proof: string) => {
  const signedTx = await web3.eth.accounts.signTransaction(
    {
      from: web3Account.address,
      to: contractAddress,
      gas: 1000000,
      gasPrice: 1000000000,
      nonce: '0x' + (await web3.eth.getTransactionCount(web3Account.address)).toString(16),
      data: contract.methods.verifyAndSaveProof(input, proof).encodeABI(),
    },
    privateKey,
  );
  try {
    const receipt = await web3.eth.sendSignedTransaction(signedTx.rawTransaction);
    console.log('Transaction receipt:', receipt);
  } catch (error) {
    console.error('Transaction error:', error);
    throw Error(error);
  }
};
