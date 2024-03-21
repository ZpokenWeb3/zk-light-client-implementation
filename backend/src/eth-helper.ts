import Web3 from 'web3';
import { Transaction, TxData } from 'ethereumjs-tx';

const web3 = new Web3('https://goerli.infura.io/v3/f4c46e6e91514ef38f4b4c7375917003');

const contractAddress = '0x63F526335DB8458c76914BdBD88F0A97E1B6b157';
const contractABI = [
  {
    inputs: [{ internalType: 'address', name: 'verifier', type: 'address' }],
    stateMutability: 'nonpayable',
    type: 'constructor',
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: 'uint256[4]',
        name: 'input',
        type: 'uint256[4]',
      },
      {
        indexed: false,
        internalType: 'uint256[4]',
        name: 'compressedProof',
        type: 'uint256[4]',
      },
    ],
    name: 'CompressedProofVerifiedAndSaved',
    type: 'event',
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: 'uint256[4]',
        name: 'input',
        type: 'uint256[4]',
      },
      {
        indexed: false,
        internalType: 'uint256[8]',
        name: 'proof',
        type: 'uint256[8]',
      },
    ],
    name: 'ProofVerifiedAndSaved',
    type: 'event',
  },
  {
    inputs: [],
    name: '_verifier',
    outputs: [{ internalType: 'contract IVerifier', name: '', type: 'address' }],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [{ internalType: 'uint256[2]', name: 'input', type: 'uint256[2]' }],
    name: 'isProofed',
    outputs: [{ internalType: 'bool', name: '', type: 'bool' }],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [{ internalType: 'bytes', name: 'hash', type: 'bytes' }],
    name: 'isProofedHash',
    outputs: [{ internalType: 'bool', name: '', type: 'bool' }],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [],
    name: 'owner',
    outputs: [{ internalType: 'address', name: '', type: 'address' }],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [{ internalType: 'address', name: 'verifier', type: 'address' }],
    name: 'setVerifier',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [{ internalType: 'uint256[2]', name: 'array', type: 'uint256[2]' }],
    name: 'toHash',
    outputs: [{ internalType: 'bytes', name: '', type: 'bytes' }],
    stateMutability: 'pure',
    type: 'function',
  },
  {
    inputs: [
      { internalType: 'uint256[4]', name: 'input', type: 'uint256[4]' },
      {
        internalType: 'uint256[4]',
        name: 'proof',
        type: 'uint256[4]',
      },
    ],
    name: 'verifyAndSaveCompressedProof',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [
      { internalType: 'uint256[4]', name: 'input', type: 'uint256[4]' },
      {
        internalType: 'uint256[8]',
        name: 'proof',
        type: 'uint256[8]',
      },
    ],
    name: 'verifyAndSaveProof',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
];
const contract = new web3.eth.Contract(contractABI, contractAddress);

const privateKey = process.env.PRIVATE_KEY as string;

const web3Account = web3.eth.accounts.privateKeyToAccount('0x' + privateKey);

export const executeContractCall = async (input: string[], proof: string[]) => {
  const txObject: TxData = {
    nonce: '0x' + (await web3.eth.getTransactionCount(web3Account.address)).toString(16),
    to: contractAddress,
    gasPrice: web3.utils.toHex(await web3.eth.getGasPrice()),
    gasLimit: web3.utils.toHex(300000),
    value: '0x0',
    data: contract.methods.verifyAndSaveProof(input, proof).encodeABI(),
  };

  const tx = new Transaction(txObject, { chain: 'goerli' });

  const privateKeyBuffer = Buffer.from(privateKey, 'hex');
  tx.sign(privateKeyBuffer);

  const serializedTx = tx.serialize().toString('hex');

  try {
    const receipt = await web3.eth.sendSignedTransaction('0x' + serializedTx);
    console.log('Transaction receipt:', receipt);
  } catch (error) {
    console.error('Transaction error:', error);
  }
};
