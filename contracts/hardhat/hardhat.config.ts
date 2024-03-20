import { config } from 'dotenv'
import "@nomicfoundation/hardhat-toolbox";

config()

export default {
  defaultNetwork: 'hardhat',
  networks: {
    hardhat: {
      allowUnlimitedContractSize: true,
//       forking: {
//         enabled: true,
//         url: `https://mainnet.infura.io/v3/${process.env.INFURA_API_KEY}`,
//       },
    },
    goerli: {
      url: 'https://rpc.ankr.com/eth_goerli',
      accounts: process.env.PRIVATE_KEY !== undefined ? [process.env.PRIVATE_KEY] : [],
    },
  },

  solidity: {
    compilers: [
      {
        version: '0.8.20',
        settings: {
          optimizer: {
            enabled: true,
            runs: 200,
          }
        },
      },
    ],
  },
}
