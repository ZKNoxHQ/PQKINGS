#deploy precomputed tables for falcon field

#deployment script
#!/bin/bash

# Configuration
# Replace with your contract name
#DeployETHFalcon.s.sol, DeployFalcon.s.sol
CONTRACT_NAME="DeployEPERVIER.s.sol"

# Deploy to networks
echo "Deploying $CONTRACT_NAME with Forge..."
#!/bin/bash

# Configuration

#list of mainnet RPC
RPC_OPTIMISM="https://mainnet.optimism.io"
RPC_POL="https://polygon.llamarpc.com"
RPC_L1="https://eth.llamarpc.com"

#list of testnet RPC, please update if required, PR welcomed
RPC_SEPOLIAOPTIMISM="https://sepolia.optimism.io"
RPC_LINEASEPOLIA="wss://linea-sepolia-rpc.publicnode.com"
RPC_L1SEPOLIA="wss://ethereum-sepolia-rpc.publicnode.com"
RPC_POLYAMOY="https://polygon-amoy.drpc.org"
RPC_SCROLLSEPOLIA="wss://scroll-sepolia-rpc.publicnode.com "
RPC_ARBITRUMSEPOLIA="https://api.zan.top/arb-sepolia"
RPC_BASESEPOLIA="wss://base-sepolia-rpc.publicnode.com"
RPC_HOLESKYMAIN="https://ethereum-holesky-rpc.publicnode.com"
RPC_ZKSYNCSEPOLIA="https://sepolia.era.zksync.dev"
RPC_MEKONG="https://rpc.mekong.ethpandaops.io"


#your APIKEY to verify contract
API_KEY_ETHERSCAN="3YA7ZVB1F1MRGP9EFDZ6H37NAZWVTRU59H"
API_KEY_OPTIMISM="KRBYUQF6YN4U78B4ZPJI6H9GJARI59IWV6"
#selected API KEY
API_KEY=$API_KEY_ETHERSCAN
LINEA_KEY_ETHERSCAN="93H7P72W4KM16VPVTJECGCSQRXYE4MR211"
BASE_APIKEY="2MB5R271I8FGMKJ2757C3S7FDXSSYTE6NN"
OPTIMISM_APIKEY="KRBYUQF6YN4U78B4ZPJI6H9GJARI59IWV6"
#selected RPC

RPC_HOLESKYMAIN="https://ethereum-holesky-rpc.publicnode.com"
RPC=$RPC_SEPOLIAOPTIMISM
# Deploy to networks
echo "RPC used: "$RPC
echo "balance:"




#forge script $CONTRACT_NAME --rpc-url $RPC --private-key $PRIVATE_KEY --broadcast --tc Script_Deploy_Falcon --etherscan-api-key $API_KEY --verify --priority-gas-price 1

forge script $CONTRACT_NAME --rpc-url $RPC --ledger --broadcast --tc Script_Deploy_epervier --etherscan-api-key $OPTIMISM_APIKEY --verify 
