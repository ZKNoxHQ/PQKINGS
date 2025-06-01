import Button from "./Button.tsx";
import {execHaloCmdWeb} from "@arx-research/libhalo/api/web";
import {computeAddress, JsonRpcProvider} from "ethers";
import {EIP155_CHAINS} from "../logic/EIP155Chains";

import { createSmartAccountClient } from "permissionless"
import { createPimlicoClient } from "permissionless/clients/pimlico"
import { http, createPublicClient, zeroAddress, encodeFunctionData, parseEther, hashTypedData, encodeAbiParameters, parseSignature } from "viem"
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts"
import { sepolia } from "viem/chains"
import { toSimpleSmartAccount } from "permissionless/accounts"
import { entryPoint08Address, getUserOperationTypedData } from "viem/account-abstraction"
import { hashAuthorization } from "ethers/hash";
import { Falcon } from "../falcon.js"

const TEST_CHAIN_ID = "eip155:11155111"
let hasCode = "";

const pimlicoUrl = "https://api.pimlico.io/v2/11155111/rpc?apikey=";
const pimlicoSponsorshipPolicyId = "sp_flashy_vector";
const sepoliaUrl = "https://ethereum-sepolia-rpc.publicnode.com";
//const testContractAddress = "0x82a3A6d204D722fF995A2fcb48a276241eebaAB0"
const testContractAddress = "0xA95a2AE978e5A46e8bBC4d1c1e48cCc2CeA3b613"
const testAddressSecondary = "0xBB8c3211951fa6225E6B90CFDD80aD9444052D81";
const testPrivateKeySecondary = ""
const abi = [
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "secondary",
          "type": "address"
        }
      ],
      "name": "initSecondary",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    }    
]
const testPrivateKey = "";
const testDestinationAddress = "0xC50c53CC0b661A7521a675ae88D9dC7a3C99eCe1"

const falconContract = "0x13b79503ED87a507551160a9E57FdBf46e6Fa444";
const iPQPublicKeyContract = "0xeAb06b810F3ECa9f3D00bad3Fd286A04ab03B3Db";
const falconDelegateContract = "0xfC61433f7D8ddc8D2Ac8AB79c10539A2Abb7a491";
const falconShakeId = 0x216840110134321;
const pqSeed = "";
const abiInitFalconDelegate = [
{
    "inputs": [
      {
        "internalType": "uint256",
        "name": "iAlgoID",
        "type": "uint256"
      },
      {
        "internalType": "address",
        "name": "iCore",
        "type": "address"
      },
      {
        "internalType": "address",
        "name": "iAuthorized_ECDSA",
        "type": "address"
      },
      {
        "internalType": "address",
        "name": "iPublicPQKey",
        "type": "address"
      }
    ],
    "name": "initialize",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  }    
]

function PrePairing({haloAddress, haloCode, onGetHalo, onGetHaloCode, onStartPairing, onResetWallet}) {

    function btnPair() {
        onStartPairing();
    }

    function btnResetWallet() {
        onResetWallet();
    }

    async function btnDelegateTest() {

        const privateKey = generatePrivateKey()
        console.log("Using private key " + privateKey);

 const publicClient = createPublicClient({
        chain: sepolia,
        transport: http(sepoliaUrl)
    })

    const pimlicoClient = createPimlicoClient({
        transport: http(pimlicoUrl)
    })

    const owner = privateKeyToAccount(privateKey)

    console.log(`Owner address: ${owner.address}`)

    const simpleSmartAccount = await toSimpleSmartAccount({
        owner,
        entryPoint: {
            address: entryPoint08Address,
            version: "0.8"
        },
        client: publicClient,
        address: owner.address
    })

    console.log(`Smart account address: ${simpleSmartAccount.address}`)

    // Create the smart account client
    const smartAccountClient = createSmartAccountClient({
        account: simpleSmartAccount,
        chain: sepolia,
        bundlerTransport: http(pimlicoUrl),
        paymaster: pimlicoClient,
        userOperation: {
            estimateFeesPerGas: async () => {
                return (await pimlicoClient.getUserOperationGasPrice()).fast
            }
        }
    })

    const factoryData = encodeFunctionData({
        abi: abi,
        functionName: "initSecondary",
        args: [ testAddressSecondary ]                
    })

    const userOp = await smartAccountClient.prepareUserOperation({
        calls: [
            {
                to: zeroAddress,
                data: "0x",
                //value: BigInt(0)
                value: 0
            }
        ],
        paymasterContext: {
            sponsorshipPolicyId: pimlicoSponsorshipPolicyId
        },
        factory: '0x7702',
        factoryData: factoryData,
        authorization: await owner.signAuthorization({
            contractAddress: testContractAddress,
            //contractAddress: "0xe6Cae83BdE06E4c305530e199D7217f42808555B",
            chainId: sepolia.id,
            nonce: 0
        })
    })

    console.log("User Operation:")
    console.log(userOp)

    const userOpHash = await smartAccountClient.sendUserOperation({
        ...userOp,
        signature: await simpleSmartAccount.signUserOperation(userOp)
    })

    console.log("User Operation Hash:")
    console.log(userOpHash)

    const transactionHash =
        await smartAccountClient.waitForUserOperationReceipt({
            hash: userOpHash
        })

    console.log("Transaction Hash:")
    console.log(transactionHash.receipt.transactionHash)

    }

    async function btnSend() {
        const privateKey = testPrivateKey;
        console.log("Using private key " + privateKey);

 const publicClient = createPublicClient({
        chain: sepolia,
        transport: http(sepoliaUrl)
    })

    const pimlicoClient = createPimlicoClient({
        transport: http(pimlicoUrl)
    })

    const owner = privateKeyToAccount(privateKey)

    console.log(`Owner address: ${owner.address}`)

    const simpleSmartAccount = await toSimpleSmartAccount({
        owner,
        entryPoint: {
            address: entryPoint08Address,
            version: "0.8"
        },
        client: publicClient,
        address: owner.address
    })

    console.log(`Smart account address: ${simpleSmartAccount.address}`)

    // Create the smart account client
    const smartAccountClient = createSmartAccountClient({
        account: simpleSmartAccount,
        chain: sepolia,
        bundlerTransport: http(pimlicoUrl),
        paymaster: pimlicoClient,
        userOperation: {
            estimateFeesPerGas: async () => {
                return (await pimlicoClient.getUserOperationGasPrice()).fast
            }
        }
    })

    const userOp = await smartAccountClient.prepareUserOperation({
        calls: [
            {
                to: testDestinationAddress,
                data: "0x",
                value: parseEther('0.0001')
            }
        ],
        paymasterContext: {
            sponsorshipPolicyId: pimlicoSponsorshipPolicyId
        },
    })

    console.log("User Operation:")
    console.log(userOp)

    const userOpHash = await smartAccountClient.sendUserOperation({
        ...userOp,
        signature: await simpleSmartAccount.signUserOperation(userOp)
    })

    console.log("User Operation Hash:")
    console.log(userOpHash)

    const transactionHash =
        await smartAccountClient.waitForUserOperationReceipt({
            hash: userOpHash
        })

    console.log("Transaction Hash:")
    console.log(transactionHash.receipt.transactionHash)

    }

    async function btnSendAcc2() {
        const privateKey = testPrivateKey;
        console.log("Using private key " + privateKey);

 const publicClient = createPublicClient({
        chain: sepolia,
        transport: http(sepoliaUrl)
    })

    const pimlicoClient = createPimlicoClient({
        transport: http(pimlicoUrl)
    })

    const owner = privateKeyToAccount(privateKey)

    console.log(`Owner address: ${owner.address}`)

    const simpleSmartAccount = await toSimpleSmartAccount({
        owner,
        entryPoint: {
            address: entryPoint08Address,
            version: "0.8"
        },
        client: publicClient,
        address: owner.address
    })

    console.log(`Smart account address: ${simpleSmartAccount.address}`)

    // Create the smart account client
    const smartAccountClient = createSmartAccountClient({
        account: simpleSmartAccount,
        chain: sepolia,
        bundlerTransport: http(pimlicoUrl),
        paymaster: pimlicoClient,
        userOperation: {
            estimateFeesPerGas: async () => {
                return (await pimlicoClient.getUserOperationGasPrice()).fast
            }
        }
    })

    const userOp = await smartAccountClient.prepareUserOperation({
        calls: [
            {
                to: testDestinationAddress,
                data: "0x",
                value: parseEther('0.0001')
            }
        ],
        paymasterContext: {
            sponsorshipPolicyId: pimlicoSponsorshipPolicyId
        },
    })

    console.log("User Operation:")
    console.log(userOp)

    console.log(simpleSmartAccount)

    //simpleSmartAccount.owner = privateKeyToAccount(testPrivateKeySecondary)
    //simpleSmartAccount.owner = privateKeyToAccount(generatePrivateKey())

    const owner2 = privateKeyToAccount(testPrivateKeySecondary)
    const simpleSmartAccount2 = await toSimpleSmartAccount({
        owner: owner2,
        entryPoint: {
            address: entryPoint08Address,
            version: "0.8"
        },
        client: publicClient,
        address: owner2.address
    })


    const userOpHash = await smartAccountClient.sendUserOperation({
        ...userOp,
        signature: await simpleSmartAccount2.signUserOperation(userOp)
    })

    console.log("User Operation Hash:")
    console.log(userOpHash)

    const transactionHash =
        await smartAccountClient.waitForUserOperationReceipt({
            hash: userOpHash
        })

    console.log("Transaction Hash:")
    console.log(transactionHash.receipt.transactionHash)

    }

    async function btnDelegatePQ() {

        const privateKey = generatePrivateKey()
        console.log("Using private key " + privateKey);

 const publicClient = createPublicClient({
        chain: sepolia,
        transport: http(sepoliaUrl)
    })

    const pimlicoClient = createPimlicoClient({
        transport: http(pimlicoUrl)
    })

    const owner = privateKeyToAccount(privateKey)

    console.log(`Owner address: ${owner.address}`)

    const simpleSmartAccount = await toSimpleSmartAccount({
        owner,
        entryPoint: {
            address: entryPoint08Address,
            version: "0.8"
        },
        client: publicClient,
        address: owner.address
    })

    console.log(`Smart account address: ${simpleSmartAccount.address}`)

    // Create the smart account client
    const smartAccountClient = createSmartAccountClient({
        account: simpleSmartAccount,
        chain: sepolia,
        bundlerTransport: http(pimlicoUrl),
        paymaster: pimlicoClient,
        userOperation: {
            estimateFeesPerGas: async () => {
                return (await pimlicoClient.getUserOperationGasPrice()).fast
            }
        }
    })

    const factoryData = encodeFunctionData({
        abi: abiInitFalconDelegate,
        functionName: "initialize",
        args: [ falconShakeId, falconContract, owner.address, iPQPublicKeyContract ]                
    })

    const authorization = {
        address: falconDelegateContract,
        chainId: sepolia.id,
        nonce: 0        
    }
    const authorizationHash = hashAuthorization(authorization)
    console.log(authorizationHash);


    const userOp = await smartAccountClient.prepareUserOperation({
        calls: [
            {
                to: zeroAddress,
                data: "0x",
                //value: BigInt(0)
                value: 0
            }
        ],
        paymasterContext: {
            sponsorshipPolicyId: pimlicoSponsorshipPolicyId
        },
        factory: '0x7702',
        factoryData: factoryData,
        paymasterVerificationGasLimit: 5000000,
        preVerificationGas : 5000000,
        verificationGasLimit : 5000000,
        authorization: await owner.signAuthorization({
            contractAddress: falconDelegateContract,
            chainId: sepolia.id,
            nonce: 0
        })
    })

    console.log("User Operation:")
    console.log(userOp)

    console.log("Signature direct " + await simpleSmartAccount.signUserOperation(userOp));
    const typedData = getUserOperationTypedData({
        chainId: publicClient.chain.id,
        entryPointAddress: entryPoint08Address,
        userOperation: {
            ...userOp,
            sender: await simpleSmartAccount.getAddress()
        }
    })
    const typedDataHash = hashTypedData(typedData);
    console.log("Typed Data hash " + typedDataHash)
    console.log("Signature side 1 " + await owner.signTypedData(typedData))

    const pqSignature = await falconSign(pqSeed, typedDataHash)
    console.log("PQ signature " + pqSignature)

    const signature1 = parseSignature(await simpleSmartAccount.signUserOperation(userOp))
    console.log(signature1)
    const signatureFull = encodeAbiParameters(
        [
            { name: 'v', type: 'uint8' },
            { name: 'r', type: 'bytes32' },
            { name: 's', type: 'bytes32' },
            { name: 'pq', type: 'bytes' }
        ],
        [ signature1.v, signature1.r, signature1.s, pqSignature ]
    )

    const userOpHash = await smartAccountClient.sendUserOperation({
        ...userOp,
        signature: signatureFull
    })

    console.log("User Operation Hash:")
    console.log(userOpHash)

    const transactionHash =
        await smartAccountClient.waitForUserOperationReceipt({
            hash: userOpHash
        })

    console.log("Transaction Hash:")
    console.log(transactionHash.receipt.transactionHash)

    }


    async function btnDelegate() {

        const privateKey = generatePrivateKey()
        console.log("Using private key " + privateKey);

 const publicClient = createPublicClient({
        chain: sepolia,
        transport: http(sepoliaUrl)
    })

    const pimlicoClient = createPimlicoClient({
        transport: http(pimlicoUrl)
    })

    const owner = privateKeyToAccount(privateKey)
    owner.address = haloAddress;

    console.log(`Owner address: ${owner.address}`)

    const simpleSmartAccount = await toSimpleSmartAccount({
        owner,
        entryPoint: {
            address: entryPoint08Address,
            version: "0.8"
        },
        client: publicClient,
        address: owner.address
    })

    console.log(`Smart account address: ${simpleSmartAccount.address}`)

    // Create the smart account client
    const smartAccountClient = createSmartAccountClient({
        account: simpleSmartAccount,
        chain: sepolia,
        bundlerTransport: http(pimlicoUrl),
        paymaster: pimlicoClient,
        userOperation: {
            estimateFeesPerGas: async () => {
                return (await pimlicoClient.getUserOperationGasPrice()).fast
            }
        }
    })

    const factoryData = encodeFunctionData({
        abi: abiInitFalconDelegate,
        functionName: "initialize",
        args: [ falconShakeId, falconContract, owner.address, iPQPublicKeyContract ]                
    })

    const authorization = {
        address: falconDelegateContract,
        chainId: sepolia.id,
        nonce: 0        
    }
    const authorizationHash = hashAuthorization(authorization)

        let res;

        try {
            res = await execHaloCmdWeb({
                "name": "sign",
                "keyNo": 1,
                "digest": authorizationHash.substring(2)
            });
        } catch (e) {
            alert(e);
            throw e;
        }

    const signatureAuthorization = parseSignature(res.signature.ether);

    const userOp = await smartAccountClient.prepareUserOperation({
        calls: [
            {
                to: zeroAddress,
                data: "0x",
                //value: BigInt(0)
                value: 0
            }
        ],
        paymasterContext: {
            sponsorshipPolicyId: pimlicoSponsorshipPolicyId
        },
        factory: '0x7702',
        factoryData: factoryData,
        paymasterVerificationGasLimit: 5000000,
        preVerificationGas : 5000000,
        verificationGasLimit : 5000000,
        authorization: {
            ...authorization,
            ...signatureAuthorization
        }
    })

    console.log("User Operation:")
    console.log(userOp)

    const typedData = getUserOperationTypedData({
        chainId: publicClient.chain.id,
        entryPointAddress: entryPoint08Address,
        userOperation: {
            ...userOp,
            sender: await simpleSmartAccount.getAddress()
        }
    })
    const typedDataHash = hashTypedData(typedData);

        try {
            res = await execHaloCmdWeb({
                "name": "sign",
                "keyNo": 1,
                "digest": typedDataHash.substring(2)
            });
        } catch (e) {
            alert(e);
            throw e;
        }

    const signature1 = parseSignature(res.signature.ether);

    const pqSignature = await falconSign(pqSeed, typedDataHash)
    console.log("PQ signature " + pqSignature)

    console.log(signature1)
    const signatureFull = encodeAbiParameters(
        [
            { name: 'v', type: 'uint8' },
            { name: 'r', type: 'bytes32' },
            { name: 's', type: 'bytes32' },
            { name: 'pq', type: 'bytes' }
        ],
        [ signature1.v, signature1.r, signature1.s, pqSignature ]
    )

    const userOpHash = await smartAccountClient.sendUserOperation({
        ...userOp,
        signature: signatureFull
    })

    console.log("User Operation Hash:")
    console.log(userOpHash)

    const transactionHash =
        await smartAccountClient.waitForUserOperationReceipt({
            hash: userOpHash
        })

    console.log("Transaction Hash:")
    console.log(transactionHash.receipt.transactionHash)

    }



  async function btnUndelegate() {


        const privateKey = generatePrivateKey()
        console.log("Using private key " + privateKey);

 const publicClient = createPublicClient({
        chain: sepolia,
        transport: http(sepoliaUrl)
    })

    const pimlicoClient = createPimlicoClient({
        transport: http(pimlicoUrl)
    })

    const owner = privateKeyToAccount(privateKey)
    owner.address = haloAddress;

    console.log(`Owner address: ${owner.address}`)

    const simpleSmartAccount = await toSimpleSmartAccount({
        owner,
        entryPoint: {
            address: entryPoint08Address,
            version: "0.8"
        },
        client: publicClient,
        address: owner.address
    })

    console.log(`Smart account address: ${simpleSmartAccount.address}`)

    // Create the smart account client
    const smartAccountClient = createSmartAccountClient({
        account: simpleSmartAccount,
        chain: sepolia,
        bundlerTransport: http(pimlicoUrl),
        paymaster: pimlicoClient,
        userOperation: {
            estimateFeesPerGas: async () => {
                return (await pimlicoClient.getUserOperationGasPrice()).fast
            }
        }
    })

    const authorization = {
        address: "0x0000000000000000000000000000000000000000",
        chainId: sepolia.id,
        nonce: await publicClient.getTransactionCount({ address : haloAddress })        
    }
    const authorizationHash = hashAuthorization(authorization)

        let res;

        try {
            res = await execHaloCmdWeb({
                "name": "sign",
                "keyNo": 1,
                "digest": authorizationHash.substring(2)
            });
        } catch (e) {
            alert(e);
            throw e;
        }

    const signatureAuthorization = parseSignature(res.signature.ether);


try {

    const userOp = await smartAccountClient.prepareUserOperation({
        calls: [
            {
                to: zeroAddress,
                data: "0x",
                //value: BigInt(0)
                value: 0
            }
        ],
        paymasterContext: {
            sponsorshipPolicyId: pimlicoSponsorshipPolicyId
        },
        factory: '0x0000000000000000000000000000000000000000',
        factoryData: '0x',        
        paymasterVerificationGasLimit: 5000000,
        preVerificationGas : 5000000,
        verificationGasLimit : 5000000,
        authorization: {
            ...authorization,
            ...signatureAuthorization
        }
    })
} catch(e) {
    alert(e);
    return;
}


    console.log("User Operation:")
    console.log(userOp)

    const typedData = getUserOperationTypedData({
        chainId: publicClient.chain.id,
        entryPointAddress: entryPoint08Address,
        userOperation: {
            ...userOp,
            sender: await simpleSmartAccount.getAddress()
        }
    })
    const typedDataHash = hashTypedData(typedData);

        try {
            res = await execHaloCmdWeb({
                "name": "sign",
                "keyNo": 1,
                "digest": typedDataHash.substring(2)
            });
        } catch (e) {
            alert(e);
            throw e;
        }

    const signature1 = parseSignature(res.signature.ether);

    const pqSignature = await falconSign(pqSeed, typedDataHash)
    console.log("PQ signature " + pqSignature)

    console.log(signature1)
    const signatureFull = encodeAbiParameters(
        [
            { name: 'v', type: 'uint8' },
            { name: 'r', type: 'bytes32' },
            { name: 's', type: 'bytes32' },
            { name: 'pq', type: 'bytes' }
        ],
        [ signature1.v, signature1.r, signature1.s, pqSignature ]
    )

    const userOpHash = await smartAccountClient.sendUserOperation({
        ...userOp,
        signature: signatureFull
    })

    console.log("User Operation Hash:")
    console.log(userOpHash)

    const transactionHash =
        await smartAccountClient.waitForUserOperationReceipt({
            hash: userOpHash
        })

    console.log("Transaction Hash:")
    console.log(transactionHash.receipt.transactionHash)


    }

    function testFalcon() {
Falcon().then((falcon) => {
  const pkLen = 897;
  const skLen = 1281;
  const sigMaxLen = 690;
  const seedLen= 32;

  const seed=Buffer.from("12345678123456781234567812345679")

  const hexString = "0x50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750";

 // Remove the "0x" prefix before passing to Buffer.from
 const message = Buffer.from(hexString.slice(2), "hex");

  // Allocate memory
  const pkPtr = falcon._malloc(pkLen);
  const skPtr = falcon._malloc(skLen);
  const msgPtr = falcon._malloc(message.length);
  const seedPtr= falcon._malloc(seedLen);

  falcon.HEAPU8.set(message, msgPtr);
  falcon.HEAPU8.set(seed, seedPtr);

  // Generate keypair, no seed
  //falcon.ccall(
  //  'crypto_sign_keypair',
  //  'number',
  //  ['number', 'number'],
  //  [pkPtr, skPtr]
  //);

  falcon.ccall(
     'crypto_keypair',
      'number',
      ['number', 'number'],
      [pkPtr, skPtr, seedPtr]
  );
  

  console.log("🔑 Message (hex):", message.toString("hex")); // optional hex output


  const secretKey = Buffer.from(falcon.HEAPU8.subarray(pkPtr, skPtr + skLen));
  console.log("🔑 Secret Key (hex):", secretKey.toString("hex")); // optional hex output


  const publicKey = Buffer.from(falcon.HEAPU8.subarray(pkPtr, pkPtr + pkLen));
  console.log("🔑 Public Key (base64):", publicKey.toString("base64"));
  console.log("🔑 Public Key (hex):", publicKey.toString("hex")); // optional hex output

  // Sign the message manually (avoid ccall due to long long*)
  const signedMsgMaxLen = message.length + sigMaxLen;
  const signedMsgPtr = falcon._malloc(signedMsgMaxLen);
  const signedMsgLenPtr = falcon._malloc(8); // 64-bit space

  const signRet = falcon._crypto_sign(
    signedMsgPtr,
    signedMsgLenPtr,
    msgPtr,
    BigInt(message.length), // <== THIS FIXES IT
    skPtr
  );

  if (signRet !== 0) {
    console.error("❌ Signing failed.");
    return;
  }

  // Read 64-bit signature length (low + high)
  function readUint64(ptr) {
    const low = falcon.HEAPU32[ptr >> 2];
    const high = falcon.HEAPU32[(ptr >> 2) + 1];
    return BigInt(high) << 32n | BigInt(low);
  }

  const sigLen = Number(readUint64(signedMsgLenPtr));
  const signedMessage = Buffer.from(falcon.HEAPU8.subarray(signedMsgPtr, signedMsgPtr + sigLen));

  console.log("✅ Signature generated.");
  console.log("🔐 Sig+Msg (base64):", signedMessage.toString("base64"));
  console.log("🔐 Sig+Msg (hexa):", signedMessage.toString("hex"));

  // Verify the message
  const recoveredMsgPtr = falcon._malloc(sigLen);
  const recoveredLenPtr = falcon._malloc(8);

  const verifyRet = falcon._crypto_sign_open(
  recoveredMsgPtr,
  recoveredLenPtr,
  signedMsgPtr,
  BigInt(sigLen), // <== HERE TOO
  pkPtr
);

  if (verifyRet === 0) {
    const recLen = Number(readUint64(recoveredLenPtr));
    const recoveredMessage = Buffer.from(falcon.HEAPU8.subarray(recoveredMsgPtr, recoveredMsgPtr + recLen));
    console.log("✅ Verification success.");
    console.log("📦 Recovered message:", recoveredMessage.toString());
    console.log("🧪 Match:", message.equals(recoveredMessage));
  } else {
    console.error("❌ Signature verification failed.");
  }

  // Free memory
  [pkPtr, skPtr, msgPtr, signedMsgPtr, signedMsgLenPtr, recoveredMsgPtr, recoveredLenPtr]
    .forEach(ptr => falcon._free(ptr));
});        
    }

  async function falconSign(seedHexInput, messageHexInput) {

    const seed = Buffer.from(seedHexInput, "hex");
    const message = Buffer.from(messageHexInput.startsWith("0x") ? messageHexInput.slice(2) : messageHexInput, "hex");

// --- Main FALCON Module execution ---
return Falcon().then((falcon) => {
  const pkLen = 897;
  const skLen = 1281;
  const sigMaxLen = 690;
  const seedLen = 32;

  // Allocate memory for key pair
  const pkPtr = falcon._malloc(pkLen);
  const skPtr = falcon._malloc(skLen);
  const seedPtr = falcon._malloc(seedLen);

  falcon.HEAPU8.set(seed, seedPtr);

  // Generate keypair using the provided seed
  falcon.ccall(
    'crypto_keypair',
    'number',
    ['number', 'number', 'number'],
    [pkPtr, skPtr, seedPtr]
  );

  const publicKey = Buffer.from(falcon.HEAPU8.subarray(pkPtr, pkPtr + pkLen));

  // --- Normal / Signature Output Path ---
  // Allocate memory for message
  const msgPtr = falcon._malloc(message.length);
  falcon.HEAPU8.set(message, msgPtr);


  // Conditional console logs for human readability
      console.log("🔑 Message (hex):", message.toString("hex"));
      const secretKey = Buffer.from(falcon.HEAPU8.subarray(skPtr, skPtr + skLen));
      console.log("🔑 Secret Key (hex):", secretKey.toString("hex"));
      console.log("🔑 Public Key (base64):", publicKey.toString("base64"));
      console.log("🔑 Public Key (hex):", publicKey.toString("hex")); // Full output includes hex PK


  // Sign the message
  const signedMsgMaxLen = message.length + sigMaxLen;
  const signedMsgPtr = falcon._malloc(signedMsgMaxLen);
  const signedMsgLenPtr = falcon._malloc(8); // 64-bit space

  const signRet = falcon._crypto_sign(
    signedMsgPtr,
    signedMsgLenPtr,
    msgPtr,
    BigInt(message.length),
    skPtr
  );

  if (signRet !== 0) {
    console.error("❌ Signing failed.");
    // Free memory before exiting on error
    [pkPtr, skPtr, msgPtr, seedPtr, signedMsgPtr, signedMsgLenPtr].forEach(ptr => falcon._free(ptr));
    return;
  }

  // Read 64-bit signature length (low + high)
  function readUint64(ptr) {
    const low = falcon.HEAPU32[ptr >> 2];
    const high = falcon.HEAPU32[(ptr >> 2) + 1];
    return BigInt(high) << 32n | BigInt(low);
  }

  const sigLen = Number(readUint64(signedMsgLenPtr));
  const signedMessage = Buffer.from(falcon.HEAPU8.subarray(signedMsgPtr, signedMsgPtr + sigLen));

      console.log("✅ Signature generated.");
      console.log("🔐 Sig+Msg (base64):", signedMessage.toString("base64"));

      console.log(signedMessage.toString("hex"));

  // Free all remaining memory
  [pkPtr, skPtr, msgPtr, seedPtr, signedMsgPtr, signedMsgLenPtr]
    .forEach(ptr => falcon._free(ptr));

  return "0x" + signedMessage.toString("hex");
  }
)}

  async function btnGetHalo() {
      let addr;

      let pkeys;

      try {
        pkeys = await execHaloCmdWeb({
            "name": "get_pkeys"
        });
      } catch (e) {
        alert(e.toString());
        return;
      }

      addr = computeAddress('0x' + pkeys.publicKeys[1]);
      onGetHalo(addr)

      const provider = new JsonRpcProvider(EIP155_CHAINS[TEST_CHAIN_ID].rpc);
      try {
        let code = await provider.getCode(addr);
        onGetHaloCode(code)
      } catch (e) {
        alert(e.toString());
        return;
      }
   }

    let displayedAddress = haloAddress;
    if (!haloAddress) {
        displayedAddress = "None"
    }
    
    return (
        <div>
            <div style={{marginBottom: '40px'}}>
                <p className={"label-text"}>
                    Active HaLo tag:
                </p>
                <p style={{textTransform: 'none', color: 'white', fontFamily: 'monospace', fontSize: 12}}>
                    {displayedAddress}
                </p>
            </div>
            <Button onClick={() => btnPair()} fullWidth={true} className={"btn-pad"}>Scan QR code</Button>
            {!haloAddress ? 
                <Button onClick={() => btnGetHalo()} fullWidth={true} className={"btn-pad"}>Scan Wallet</Button> :
                <Button onClick={() => btnResetWallet()} fullWidth={true} className={"btn-pad"}>Reset Wallet</Button> 
            }
            {haloAddress ? haloCode == "0x" ?
                <Button onClick={() => btnDelegate()} fullWidth={true} className={"btn-pad"}>Delegate Wallet</Button> :
                <Button onClick={() => btnUndelegate()} fullWidth={true} className={"btn-pad"}>Remove Delegate</Button>              
              : ""
            }
            <Button onClick={() => btnDelegateTest()} fullWidth={true} className={"btn-pad"}>TEST DELEGATE</Button>                
            <Button onClick={() => btnSend()} fullWidth={true} className={"btn-pad"}>TEST SEND</Button>
            <Button onClick={() => btnSendAcc2()} fullWidth={true} className={"btn-pad"}>TEST SEND ACC 2</Button>          
            <Button onClick={() => btnDelegatePQ()} fullWidth={true} className={"btn-pad"}>TEST DELEGATE PQ</Button>
            <Button onClick={() => testFalcon()} fullWidth={true} className={"btn-pad"}>SELF TEST FALCON</Button>
        </div>
    );
}

export default PrePairing;

