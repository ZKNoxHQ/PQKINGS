# PQKINGS

<p align="center">
<img src="[../../../../../images/pectra.png](https://github.com/user-attachments/assets/9cc3feef-405e-4003-afbc-5d7730ff0326)" alt="drawing" class="center" width="350"/>
<p align="center">
<small>(The PQ KING)</small>


ETHPRAGUE 7702 Hybrid Account ( Legacy + Post Quantum)

## DESCRIPTION

## WHAT WILL BE DEMONSTRATED

The ETHPRAGUE wristbands are turned into Ethereum signers using the ARX chip it contains. It has been decided that the major threat is not the lack of secure screen but rather the Quantum 
Computer that will be shipped next week (or a bit later). To resist the threat, a Post Quantum signer is added into a 7702 smart account, providing Hybrid Cryptography protection.

## HOW DOES IT WORKS

## INSTALLATION

- The communication between the wrist and the labtop requires [HALO library](https://github.com/arx-research/libhalo) installed on the labtop, and an application to communicate via NFC. For this we used [TagInfo](https://play.google.com/store/apps/details?id=com.nxp.taginfolite&hl=fr).
- The javascript for the post quantum FALCON algorithm has been generated from NIST code, using Emscripten and is available in solidity/falcon/test_falcon.js
- The solidity repository is a fork from [ZKNOX/ETHFALCON](https://github.com/ZKNoxHQ/ETHFALCON) repository has been forked for the hackathon. The dedicated README is here.




## APIs

### Javascript falcon signer
The javascript implements the following functions:
- crypto_keypair(pkPtr, skPtr, seedPtr) takes as input a 32 bytes seed and generate a (publickey, secretKey) couple for the NIST FALCON512 algorithm
- falcon._crypto_sign(
    signedMsgPtr,
    signedMsgLenPtr,
    msgPtr,
    BigInt(message.length), 
    skPtr
  ); takes as input pointers on the msg, its length, and the generated secret key, and output the signedMsg and its length
- falcon._crypto_sign_open(
  recoveredMsgPtr,
  recoveredLenPtr,
  signedMsgPtr,
  BigInt(sigLen), 
  pkPtr
);
takes as input pointers on the msg, and signatures , and return 0 if the verification succeeded. 

### Solidity

The ZKNOX_hybrid.sol contracts operates the hybridation of FALCON with ECDSA.

## DEPLOYMENTS
