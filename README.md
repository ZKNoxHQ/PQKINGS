# PQKINGS

<p align="center">
  <img src="(https://github.com/user-attachments/assets/9604a015-7487-4bd8-bee2-5ac7fa395432" alt="The PQ King" width="350"/>
</p>
<p align="center">
  <small>(The PQ KING)</small>
</p>



Got it, here's the improved README in Markdown format, ready for you to copy and paste:

-----

# ETHPRAGUE 7702 Hybrid Account (Legacy + Post-Quantum)

### Protecting Your Ethereum Accounts from Quantum Threats

-----

## 🚀 Description

This project demonstrates a groundbreaking **Ethereum Smart Account** that offers **Hybrid Cryptography protection** for your assets. Leveraging the new **EIP-7702** standard, we integrate both traditional **ECDSA (Legacy)** and cutting-edge **Post-Quantum (PQ) FALCON** signing capabilities.

Our unique demonstration at ETHPRAGUE turns everyday **wristbands** into secure Ethereum signers using their embedded ARX chips. While a secure screen is important, we believe the more imminent threat is the rapid advancement of **Quantum Computing**. Our solution ensures your account remains secure even against future quantum attacks by combining the best of both cryptographic worlds.

-----

## ✨ What Will Be Demonstrated

Attendees will witness:

  * **Wristband-as-Signer:** How ETHPRAGUE wristbands, powered by ARX chips, function as direct Ethereum transaction signers.
  * **Post-Quantum Resilience:** The integration of a **FALCON512 Post-Quantum signer** within a **7702 Smart Account**, showcasing practical quantum resistance.
  * **Hybrid Security:** A practical implementation of a hybrid account protecting funds with both legacy (ECDSA) and post-quantum cryptography.

-----

## 🛠️ How It Works

Our solution builds upon the new EIP-7702 standard to create a flexible smart account. When a transaction needs to be signed:

1.  **Wristband Interaction:** The wristband's ARX chip securely generates a signature using its embedded key.
2.  **Post-Quantum Signing:** The signature is then processed with the FALCON post-quantum algorithm (via JavaScript integration).
3.  **Hybrid Verification (On-Chain):** The `ZKNOX_hybrid.sol` smart contract on Ethereum verifies both the traditional ECDSA signature (from the wristband) and the FALCON post-quantum signature. This dual-verification ensures the account is protected against both classical and quantum-era threats.

-----

## ⚙️ Installation & Setup

To interact with this demonstration and set up your environment:

### **1. Wristband Communication (Local Machine)**

The wristband communicates with your laptop via NFC.

  * **HALO Library:** Install the necessary `HALO` library on your laptop.
  * **NFC Application:** Use `TagInfo` (or similar NFC communication software) to establish communication with the wristband.

### **2. Post-Quantum FALCON JavaScript**

The JavaScript implementation of the FALCON algorithm, generated from NIST code using Emscripten, is crucial for off-chain post-quantum signing.

  * **Location:** You'll find the generated JavaScript file at `solidity/falcon/test_falcon.js`.

### **3. Solidity Smart Contracts**

The core smart contracts are located in a fork of the `ZKNOX/ETHFALCON` repository.

  * **Repository:** This repository was forked specifically for the ETHPRAGUE hackathon.
  * **Dedicated README:** For detailed setup and contract information, please refer to the [dedicated README in the `ZKNOX/ETHFALCON` fork](https://www.google.com/search?q=%5Bhttps://github.com/ZKNoxHQ/PQKINGS%5D\(https://github.com/ZKNoxHQ/PQKINGS\)).

-----

## 📖 APIs

### **JavaScript FALCON Signer**

The JavaScript module for the FALCON algorithm provides the following key functions:

  * `crypto_keypair(pkPtr, skPtr, seedPtr)`
      * **Input:** A 32-byte seed.
      * **Output:** Generates a `(publicKey, secretKey)` pair for the NIST FALCON512 algorithm.
  * `falcon._crypto_sign(signedMsgPtr, signedMsgLenPtr, msgPtr, BigInt(message.length), skPtr)`
      * **Input:** Pointers to the message, its length, and the generated secret key.
      * **Output:** The `signedMsg` and its `length`.
  * `falcon._crypto_sign_open(recoveredMsgPtr, recoveredLenPtr, signedMsgPtr, BigInt(sigLen), pkPtr)`
      * **Input:** Pointers to the message and signature.
      * **Output:** Returns `0` if the verification succeeded.

### **Solidity Contracts**

  * `ZKNOX_hybrid.sol`: This contract orchestrates the **hybridation** of the FALCON post-quantum signature verification with standard ECDSA verification, forming the core of the hybrid smart account logic.
