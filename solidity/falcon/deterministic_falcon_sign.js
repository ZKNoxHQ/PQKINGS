// Filename: test_falcon.js (modified)

const fs = require('fs');
const Module = require('./falcon.js'); // Ensure falcon.js is in the same directory

// --- Get arguments from command line ---
// Expected usage:
//   node test_falcon.js <32_byte_seed_hex> <message_hex_with_0x_prefix>
//   node test_falcon.js <32_byte_seed_hex> <message_hex_with_0x_prefix> --output-signature-only
//   node test_falcon.js <32_byte_seed_hex> <message_hex_with_0x_prefix> --output-publickey-only

const args = process.argv.slice(2);

let seedHexInput;
let messageHexInput;
let outputSignatureOnly = false;
let outputPublicKeyOnly = false;

// Basic argument parsing
if (args.length < 2 || args.length > 3) {
  console.error("Usage: node test_falcon.js <32_byte_seed_hex> <message_hex_with_0x_prefix> [--output-signature-only | --output-publickey-only]");
  process.exit(1);
}

seedHexInput = args[0];
messageHexInput = args[1];

if (args.length === 3) {
    if (args[2] === "--output-signature-only") {
        outputSignatureOnly = true;
    } else if (args[2] === "--output-publickey-only") {
        outputPublicKeyOnly = true;
    } else {
        console.error("Error: Invalid third argument. Use '--output-signature-only' or '--output-publickey-only' or omit it.");
        process.exit(1);
    }
}

// Ensure flags are mutually exclusive
if (outputSignatureOnly && outputPublicKeyOnly) {
    console.error("Error: Cannot use both '--output-signature-only' and '--output-publickey-only' simultaneously.");
    process.exit(1);
}

// Validate seed length (must be 32 bytes = 64 hex characters)
if (seedHexInput.length !== 64) {
    console.error("Error: Seed must be 32 bytes (64 hex characters).");
    process.exit(1);
}

// Convert seed and message hex strings to Buffers
const seed = Buffer.from(seedHexInput, "hex");
const message = Buffer.from(messageHexInput.startsWith("0x") ? messageHexInput.slice(2) : messageHexInput, "hex");

// --- Main FALCON Module execution ---
Module().then((falcon) => {
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

  if (outputPublicKeyOnly) {
      // --- CRUCIAL LINE FOR PUBLIC KEY EXTRACTION ---
      console.log(publicKey.toString("hex"));
      // Free memory before exiting
      [pkPtr, skPtr, seedPtr].forEach(ptr => falcon._free(ptr));
      return; // Exit script after outputting public key
  }

  // --- Normal / Signature Output Path ---
  // Allocate memory for message
  const msgPtr = falcon._malloc(message.length);
  falcon.HEAPU8.set(message, msgPtr);


  // Conditional console logs for human readability
  if (!outputSignatureOnly) { // This means either no flag or --output-publickey-only was NOT set
      console.log("🔑 Message (hex):", message.toString("hex"));
      const secretKey = Buffer.from(falcon.HEAPU8.subarray(skPtr, skPtr + skLen));
      console.log("🔑 Secret Key (hex):", secretKey.toString("hex"));
      console.log("🔑 Public Key (base64):", publicKey.toString("base64"));
      console.log("🔑 Public Key (hex):", publicKey.toString("hex")); // Full output includes hex PK
  }


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
    process.exit(1); // Exit with error code
  }

  // Read 64-bit signature length (low + high)
  function readUint64(ptr) {
    const low = falcon.HEAPU32[ptr >> 2];
    const high = falcon.HEAPU32[(ptr >> 2) + 1];
    return BigInt(high) << 32n | BigInt(low);
  }

  const sigLen = Number(readUint64(signedMsgLenPtr));
  const signedMessage = Buffer.from(falcon.HEAPU8.subarray(signedMsgPtr, signedMsgPtr + sigLen));

  if (!outputSignatureOnly) {
      console.log("✅ Signature generated.");
      console.log("🔐 Sig+Msg (base64):", signedMessage.toString("base64"));
  }

  // --- CRUCIAL LINE FOR SIGNATURE EXTRACTION (when outputSignatureOnly is true) ---
  // When outputSignatureOnly is true, this is the ONLY output
  if (outputSignatureOnly) {
      console.log(signedMessage.toString("hex"));
  }


  // Verify the message
  if (!outputSignatureOnly) { // Only verify if not in "signature only" mode
      const recoveredMsgPtr = falcon._malloc(sigLen); // Max length of recovered message is sigLen (signed message length)
      const recoveredLenPtr = falcon._malloc(8);

      const verifyRet = falcon._crypto_sign_open(
        recoveredMsgPtr,
        recoveredLenPtr,
        signedMsgPtr,
        BigInt(sigLen),
        pkPtr
      );

      if (verifyRet === 0) {
        const recLen = Number(readUint64(recoveredLenPtr));
        const recoveredMessage = Buffer.from(falcon.HEAPU8.subarray(recoveredMsgPtr, recoveredMsgPtr + recLen));
        console.log("✅ Verification success.");
        console.log("📦 Recovered message (hex):", recoveredMessage.toString("hex"));
        console.log("🧪 Match:", message.equals(recoveredMessage));
      } else {
        console.error("❌ Signature verification failed.");
      }

      // Free memory for verification parts
      [recoveredMsgPtr, recoveredLenPtr].forEach(ptr => falcon._free(ptr));
  }

  // Free all remaining memory
  [pkPtr, skPtr, msgPtr, seedPtr, signedMsgPtr, signedMsgLenPtr]
    .forEach(ptr => falcon._free(ptr));

}).catch(error => {
  console.error("An error occurred during FALCON module initialization or execution:", error);
  process.exit(1); // Exit with error code
});