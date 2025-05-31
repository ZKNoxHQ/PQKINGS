const fs = require('fs');
const Module = require('./falcon.js');

// --- Get arguments from command line ---
// Expected usage: node test_falcon.js <32_byte_seed_hex> <message_hex_with_0x_prefix>
const args = process.argv.slice(2); // Slice to get only the actual arguments

if (args.length < 2) {
  console.error("Usage: node test_falcon.js <32_byte_seed_hex> <message_hex_with_0x_prefix>");
  process.exit(1);
}

const seedHexInput = args[0];
const messageHexInput = args[1];

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
  const seedLen = 32; // This is now enforced by input validation

  // Allocate memory
  const pkPtr = falcon._malloc(pkLen);
  const skPtr = falcon._malloc(skLen);
  const msgPtr = falcon._malloc(message.length);
  const seedPtr = falcon._malloc(seedLen);

  falcon.HEAPU8.set(message, msgPtr);
  falcon.HEAPU8.set(seed, seedPtr);

  // Generate keypair using the provided seed
  falcon.ccall(
    'crypto_keypair',
    'number',
    ['number', 'number', 'number'],
    [pkPtr, skPtr, seedPtr]
  );

  console.log("🔑 Message (hex):", message.toString("hex"));

  // The secretKey and publicKey are extracted from WASM memory.
  // Note: The secretKey buffer here might include padding or other data
  // depending on how crypto_keypair lays out data. For actual use,
  // ensure you know the exact layout if you need to store/retrieve it.
  const secretKey = Buffer.from(falcon.HEAPU8.subarray(skPtr, skPtr + skLen));
  console.log("🔑 Secret Key (hex):", secretKey.toString("hex"));

  const publicKey = Buffer.from(falcon.HEAPU8.subarray(pkPtr, pkPtr + pkLen));
  console.log("🔑 Public Key (base64):", publicKey.toString("base64"));
  console.log("🔑 Public Key (hex):", publicKey.toString("hex"));

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
  console.log("🔐 Sig+Msg (hexa):", signedMessage.toString("hex"));

  // Verify the message
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

  // Free memory
  [pkPtr, skPtr, msgPtr, seedPtr, signedMsgPtr, signedMsgLenPtr, recoveredMsgPtr, recoveredLenPtr]
    .forEach(ptr => falcon._free(ptr));
}).catch(error => {
  console.error("An error occurred during FALCON module initialization or execution:", error);
});
