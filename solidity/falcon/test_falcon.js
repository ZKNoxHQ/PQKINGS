const fs = require('fs');
const Module = require('./falcon.js');

Module().then((falcon) => {
  const pkLen = 897;
  const skLen = 1281;
  const sigMaxLen = 690;
  const seedLen= 32;

  const message = Buffer.from("hello from ZKNOX!");
  const seed=Buffer.from("12345678123456781234567812345679")

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
