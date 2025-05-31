// first install npm install ethers
import { Wallet, hashMessage, recoverAddress, SigningKey, sha256 } from "ethers";

// --- Get arguments from command line ---
// Expected usage: node your_script_name.js <32_byte_seed_hex> <message_string>
const args = process.argv.slice(2); // Slice to get only the actual arguments

if (args.length < 2) {
  console.error("Usage: node your_script_name.js <32_byte_seed_hex> <message_string>");
  process.exit(1);
}

const deterministicSeedInput = args[0];
const message = args[1]; // The message is now taken directly from the second argument

// Validate seed length (must be 32 bytes = 64 hex characters)
if (deterministicSeedInput.length !== 64 || !/^[0-9a-fA-F]{64}$/.test(deterministicSeedInput)) {
    console.error("Error: Seed must be a 32-byte (64 hex characters) hexadecimal string.");
    process.exit(1);
}

// Prepend "0x" if it's not there, as ethers.sha256 typically expects it or a Uint8Array
const deterministicSeed = deterministicSeedInput.startsWith("0x") ? deterministicSeedInput : "0x" + deterministicSeedInput;

async function signMessage() {
    // Derive the private key deterministically from the seed using SHA256
    const privateKey = sha256(deterministicSeed);

    // Create a Wallet instance from the derived private key
    const wallet = new Wallet(privateKey);

    const messageHash = hashMessage(message);
    const signature = await wallet.signMessage(message);
    const recoveredAddress = recoverAddress(messageHash, signature);

    // Helper to parse the signature
    function parseSignature(signature) {
      const sig = signature.startsWith("0x") ? signature.slice(2) : signature;
      return {
        r: "0x" + sig.slice(0, 64),
        s: "0x" + sig.slice(64, 128),
        v: parseInt(sig.slice(128, 130), 16),
      };
    }
    const sig = parseSignature(signature);

    const signingKey = new SigningKey(wallet.privateKey);
    const publicKey = signingKey.publicKey;

    // Extract X and Y coordinates from the uncompressed public key
    const x = "0x" + publicKey.slice(4, 68); // Slice from index 4 to 68 for X (skipping 0x04 prefix)
    const y = "0x" + publicKey.slice(68);   // Slice from index 68 to end for Y

    console.log("Message:         ", message);
    console.log("Input Seed (hex):", deterministicSeedInput);
    console.log("Derived Private Key:", privateKey);
    console.log("Wallet Address:  ", wallet.address);
    console.log("Message Hash:    ", messageHash);
    console.log("Signature:       ", signature);
    console.log("r (signature):   ", sig.r);
    console.log("s (signature):   ", sig.s);
    console.log("v (signature):   ", sig.v);
    console.log("Public Key (uncompressed):", publicKey); // The full 0x04... key
    console.log("Public Key X:    ", x);
    console.log("Public Key Y:    ", y);
    console.log("Recovered Addr:  ", recoveredAddress);
}

signMessage(); // Call the async function

console.log("ending script...");