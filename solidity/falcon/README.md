# Bindings Go and javascript

This repository provides binding in Go and javascript of the NIST source files.


## Javascript bindings

### Install Emscripten (emsdk)
Emscripten is a complete compiler toolchain to WebAssembly, using LLVM. It is required to execute the make ```js target```.

 ```bash
git clone https://github.com/emscripten-core/emsdk.git
cd emsdk
./emsdk install latest
./emsdk activate latest
source ./emsdk_env.sh
 ```


### Compile and test

 ```bash
 make js
 node test_falcon.js
 ```
A reference example of use (key generation, sign and verify) is provided in test_falcon.js, it corresponds to the solidity test vector.



### Interact with the smart contracts 

Use deterministic_falcon_sign to deterministically generate a key pair from seed and sign. Input are the 32 bytes seed and the hexadecimal value of the hash of the message to sign.
 ```bash
Usage: deterministic_falcon_sign.js <32_byte_seed_hex> <message_hex_with_0x_prefix> [--output-signature-only | --output-publickey-only]
 ```

Output only the public key (second argument is useless but shall be provided):

 ```bash
node deterministic_falcon_sign.js 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 0x50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750 --output-publickey-only
 ```

Then, using the same seed, use it to produce signature for messages

 ```bash
node deterministic_falcon_sign.js 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 0x50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750 --output-signature-only
 ```

## Go bindings

 ```bash
 make go
go run falcon.go
 ```