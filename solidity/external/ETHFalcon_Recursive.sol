//This is a fork from https://github.com/Tetration-Lab/falcon-solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {NTT} from "./NTT_Recursive.sol";
import {Test, console} from "forge-std/Test.sol";
import "../src/ZKNOX_HashToPoint.sol"; // Tetration implementation is used here

contract ETHFalcon {
   
    NTT ntt;

    struct Signature {
        bytes salt;
        int256[] s1;
    }

    struct FalconRecover_sig {
        bytes r;
        uint256[] s1;
        uint256[] s2;
        uint256[] ntts2m1;
    }

    constructor() {
        ntt = new NTT();
    }

    function verify(
        bytes memory msgs,
        Signature memory signature,
        uint256[] memory h // public key
    ) public view returns (address ret) {
        require(h.length == 512, "Invalid public key length");
        require(signature.s1.length == 512, "Invalid signature length");
        uint256[] memory s1 = new uint256[](512);
        for (uint256 i = 0; i < 512; i++) {
            if (signature.s1[i] < 0) {
                s1[i] = uint256(int256(q) + signature.s1[i]);
            } else {
                s1[i] = uint256(signature.s1[i]);
            }
        }
        uint256[] memory hashed = hashToPointTETRATION(signature.salt, msgs);
        uint256[] memory s0 = ntt.subZQ(hashed, ntt.mulZQ(s1, h));
       
        // normalize s0 // to positive cuz you'll **2 anyway?
        for (uint256 i = 0; i < n; i++) {
            if (s0[i] > qs1) {
                s0[i] = q - s0[i];
            } else {
                s0[i] = s0[i];
            }
        }

        // normalize s1
        for (uint256 i = 0; i < n; i++) {
            if (s1[i] > qs1) {
                s1[i] = q - s1[i];
            } else {
                s1[i] = s1[i];
            }
        }

        uint256 norm = 0;
        for (uint256 i = 0; i < n; i++) {
            norm += s0[i] * s0[i];
            norm += s1[i] * s1[i];
        }
        require(norm < sigBound, "Signature is invalid");
        return (address(0));
    }

    //a version optimized by precomputing the NTT for of the public key
    function verify_nttpub(
        bytes memory msgs,
        Signature memory signature,
        uint256[] memory ntt_h // public key, ntt form
    ) public view returns (address ret) {
        require(ntt_h.length == 512, "Invalid public key length");
        require(signature.s1.length == 512, "Invalid signature length");
        uint256[] memory s1 = new uint256[](512);
        for (uint256 i = 0; i < 512; i++) {
            if (signature.s1[i] < 0) {
                s1[i] = uint256(int256(q) + signature.s1[i]);
            } else {
                s1[i] = uint256(signature.s1[i]);
            }
        }
        uint256[] memory hashed = hashToPointTETRATION(signature.salt, msgs);
        uint256[] memory s0 = ntt.subZQ(hashed, ntt.mulZQ_opt(s1, ntt_h));
      
        // normalize s0 // to positive cuz you'll **2 anyway?
        for (uint256 i = 0; i < n; i++) {
            if (s0[i] > qs1) {
                s0[i] = q - s0[i];
            } else {
                s0[i] = s0[i];
            }
        }
        // normalize s1
        for (uint256 i = 0; i < n; i++) {
            if (s1[i] > qs1) {
                s1[i] = q - s1[i];
            } else {
                s1[i] = s1[i];
            }
        }
        uint256 norm = 0;
        for (uint256 i = 0; i < n; i++) {
            norm += s0[i] * s0[i];
            norm += s1[i] * s1[i];
        }
        require(norm < sigBound, "Signature is invalid");
        return (address(0));
    }


}
