/**
 *
 */
/*ZZZZZZZZZZZZZZZZZZZKKKKKKKKK    KKKKKKKNNNNNNNN        NNNNNNNN     OOOOOOOOO     XXXXXXX       XXXXXXX                         ..../&@&#.       .###%@@@#, ..
/*Z:::::::::::::::::ZK:::::::K    K:::::KN:::::::N       N::::::N   OO:::::::::OO   X:::::X       X:::::X                      ...(@@* .... .           &#//%@@&,.
/*Z:::::::::::::::::ZK:::::::K    K:::::KN::::::::N      N::::::N OO:::::::::::::OO X:::::X       X:::::X                    ..*@@.........              .@#%%(%&@&..
/*Z:::ZZZZZZZZ:::::Z K:::::::K   K::::::KN:::::::::N     N::::::NO:::::::OOO:::::::OX::::::X     X::::::X                   .*@( ........ .  .&@@@@.      .@%%%%%#&@@.
/*ZZZZZ     Z:::::Z  KK::::::K  K:::::KKKN::::::::::N    N::::::NO::::::O   O::::::OXXX:::::X   X::::::XX                ...&@ ......... .  &.     .@      /@%%%%%%&@@#
/*        Z:::::Z      K:::::K K:::::K   N:::::::::::N   N::::::NO:::::O     O:::::O   X:::::X X:::::X                   ..@( .......... .  &.     ,&      /@%%%%&&&&@@@.
/*       Z:::::Z       K::::::K:::::K    N:::::::N::::N  N::::::NO:::::O     O:::::O    X:::::X:::::X                   ..&% ...........     .@%(#@#      ,@%%%%&&&&&@@@%.
/*      Z:::::Z        K:::::::::::K     N::::::N N::::N N::::::NO:::::O     O:::::O     X:::::::::X                   ..,@ ............                 *@%%%&%&&&&&&@@@.
/*     Z:::::Z         K:::::::::::K     N::::::N  N::::N:::::::NO:::::O     O:::::O     X:::::::::X                  ..(@ .............             ,#@&&&&&&&&&&&&@@@@*
/*    Z:::::Z          K::::::K:::::K    N::::::N   N:::::::::::NO:::::O     O:::::O    X:::::X:::::X                   .*@..............  . ..,(%&@@&&&&&&&&&&&&&&&&@@@@,
/*   Z:::::Z           K:::::K K:::::K   N::::::N    N::::::::::NO:::::O     O:::::O   X:::::X X:::::X                 ...&#............. *@@&&&&&&&&&&&&&&&&&&&&@@&@@@@&
/*ZZZ:::::Z     ZZZZZKK::::::K  K:::::KKKN::::::N     N:::::::::NO::::::O   O::::::OXXX:::::X   X::::::XX               ...@/.......... *@@@@. ,@@.  &@&&&&&&@@@@@@@@@@@.
/*Z::::::ZZZZZZZZ:::ZK:::::::K   K::::::KN::::::N      N::::::::NO:::::::OOO:::::::OX::::::X     X::::::X               ....&#..........@@@, *@@&&&@% .@@@@@@@@@@@@@@@&
/*Z:::::::::::::::::ZK:::::::K    K:::::KN::::::N       N:::::::N OO:::::::::::::OO X:::::X       X:::::X                ....*@.,......,@@@...@@@@@@&..%@@@@@@@@@@@@@/
/*Z:::::::::::::::::ZK:::::::K    K:::::KN::::::N        N::::::N   OO:::::::::OO   X:::::X       X:::::X                   ...*@,,.....%@@@,.........%@@@@@@@@@@@@(
/*ZZZZZZZZZZZZZZZZZZZKKKKKKKKK    KKKKKKKNNNNNNNN         NNNNNNN     OOOOOOOOO     XXXXXXX       XXXXXXX                      ...&@,....*@@@@@ ..,@@@@@@@@@@@@@&.
/*                                                                                                                                   ....,(&@@&..,,,/@&#*. .
/*                                                                                                                                    ......(&.,.,,/&@,.
/*                                                                                                                                      .....,%*.,*@%
/*                                                                                                                                    .#@@@&(&@*,,*@@%,..
/*                                                                                                                                    .##,,,**$.,,*@@@@@%.
/*                                                                                                                                     *(%%&&@(,,**@@@@@&
/*                                                                                                                                      . .  .#@((@@(*,**
/*                                                                                                                                             . (*. .
/*                                                                                                                                              .*/
///* Copyright (C) 2025 - Renaud Dubois, Simon Masson - This file is part of ZKNOX project
///* License: This software is licensed under MIT License
///* This Code may be reused including this header, license and copyright notice.
///* See LICENSE file at the root folder of the project.
///* FILE: ZKNOX_falcon.sol
///* Description: Compute NIST compliant falcon verification
/**
 *
 */
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {IEntryPoint} from "../lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "./ZKNOX_HashToPoint.sol";

import "./ZKNOX_IVerifier.sol";
import "./ZKNOX_common.sol";
import "./ZKNOX_falcon_core.sol";

//choose the XOF to use here
import "./ZKNOX_falcon_encodings.sol";
import "./ZKNOX_falcon_utils.sol";

import { console } from "forge-std/Test.sol";
import {IValidator} from "../lib/kernel/src/interfaces/IERC7579Modules.sol";

import {SIG_VALIDATION_SUCCESS_UINT, SIG_VALIDATION_FAILED_UINT} from "../lib/kernel/src/types/Constants.sol";
import {ZKNOX_NTT} from "./ZKNOX_NTT.sol";
import {PackedUserOperation} from "../lib/kernel/src/interfaces/PackedUserOperation.sol";

/// @notice Contract designed for being delegated to by EOAs to authorize a IVerifier key to transact on their behalf.
contract ZKNOX_ZeroDev_Kernel_Module is IValidator {

    // TODO: remove after testing
    function helloWorld() external {
        console.log("hello world!");
    }

    error InvalidCaller();

    bytes32 constant SIMPLEHYBRID7702_STORAGE_POSITION = keccak256("zknox.hybrid.7702");

    // address of entryPoint v0.8
    function entryPoint() public pure returns (IEntryPoint) {
        return IEntryPoint(0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108);
    }

    struct Storage {
        //derived address from ecdsa
        address authorized_ECDSA;

        /// @notice Address of the contract storing the post quantum public key
        address authorized_PQPublicKey;
        /// @notice Address of the verification contract logic

        address CoreAddress; //address of the core verifier (FALCON, DILITHIUM, etc.), shall be the address of a ISigVerifier
        uint256 algoID;
    }

    function getStorage() internal pure returns (Storage storage ds) {
        bytes32 position = SIMPLEHYBRID7702_STORAGE_POSITION;
        assembly {
            ds.slot := position
        }
    }

    constructor() {}

    //input are AlgoIdentifier, Signature verification address, publickey storing contract
    function initialize(uint256 iAlgoID, address iCore, address iAuthorized_ECDSA, address iPublicPQKey) external {
        /*  TODO: uncomment!
        if (msg.sender != address(entryPoint().senderCreator())) {
            revert InvalidCaller();
        }
        */
        if (getStorage().CoreAddress != address(0)) {
            revert AlreadyInitialized(iPublicPQKey);
        }

        getStorage().authorized_ECDSA=iAuthorized_ECDSA;  //derived address from ecdsa secp256K1
        getStorage().CoreAddress = iCore; // Address of contract of Signature verification (FALCON, DILITHIUM)
        getStorage().algoID = iAlgoID;
        getStorage().authorized_PQPublicKey = iPublicPQKey;
    }

    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal virtual returns (uint256 validationData) {
        (uint8 v, bytes32 r, bytes32 s, bytes memory sm) = abi.decode(userOp.signature, (uint8, bytes32, bytes32, bytes));
        bytes32 h = 0x50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750;//the hash signed by FALCON NIST and ECDSA, provided by etherjs for ECDSA and test_falcon.js for falcon

//        TODO: the plan is to use EIP-191 message hash as input of both ECDSA and Falcon
//        bytes message = abi.encodePacked("\x19Ethereum Signed Message:\n", userOpHash);
//        bytes32 h1 = keccak256(message);
//        return isValid(userOpHash, v, r, s, sm) ? SIG_VALIDATION_SUCCESS_UINT : SIG_VALIDATION_FAILED_UINT;
        return isValid(h, v, r, s, sm) ? SIG_VALIDATION_SUCCESS_UINT : SIG_VALIDATION_FAILED_UINT;
    }


    //digest, v,r,s are input to ecrecover, sm is the falcon signature
    //TODO : do not revert - kept for hackathon
    function isValid(
        bytes32 digest,
        uint8 v,
        bytes32 r,
        bytes32 s,
        bytes memory sm // the signature in the NIST KAT format, as output by test_falcon.js
        ) public returns (bool)
        {
             uint256 slen = (uint256(uint8(sm[0])) << 8) + uint256(uint8(sm[1]));
            uint256 mlen = sm.length - slen - 42;

            bytes memory message;
            bytes memory salt = new bytes(40);

        for (uint i = 0; i < 40; i++) {
          salt[i] = sm[i + 2];
         }
        message = new bytes(mlen);
        for (uint256 j = 0; j < mlen; j++) {
          message[j] = sm[j + 42];
        }

         if (sm[2 + 40 + mlen] != 0x29) {
             revert("wrong header sigbytes");
         }

        uint256[] memory s2 =_ZKNOX_NTT_Compact((_decompress_sig(sm, 2 + 40 + mlen + 1)));

         ISigVerifier Core = ISigVerifier(getStorage().CoreAddress);

         uint256[] memory nttpk;
         address recovered = ecrecover(digest, v, r, s);

         require(getStorage().authorized_PQPublicKey != address(0), "authorizedPublicKey null");
         require(recovered==getStorage().authorized_ECDSA, "Invalid ECDSA signature");
         nttpk = Core.GetPublicKey(getStorage().authorized_PQPublicKey);
         require(Core.verify(abi.encodePacked(digest), salt, s2, nttpk), "Invalid FALCON");

         return true;
        }



    function GetPublicKey() public view returns (uint256[] memory res) {
        ISigVerifier Core = ISigVerifier(getStorage().CoreAddress);
        res = Core.GetPublicKey(getStorage().authorized_PQPublicKey);
    }

    function GetStorage() public view returns (address, address) {
        return (getStorage().CoreAddress, getStorage().authorized_PQPublicKey);
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
    external
    payable
    returns (uint256) {
        console.log("INSIDE THE validateUserOp OF THE CUSTOM MODULE");
        return _validateSignature(userOp, userOpHash);
    }

    function isValidSignatureWithSender(address sender, bytes32 hash, bytes calldata data)
    external
    view
    returns (bytes4) {
        return 0xffffffff;
    }

    function onInstall(bytes calldata data) external payable {

    }

    function onUninstall(bytes calldata data) external payable {

    }

    function isModuleType(uint256 moduleTypeId) external view returns (bool) {
        return true;
    }

    function isInitialized(address smartAccount) external view returns (bool) {
        return true;
    }
    //receive() external payable {}
} //end contract
