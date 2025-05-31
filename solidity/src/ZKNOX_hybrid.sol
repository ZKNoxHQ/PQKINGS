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

import "./ZKNOX_common.sol";
import "./ZKNOX_IVerifier.sol";

import "./ZKNOX_falcon_utils.sol";
import {ZKNOX_NTT} from "./ZKNOX_NTT.sol";
import "./ZKNOX_falcon_core.sol";

//choose the XOF to use here
import "./ZKNOX_HashToPoint.sol";
import "./ZKNOX_falcon_encodings.sol";

/// @notice Contract designed for being delegated to by EOAs to authorize a IVerifier key to transact on their behalf.
contract ZKNOX_HybridVerifier {
    //derived address from ecdsa
    address public authorized_ECDSA;
   
    /// @notice Address of the contract storing the post quantum public key
    address public authorized_PQPublicKey;
    /// @notice Address of the verification contract logic

    address public CoreAddress; //adress of the core verifier (FALCON, DILITHIUM, etc.), shall be the adress of a ISigVerifier
    uint256 public algoID;

    /// @notice Internal nonce used for replay protection, must be tracked and included into prehashed message.
    uint256 public nonce;

    constructor() {}
    
    //input are AlgoIdentifier, Signature verification address, publickey storing contract
    function initialize(uint256 iAlgoID, address iCore, address iAuthorized_ECDSA, address iPublicPQKey) external {
        require(CoreAddress == address(0), "already initialized");
       
        authorized_ECDSA=iAuthorized_ECDSA;  //derived address from ecdsa secp256K1
        CoreAddress = iCore; // Address of contract of Signature verification (FALCON, DILITHIUM)
        algoID = iAlgoID;
        authorized_PQPublicKey = iPublicPQKey;
        nonce = 0;
    }

    //digest, v,r,s are input to ecrecover, sm is the falcon signature
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

         ISigVerifier Core = ISigVerifier(CoreAddress);

         uint256[] memory nttpk;
         address recovered = ecrecover(digest, v, r, s);

         require(authorized_PQPublicKey != address(0), "authorizedPublicKey null");
         require(recovered==authorized_ECDSA, "Invalid ECDSA signature");
         nttpk = Core.GetPublicKey(authorized_PQPublicKey);
         require(Core.verify(abi.encodePacked(digest), salt, s2, nttpk), "Invalid FALCON");

         return true;
        }
    


    function GetPublicKey() public view returns (uint256[] memory res) {
        ISigVerifier Core = ISigVerifier(CoreAddress);
        res = Core.GetPublicKey(authorized_PQPublicKey);
    }

    function GetStorage() public view returns (address, address) {
        return (CoreAddress, authorized_PQPublicKey);
    }
    //receive() external payable {}
} //end contract