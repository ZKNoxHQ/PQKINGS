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
///* FILE: ZKNOX_delegate.sol
///* Description: A contract designed to be delegated to a 7702 authorization
/**
 *
 */
pragma solidity ^0.8.25;

import "./ZKNOX_common.sol";
import "./ZKNOX_IVerifier.sol";
import "../lib/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";

//forge install OpenZeppelin/openzeppelin-contracts --no-commit
import "../lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";
import "../lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";
import "../lib/openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
// SPDX-License-Identifier: MIT

/// @notice Contract designed for being delegated to by EOAs to authorize a IVerifier key to transact on their behalf.
contract ZKNOX_Verifier is Initializable, UUPSUpgradeable, OwnableUpgradeable {
    /// @notice Address of the contract storing the public key
    address public authorizedPublicKey;
    /// @notice Address of the verification contract logic

    address public CoreAddress; //adress of the core verifier (FALCON, DILITHIUM, etc.), shall be the adress of a ISigVerifier
    uint256 public algoID;

    /// @notice Internal nonce used for replay protection, must be tracked and included into prehashed message.
    uint256 public nonce;

    //input are AlgoIdentifier, Signature verification address, publickey storing contract
    function initialize(uint256 iAlgoID, address iCore, address iPublicKey) public initializer {
        __UUPSUpgradeable_init(); // Initialize UUPS
        __Ownable_init(msg.sender); // Initialize Ownable
        CoreAddress = iCore; // Address of contract of Signature verification (FALCON, DILITHIUM)
        algoID = iAlgoID;
        authorizedPublicKey = iPublicKey;
        nonce = 0;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {
        // Only the owner should be allowed to upgrade the contract
    }

    /// @notice Authorizes provided public key to transact on behalf of this account. Only callable by EOA itself.
    function authorize(address iPublicKey) public {
        require(msg.sender == address(this));

        authorizedPublicKey = iPublicKey;
        //todo: add a checking of parameters related to algoID and public Key
    }

    /// @notice Main entrypoint for authorized transactions. Accepts transaction parameters (to, data, value) and a musig2 signature.
    function transact(
        address to,
        bytes memory data,
        uint256 val,
        bytes memory salt, // compacted signature salt part
        uint256[] memory s2 // compacted signature s2 part)
    ) external payable {
        bytes32 digest = keccak256(abi.encode(nonce++, to, data, val));
        ISigVerifier Core = ISigVerifier(CoreAddress);

        uint256[] memory nttpk;
        nttpk = Core.GetPublicKey(authorizedPublicKey);

        require(Core.verify(abi.encodePacked(digest), salt, s2, nttpk), "Invalid signature");

        (bool success,) = to.call{value: val}(data);

        require(success, "failing executing the cal");
    }

    //debug function for now: todo, remove when transact successfully tested
    function verify(
        bytes memory data,
        bytes memory salt, // compacted signature salt part
        uint256[] memory s2
    ) public view returns (bool) {
        ISigVerifier Core = ISigVerifier(CoreAddress);
        uint256[] memory nttpk;
        nttpk = Core.GetPublicKey(authorizedPublicKey);
        return Core.verify(data, salt, s2, nttpk);
    }

    function GetPublicKey() public view returns (uint256[] memory res) {
        ISigVerifier Core = ISigVerifier(CoreAddress);
        res = Core.GetPublicKey(authorizedPublicKey);
    }

    function GetStorage() public view returns (address, address) {
        return (CoreAddress, authorizedPublicKey);
    }
    //receive() external payable {}
} //end contract

contract ZKNOX_Verifier_Proxy is ERC1967Proxy {
    constructor(address _logic, bytes memory _data) ERC1967Proxy(_logic, _data) {}

    // Fallback function to handle the forwarding of calls
    fallback() external payable override {
        //revert("fallback called");

        // Forward the call to the implementation contract via delegatecall
        (bool success,) = _implementation().delegatecall(msg.data);
        require(success, "Delegatecall failed");
    }
}
