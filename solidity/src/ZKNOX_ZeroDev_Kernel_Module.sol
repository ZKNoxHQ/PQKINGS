pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {_packValidationData} from "../lib/account-abstraction/contracts/core/Helpers.sol";
import {PackedUserOperation} from "../lib/kernel/src/interfaces/PackedUserOperation.sol";
import {IValidator} from "../lib/kernel/src/interfaces/IERC7579Modules.sol";

contract ZKNOX_ZeroDev_Kernel_Module is IValidator {

    function helloWorld() external {
        console.log("hello world!");
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
    external
    payable
    returns (uint256) {
        console.log("INSIDE THE validateUserOp OF THE CUSTOM MODULE");
        return _packValidationData(false, 0, 0);
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
}
