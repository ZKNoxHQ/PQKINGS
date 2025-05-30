pragma solidity ^0.8.25;

import "../lib/account-abstraction/contracts/core/EntryPoint.sol";

import {Kernel} from "../lib/kernel/src/Kernel.sol";
import {ValidationMode, ValidationType} from "../lib/kernel/src/types/Types.sol";
import {IValidator, IHook} from "../lib/kernel/src/interfaces/IERC7579Modules.sol";
import {ValidatorLib} from "../lib/kernel/src/utils/ValidationTypeLib.sol";
import {InstallValidatorDataFormat, InstallFallbackDataFormat} from "../lib/kernel/src/types/Structs.sol";
import {MODULE_TYPE_VALIDATOR, MODULE_TYPE_FALLBACK, HOOK_MODULE_NOT_INSTALLED, VALIDATION_TYPE_VALIDATOR, VALIDATION_MODE_DEFAULT, CALLTYPE_SINGLE} from "../lib/kernel/src/types/Constants.sol";
import {ZKNOX_ZeroDev_Kernel_Module} from "../src/ZKNOX_ZeroDev_Kernel_Module.sol";

import {Test, console} from "forge-std/Test.sol";
import "forge-std/Vm.sol";

import {IEntryPoint as IEntryPointZeroDev} from "../lib/kernel/src/interfaces/IEntryPoint.sol";

contract ZKNOX_ZeroDev_Kernel_Module_Test is Test {
    ZKNOX_ZeroDev_Kernel_Module public module;
    Kernel public kernel;
    EntryPoint public entryPoint;

    function setUp() external {
        module = new ZKNOX_ZeroDev_Kernel_Module();
        entryPoint = new EntryPoint();
        kernel = new Kernel(IEntryPointZeroDev(address(entryPoint)));
        vm.deal(address(kernel), 10 ether);
        bytes memory selectorData = abi.encodePacked(ZKNOX_ZeroDev_Kernel_Module.helloWorld.selector);
        InstallValidatorDataFormat memory data = InstallValidatorDataFormat(hex"", hex"", selectorData);
//        not needed without 7702
//        bytes[] memory configs = new bytes[](0);
//        kernel.initialize(
//            ValidatorLib.validatorToIdentifier(IValidator(address(1))), IHook(address(0)), hex"", hex"", configs
//        );

        vm.startBroadcast(address(kernel));
        kernel.installModule(MODULE_TYPE_VALIDATOR, address(module),
            abi.encodePacked(HOOK_MODULE_NOT_INSTALLED,
                abi.encode(data.validatorData, data.hookData, data.selectorData)
            )
        );

        // TODO: we don't need it if we don't have any custom function
        InstallFallbackDataFormat memory fallbackData = InstallFallbackDataFormat(selectorData, hex"");
        kernel.installModule(MODULE_TYPE_FALLBACK, address(module),
            abi.encodePacked(
                selectorData,
                HOOK_MODULE_NOT_INSTALLED,
                abi.encode(abi.encodePacked(bytes1(0), bytes1(0), bytes1(0), bytes1(0)), fallbackData.hookData))
        );
    }

    function test_HelloWorld() external {
        PackedUserOperation memory op = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(),
            initCode: abi.encodePacked(hex""),
            callData : abi.encodePacked(ZKNOX_ZeroDev_Kernel_Module.helloWorld.selector),
            accountGasLimits : bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas : 1000000,
            gasFees : bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData : hex"",
        signature : hex""
        });
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, payable(address(1)));
    }

    function encodeNonce() internal returns (uint256){
        ValidationMode mode = VALIDATION_MODE_DEFAULT;
        uint192 nonceKey = ValidatorLib.encodeAsNonceKey(
            ValidationMode.unwrap(mode),
            ValidationType.unwrap(VALIDATION_TYPE_VALIDATOR),
            bytes20(address(module)),
            0 // parallel key
        );
        return entryPoint.getNonce(address(kernel), nonceKey);
    }
}
