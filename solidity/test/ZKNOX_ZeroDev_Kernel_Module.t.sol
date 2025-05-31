pragma solidity ^0.8.25;

import "../lib/account-abstraction/contracts/core/EntryPoint.sol";

import "../src/ZKNOX_falcon.sol";
import "../src/ZKNOX_falcon_encodings.sol";

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

        // Copied from ZKNOX_hybrid.t.sol
        ZKNOX_falcon falcon = new ZKNOX_falcon();
        uint256 iAlgoID = FALCONSHAKE_ID;
        bytes32 salty = keccak256(abi.encodePacked("ZKNOX_v0.14"));
        address iVerifier_algo = address(falcon);
        bytes memory pk=hex"09bc10a933624770811dc5e315526a3496c0e89b8e8436401a0848868c8b297ad7960a4f4df60bb2eba58b6d6828c99dce1d8b41ea6188af8e90081f3b2deee68a3888fb5ae87d99e2a110211cac1eadfa3a724c276a9108db19e8ff0add0da14aedd2073294ea7b682276edd449108e2b765ea2c03689b05fa6ba9146e16468325fdb39606472c61022f6679f247c16166c13af73994dc3dfa0b462b22747ee43a60f018eb5a26992805841c52b2b9ab829fbd4ed8b134625dbb95a10e62bbeeb806a95f985943472bc82ac510ae051ae2aff02a6cda68edfe971aef468356f075cb9b8c974566a3a46742123e78a79d96a941a94857e2acc3449955589ce80a6cc0ceb773224453b6309a280e659e585a68a98ea860869eba50a1d9776901babde4311638efc656cc564cc50987e1a8564e6e7bd47960d988f0a5a04746454528fab9cd89da9f1e534394229c91059f428b522cbf15eb359b9a08adfd3fe1d3548265a2e3b75c1f239df4e90734d704be8817b5639caa9d289fb4ee0f5e4d7603faff43d74734f8f6bdd9ff7b6578dac9e15949a54fa5465a925a61ebbb2f8eb858c1f487a9144840a1f9864f5ca49a7a63f6ec2a7f672c2c7ac18e973a1c0ca864e63db9f8731a996d1098809a89024f88bb8d757346993e52b138501315cf2086056060486870a5c437e886b8bcb422c0cde1ee081eddf18762a15926e8a8b5235b12d6d8ca5c60d72cfad3e755100d75096b5b8317ce7d5d36c5e01f7945a883cafa0a512e8edf28554c075145dec6798a3e2fac6cfa4851011b4906255521d5968102d10a92ff93d85b82d804469e90df8aee1b54212a66f461eb3514f29af958c326606e576254ef1a9ec83c62c568444d19e573b9c1c10d7a0b96fe4027a7a21c09b71cd7b271a828aa048203ae1691f5826e03a411e283dfa5a1a1b05bcf67ce6801590ab84a5d281edd573eadf50f6289d79b05b136ec16178d812d7f7e0f38cd9e83692064253f1dfda28ab97578dc0768fca404ef57ff24b463e3d50288970289e264a0eb9138a773fb114e0fd0c5fb5812186cea1f2a53ec133dfa3ad8809fd47cd56cb2e0185c266a17d263291753a47a2b531a5e9e4d29037646f934518c33e2c1fe2df5b2c0dea9fa2c751d689b24a819ce0f0bf82cab7b3adfc341a516b16c146a7c6a0e890a2d7451cf22459e3f3ab74b3076a62fbb11899a1a809357cb28a328761e0a4d56b501eca76a87169f560159c46a6a635b344c5";
        address iPQPublicKey = DeployPolynomial_NIST(salty, pk);
        address ECDSAPublicKey=0x24D63ffC083dB45d713F970565AA322c71A6e79c;
        module.initialize(iAlgoID, iVerifier_algo, ECDSAPublicKey, iPQPublicKey);

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
        /*** HARD-CODED SIGNATURE ***/

        bytes32 h = 0x50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750;//the hash signed by FALCON NIST and ECDSA, provided by etherjs for ECDSA and test_falcon.js for falcon
        //the ecdsa signature
        uint8 v = 28;
        bytes32 r = 0xb53b48c0bd1639e836cc93b267aeff63bcc3d597211107d2e93ae71c2560a46e;
        bytes32 s = 0x08c1f40ee7743dd09372566d171651195cbd963cf57b9ac7ea78b3879e71b8c8;
        //the falcon signature
        // forgefmt: disable-next-line
        bytes memory sm=hex"0268530f8afbc74536b9a963b4f1c4cb738bcea7403d4d606b6e074ec5d3baf39d18726003ca37a62a7450b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750297ec2d4595cbb8c63969e43a166aa9bb8deec56e12b846277e35c5fed1c50c32e48b1196c107664e7e69485033f616a1e2f43472db23d5cc429ce91199ebcf7a4dec55238b1f6aca32e54bac3f1cc14fe8f53d48d5fe9f21f23be9c109c4254636c5d17778af36ffcb37a767b0a17febd893e674c2201e79fd574dd3cba94ea63767edeb3e6cea18f09dae8b0dabb440851ab7fdca10bf0138acec3275672324331dea466f69e86a4e6e6dec65a204275287e3b22d83ac8912feabd7c272f94d232120d27c0e625ca17d12c2c69b0eb26d2c94d81fbc7a5b0f30529bf502a73145508bb3bbb1f7c31db45f477ec9651f3bd7630daf8b170b1c1170a6cbf50b64c5ca559898c6ebfd46621d19fa13afd93579a654c5932bdebb9478a6943d838c4fb5e61a5ea65152191c8d0724d673d6fecff4bc29e90879a00cfe5e16b3713d6a43f5edad250d814670b20c1e629ab147a21e8c7604caec4adefe6cc14b1a2238942490489afdef48bfac1f6ee556f8a2edef9d83675748f58f9ed37467ac567a889dde8ea72ddf97a6f3fdf249c72ceb5f2f1915d2a08511079997b8a992ca18f651dea3a168f26cb8d011273784ecc9e381f676da0b0b77fb8fe09e5455a5499b6e5aed73619f3e3d9b7aafea679e1b36ab10c3e4b3f40082962c2a0f4b87786b691ff5246809b2ed94978afd76b357c9c7ef1256bbff0e82f279bad32aadc45bb339156288bf4202e110d81457a1b5299e272754999ec350fc57afffd9361e57024ca0dfa36d5da322795468c9532739ef5358e8902225b48ed6d964ffa7c46b18a8a9448b65704606b06b17e49ca2e46a13868978f3ed1d3c0943d8dc90b24de72714fc940";

        /*** HARD-CODED SIGNATURE END ***/
        PackedUserOperation memory op = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(),
            initCode: abi.encodePacked(hex""),
            callData : abi.encodePacked(ZKNOX_ZeroDev_Kernel_Module.helloWorld.selector),
            accountGasLimits : bytes32(abi.encodePacked(uint128(10000000), uint128(10000000))),
            preVerificationGas : 1000000,
            gasFees : bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData : hex"",
            signature : abi.encode(v, r, s, sm)
        });
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps{gas: 25000000}(ops, payable(address(1)));
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
