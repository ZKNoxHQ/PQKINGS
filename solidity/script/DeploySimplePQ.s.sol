// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script} from "../lib/forge-std/src/Script.sol";
import {BaseScript} from "./BaseScript.sol";

import "../src/ZKNOX_falcon_encodings.sol";
import "../src/ZKNOX_falcon.sol";
import "../src/ZKNOX_falcon_deploy.sol";
import "../src/ZKNOX_display.sol";
import "../src/ZKNOX_SimpleHybrid7702.sol";

import {console} from "forge-std/Test.sol";
//deploy the precomputed tables for psirev and psiInvrev

contract Script_Deploy_Falcon is BaseScript {
    // SPDX-License-Identifier: MIT

    function run() external {
        vm.startBroadcast();

        bytes32 salty = keccak256(abi.encodePacked("ZKNOX_v0.16"));

        ZKNOX_falcon FALCON = new ZKNOX_falcon{salt: salty}();

        console.log("Falcon : ", address(FALCON));

        bytes memory pk=hex"09bc10a933624770811dc5e315526a3496c0e89b8e8436401a0848868c8b297ad7960a4f4df60bb2eba58b6d6828c99dce1d8b41ea6188af8e90081f3b2deee68a3888fb5ae87d99e2a110211cac1eadfa3a724c276a9108db19e8ff0add0da14aedd2073294ea7b682276edd449108e2b765ea2c03689b05fa6ba9146e16468325fdb39606472c61022f6679f247c16166c13af73994dc3dfa0b462b22747ee43a60f018eb5a26992805841c52b2b9ab829fbd4ed8b134625dbb95a10e62bbeeb806a95f985943472bc82ac510ae051ae2aff02a6cda68edfe971aef468356f075cb9b8c974566a3a46742123e78a79d96a941a94857e2acc3449955589ce80a6cc0ceb773224453b6309a280e659e585a68a98ea860869eba50a1d9776901babde4311638efc656cc564cc50987e1a8564e6e7bd47960d988f0a5a04746454528fab9cd89da9f1e534394229c91059f428b522cbf15eb359b9a08adfd3fe1d3548265a2e3b75c1f239df4e90734d704be8817b5639caa9d289fb4ee0f5e4d7603faff43d74734f8f6bdd9ff7b6578dac9e15949a54fa5465a925a61ebbb2f8eb858c1f487a9144840a1f9864f5ca49a7a63f6ec2a7f672c2c7ac18e973a1c0ca864e63db9f8731a996d1098809a89024f88bb8d757346993e52b138501315cf2086056060486870a5c437e886b8bcb422c0cde1ee081eddf18762a15926e8a8b5235b12d6d8ca5c60d72cfad3e755100d75096b5b8317ce7d5d36c5e01f7945a883cafa0a512e8edf28554c075145dec6798a3e2fac6cfa4851011b4906255521d5968102d10a92ff93d85b82d804469e90df8aee1b54212a66f461eb3514f29af958c326606e576254ef1a9ec83c62c568444d19e573b9c1c10d7a0b96fe4027a7a21c09b71cd7b271a828aa048203ae1691f5826e03a411e283dfa5a1a1b05bcf67ce6801590ab84a5d281edd573eadf50f6289d79b05b136ec16178d812d7f7e0f38cd9e83692064253f1dfda28ab97578dc0768fca404ef57ff24b463e3d50288970289e264a0eb9138a773fb114e0fd0c5fb5812186cea1f2a53ec133dfa3ad8809fd47cd56cb2e0185c266a17d263291753a47a2b531a5e9e4d29037646f934518c33e2c1fe2df5b2c0dea9fa2c751d689b24a819ce0f0bf82cab7b3adfc341a516b16c146a7c6a0e890a2d7451cf22459e3f3ab74b3076a62fbb11899a1a809357cb28a328761e0a4d56b501eca76a87169f560159c46a6a635b344c5";

        address iPQPublicKey = DeployPolynomial_NIST(salty, pk);

        console.log("iPQPublicKey : ", iPQPublicKey);

        ZKNOX_SimpleHybrid7702 delegate = new ZKNOX_SimpleHybrid7702{salt: salty}();

        console.log("Delegate : ", address(delegate));

        vm.stopBroadcast();
    }
}
