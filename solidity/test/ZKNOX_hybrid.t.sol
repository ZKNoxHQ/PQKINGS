
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import "../src/ZKNOX_falcon_encodings.sol";
import "../src/ZKNOX_falcon.sol";
import "../src/ZKNOX_falcon_deploy.sol";
import "../src/ZKNOX_display.sol";
import "../src/ZKNOX_hybrid.sol";

import "forge-std/Vm.sol";


contract Hybrid_Test is Test {
    ZKNOX_falcon falcon;
    //exemple of stateless initialisation, no external contract provided
   // Alice's address and private key (EOA with no initial contract code).
    address payable ALICE_ADDRESS = payable(0x70997970C51812dc3A010C7d01b50e0d17dc79C8);
    uint256 constant ALICE_PK = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;

    // Bob's address and private key (Bob will execute transactions on Alice's behalf).
    address constant BOB_ADDRESS = 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC;
    uint256 constant BOB_PK = 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a;
    // Deployer's address and private key (used to deploy contracts).
    address private constant DEPLOYER_ADDRESS = 0xa0Ee7A142d267C1f36714E4a8F75612F20a79720;
    uint256 private constant DEPLOYER_PK = 0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6;

    // The contract that Alice will delegate execution to.

    ZKNOX_HybridVerifier Verifier;

   

    //stateful initialisation
    function setUp() public {
        // Deploy the delegation contract (Alice will delegate calls to this contract).
        
        bytes memory pk=hex"09bc10a933624770811dc5e315526a3496c0e89b8e8436401a0848868c8b297ad7960a4f4df60bb2eba58b6d6828c99dce1d8b41ea6188af8e90081f3b2deee68a3888fb5ae87d99e2a110211cac1eadfa3a724c276a9108db19e8ff0add0da14aedd2073294ea7b682276edd449108e2b765ea2c03689b05fa6ba9146e16468325fdb39606472c61022f6679f247c16166c13af73994dc3dfa0b462b22747ee43a60f018eb5a26992805841c52b2b9ab829fbd4ed8b134625dbb95a10e62bbeeb806a95f985943472bc82ac510ae051ae2aff02a6cda68edfe971aef468356f075cb9b8c974566a3a46742123e78a79d96a941a94857e2acc3449955589ce80a6cc0ceb773224453b6309a280e659e585a68a98ea860869eba50a1d9776901babde4311638efc656cc564cc50987e1a8564e6e7bd47960d988f0a5a04746454528fab9cd89da9f1e534394229c91059f428b522cbf15eb359b9a08adfd3fe1d3548265a2e3b75c1f239df4e90734d704be8817b5639caa9d289fb4ee0f5e4d7603faff43d74734f8f6bdd9ff7b6578dac9e15949a54fa5465a925a61ebbb2f8eb858c1f487a9144840a1f9864f5ca49a7a63f6ec2a7f672c2c7ac18e973a1c0ca864e63db9f8731a996d1098809a89024f88bb8d757346993e52b138501315cf2086056060486870a5c437e886b8bcb422c0cde1ee081eddf18762a15926e8a8b5235b12d6d8ca5c60d72cfad3e755100d75096b5b8317ce7d5d36c5e01f7945a883cafa0a512e8edf28554c075145dec6798a3e2fac6cfa4851011b4906255521d5968102d10a92ff93d85b82d804469e90df8aee1b54212a66f461eb3514f29af958c326606e576254ef1a9ec83c62c568444d19e573b9c1c10d7a0b96fe4027a7a21c09b71cd7b271a828aa048203ae1691f5826e03a411e283dfa5a1a1b05bcf67ce6801590ab84a5d281edd573eadf50f6289d79b05b136ec16178d812d7f7e0f38cd9e83692064253f1dfda28ab97578dc0768fca404ef57ff24b463e3d50288970289e264a0eb9138a773fb114e0fd0c5fb5812186cea1f2a53ec133dfa3ad8809fd47cd56cb2e0185c266a17d263291753a47a2b531a5e9e4d29037646f934518c33e2c1fe2df5b2c0dea9fa2c751d689b24a819ce0f0bf82cab7b3adfc341a516b16c146a7c6a0e890a2d7451cf22459e3f3ab74b3076a62fbb11899a1a809357cb28a328761e0a4d56b501eca76a87169f560159c46a6a635b344c5";
         // forgefmt: disable-next-line
        falcon = new ZKNOX_falcon();
        // public key in ntt form
        // forgefmt: disable-next-line

        uint256 iAlgoID = FALCONSHAKE_ID;

        bytes32 salty = keccak256(abi.encodePacked("ZKNOX_v0.14"));

        address iVerifier_algo = address(falcon);
        address iPQPublicKey = DeployPolynomial_NIST(salty, pk);
        address ECDSAPublicKey=0x24D63ffC083dB45d713F970565AA322c71A6e79c;

        Verifier = new ZKNOX_HybridVerifier();

        // Alice signs a delegation allowing `implementation` to execute transactions on her behalf.
        Vm.SignedDelegation memory signedDelegation = vm.signDelegation(address(Verifier), ALICE_PK);

        vm.attachDelegation(signedDelegation);
        ZKNOX_HybridVerifier aliceVerifier = ZKNOX_HybridVerifier(ALICE_ADDRESS);
        aliceVerifier.initialize(iAlgoID, iVerifier_algo, ECDSAPublicKey, iPQPublicKey);
        console.log("param Verifier:", aliceVerifier.algoID(), aliceVerifier.CoreAddress(), aliceVerifier.authorized_PQPublicKey());

    }

    //unitary test of joint ECDSA+falcon
    function test_prague_hybridsig() public returns (address) {
        bytes32 h = 0x50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750;//the hash signed by FALCON NIST and ECDSA, provided by etherjs for ECDSA and test_falcon.js for falcon
        // forgefmt: disable-next-line
        bytes memory pk=hex"09bc10a933624770811dc5e315526a3496c0e89b8e8436401a0848868c8b297ad7960a4f4df60bb2eba58b6d6828c99dce1d8b41ea6188af8e90081f3b2deee68a3888fb5ae87d99e2a110211cac1eadfa3a724c276a9108db19e8ff0add0da14aedd2073294ea7b682276edd449108e2b765ea2c03689b05fa6ba9146e16468325fdb39606472c61022f6679f247c16166c13af73994dc3dfa0b462b22747ee43a60f018eb5a26992805841c52b2b9ab829fbd4ed8b134625dbb95a10e62bbeeb806a95f985943472bc82ac510ae051ae2aff02a6cda68edfe971aef468356f075cb9b8c974566a3a46742123e78a79d96a941a94857e2acc3449955589ce80a6cc0ceb773224453b6309a280e659e585a68a98ea860869eba50a1d9776901babde4311638efc656cc564cc50987e1a8564e6e7bd47960d988f0a5a04746454528fab9cd89da9f1e534394229c91059f428b522cbf15eb359b9a08adfd3fe1d3548265a2e3b75c1f239df4e90734d704be8817b5639caa9d289fb4ee0f5e4d7603faff43d74734f8f6bdd9ff7b6578dac9e15949a54fa5465a925a61ebbb2f8eb858c1f487a9144840a1f9864f5ca49a7a63f6ec2a7f672c2c7ac18e973a1c0ca864e63db9f8731a996d1098809a89024f88bb8d757346993e52b138501315cf2086056060486870a5c437e886b8bcb422c0cde1ee081eddf18762a15926e8a8b5235b12d6d8ca5c60d72cfad3e755100d75096b5b8317ce7d5d36c5e01f7945a883cafa0a512e8edf28554c075145dec6798a3e2fac6cfa4851011b4906255521d5968102d10a92ff93d85b82d804469e90df8aee1b54212a66f461eb3514f29af958c326606e576254ef1a9ec83c62c568444d19e573b9c1c10d7a0b96fe4027a7a21c09b71cd7b271a828aa048203ae1691f5826e03a411e283dfa5a1a1b05bcf67ce6801590ab84a5d281edd573eadf50f6289d79b05b136ec16178d812d7f7e0f38cd9e83692064253f1dfda28ab97578dc0768fca404ef57ff24b463e3d50288970289e264a0eb9138a773fb114e0fd0c5fb5812186cea1f2a53ec133dfa3ad8809fd47cd56cb2e0185c266a17d263291753a47a2b531a5e9e4d29037646f934518c33e2c1fe2df5b2c0dea9fa2c751d689b24a819ce0f0bf82cab7b3adfc341a516b16c146a7c6a0e890a2d7451cf22459e3f3ab74b3076a62fbb11899a1a809357cb28a328761e0a4d56b501eca76a87169f560159c46a6a635b344c5";

        // forgefmt: disable-next-line
        bytes memory sm=hex"0268530f8afbc74536b9a963b4f1c4cb738bcea7403d4d606b6e074ec5d3baf39d18726003ca37a62a7450b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750297ec2d4595cbb8c63969e43a166aa9bb8deec56e12b846277e35c5fed1c50c32e48b1196c107664e7e69485033f616a1e2f43472db23d5cc429ce91199ebcf7a4dec55238b1f6aca32e54bac3f1cc14fe8f53d48d5fe9f21f23be9c109c4254636c5d17778af36ffcb37a767b0a17febd893e674c2201e79fd574dd3cba94ea63767edeb3e6cea18f09dae8b0dabb440851ab7fdca10bf0138acec3275672324331dea466f69e86a4e6e6dec65a204275287e3b22d83ac8912feabd7c272f94d232120d27c0e625ca17d12c2c69b0eb26d2c94d81fbc7a5b0f30529bf502a73145508bb3bbb1f7c31db45f477ec9651f3bd7630daf8b170b1c1170a6cbf50b64c5ca559898c6ebfd46621d19fa13afd93579a654c5932bdebb9478a6943d838c4fb5e61a5ea65152191c8d0724d673d6fecff4bc29e90879a00cfe5e16b3713d6a43f5edad250d814670b20c1e629ab147a21e8c7604caec4adefe6cc14b1a2238942490489afdef48bfac1f6ee556f8a2edef9d83675748f58f9ed37467ac567a889dde8ea72ddf97a6f3fdf249c72ceb5f2f1915d2a08511079997b8a992ca18f651dea3a168f26cb8d011273784ecc9e381f676da0b0b77fb8fe09e5455a5499b6e5aed73619f3e3d9b7aafea679e1b36ab10c3e4b3f40082962c2a0f4b87786b691ff5246809b2ed94978afd76b357c9c7ef1256bbff0e82f279bad32aadc45bb339156288bf4202e110d81457a1b5299e272754999ec350fc57afffd9361e57024ca0dfa36d5da322795468c9532739ef5358e8902225b48ed6d964ffa7c46b18a8a9448b65704606b06b17e49ca2e46a13868978f3ed1d3c0943d8dc90b24de72714fc940";
        //Public Key X:     0x25d78deee0f08530687ba1b624bcdbd4560e55d61334e406b7bfd59b9b889d27
        //Public Key Y:     0x075d427f734aa0e304938358e610fae302996ee2593deb9117a03d89baabcd95

        //the ecdsa signature
        uint8 v = 28;
        bytes32 r = 0xb53b48c0bd1639e836cc93b267aeff63bcc3d597211107d2e93ae71c2560a46e;
        bytes32 s = 0x08c1f40ee7743dd09372566d171651195cbd963cf57b9ac7ea78b3879e71b8c8;

        address res= ecrecover(h, v, r, s);
        assertEq(uint160(0x24D63ffC083dB45d713F970565AA322c71A6e79c), uint160(res));


        uint256[] memory kpub;
        uint256[] memory s2;

        uint256[] memory cs2;
        bytes memory salt;
        bytes memory message;

        (kpub, s2, salt, message) = decompress_KAT(pk, sm);

        uint256[] memory ntth = _ZKNOX_NTT_Compact(_ZKNOX_NTTFW_vectorized(kpub));

        cs2 = _ZKNOX_NTT_Compact(s2);

        console.log("ntth length:", ntth.length);
        console.log("ntthh[0]:");
        
        for(uint i=0;i<1;i++){
            console.log("%x",ntth[i]);
        }

        console.log("salt:");
        console.logBytes(salt);

        console.log("message:");
        console.logBytes(message);

        bool result = falcon.verify(message, salt, cs2, ntth);

        console.log("result", result);

        return res;
    }


    function testVector0_prague_hybridsig_delegation() public  {
        bytes32 h = 0x50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750;//the hash signed by FALCON NIST and ECDSA, provided by etherjs for ECDSA and test_falcon.js for falcon
         //the ecdsa signature
        uint8 v = 28;
        bytes32 r = 0xb53b48c0bd1639e836cc93b267aeff63bcc3d597211107d2e93ae71c2560a46e;
        bytes32 s = 0x08c1f40ee7743dd09372566d171651195cbd963cf57b9ac7ea78b3879e71b8c8;
        //the falcon signature
        // forgefmt: disable-next-line
        bytes memory sm=hex"0268530f8afbc74536b9a963b4f1c4cb738bcea7403d4d606b6e074ec5d3baf39d18726003ca37a62a7450b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750297ec2d4595cbb8c63969e43a166aa9bb8deec56e12b846277e35c5fed1c50c32e48b1196c107664e7e69485033f616a1e2f43472db23d5cc429ce91199ebcf7a4dec55238b1f6aca32e54bac3f1cc14fe8f53d48d5fe9f21f23be9c109c4254636c5d17778af36ffcb37a767b0a17febd893e674c2201e79fd574dd3cba94ea63767edeb3e6cea18f09dae8b0dabb440851ab7fdca10bf0138acec3275672324331dea466f69e86a4e6e6dec65a204275287e3b22d83ac8912feabd7c272f94d232120d27c0e625ca17d12c2c69b0eb26d2c94d81fbc7a5b0f30529bf502a73145508bb3bbb1f7c31db45f477ec9651f3bd7630daf8b170b1c1170a6cbf50b64c5ca559898c6ebfd46621d19fa13afd93579a654c5932bdebb9478a6943d838c4fb5e61a5ea65152191c8d0724d673d6fecff4bc29e90879a00cfe5e16b3713d6a43f5edad250d814670b20c1e629ab147a21e8c7604caec4adefe6cc14b1a2238942490489afdef48bfac1f6ee556f8a2edef9d83675748f58f9ed37467ac567a889dde8ea72ddf97a6f3fdf249c72ceb5f2f1915d2a08511079997b8a992ca18f651dea3a168f26cb8d011273784ecc9e381f676da0b0b77fb8fe09e5455a5499b6e5aed73619f3e3d9b7aafea679e1b36ab10c3e4b3f40082962c2a0f4b87786b691ff5246809b2ed94978afd76b357c9c7ef1256bbff0e82f279bad32aadc45bb339156288bf4202e110d81457a1b5299e272754999ec350fc57afffd9361e57024ca0dfa36d5da322795468c9532739ef5358e8902225b48ed6d964ffa7c46b18a8a9448b65704606b06b17e49ca2e46a13868978f3ed1d3c0943d8dc90b24de72714fc940";
        

          vm.startBroadcast(ALICE_PK);

        // Debug: Print stored values to verify correct setup



        console.log(
            "Stored authorizedPublicKey at Alice (ecdsa):",
            address(uint160(uint256(vm.load(ALICE_ADDRESS, bytes32(uint256(0))))))
        );
        console.log(
            "Stored authorizedPQPublicKey at Alice (falcon):",
            address(uint160(uint256(vm.load(ALICE_ADDRESS, bytes32(uint256(0))))))
        );
        console.log(
            "Stored CoreAddress at Alice:", address(uint160(uint256(vm.load(ALICE_ADDRESS, bytes32(uint256(1))))))
        );
        console.log("Stored algoID at Alice:", uint256(vm.load(ALICE_ADDRESS, bytes32(uint256(2)))));
        console.log("Stored nonce at Alice:", uint256(vm.load(ALICE_ADDRESS, bytes32(uint256(3)))));

        // As Bob, execute the transaction via Alice's temporarily assigned contract.
        vm.stopBroadcast();

        vm.broadcast(BOB_PK);
        bytes memory code = address(ALICE_ADDRESS).code; //this shall be ef0100, followed by adress

        console.log("Verifier address:%x", uint256(uint160(address(Verifier))));

        console.log("code written at eoa Alice:");
        console.logBytes(code);

        // Verify that Alice's account now temporarily behaves as a smart contract.
        require(code.length > 0, "no code written to Alice");

       

        // As Bob, execute the transaction via Alice's temporarily assigned contract.
        bool isValid=ZKNOX_HybridVerifier(ALICE_ADDRESS).isValid(h,v,r,s,sm); 
        console.log("signature result:", isValid);

    }


}