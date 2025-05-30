// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "../src/ZKNOX_IVerifier.sol";
import "../src/ZKNOX_delegate_noproxy.sol";

import "../src/ZKNOX_ethfalcon.sol";
import "../src/ZKNOX_falcon_deploy.sol";

import {console, Test} from "forge-std/Test.sol";
import {BaseScript} from "./BaseScript.sol";
import "forge-std/Vm.sol";

//simple ERC20 for the demonstration
contract ERC20 {
    address public minter;
    mapping(address => uint256) private _balances;

    constructor(address _minter) {
        minter = _minter;
    }

    function mint(uint256 amount, address to) public {
        _mint(to, amount);
    }

    function balanceOf(address account) public view returns (uint256) {
        return _balances[account];
    }

    function _mint(address account, uint256 amount) internal {
        require(msg.sender == minter, "ERC20: msg.sender is not minter"); //comment until delegation works
        console.log("message sender:", msg.sender);
        require(account != address(0), "ERC20: mint to the zero address");
        unchecked {
            _balances[account] += amount;
        }
    }

    function _acknowledge(bytes memory data) public pure returns (string memory res) {
        return string(abi.encodePacked(data, "\n was successfully signed!"));
    }
}

contract CallExecutor {
    function executeCall(
        address verifier,
        address token,
        bytes memory data,
        uint256 value,
        bytes memory salt,
        uint256[] memory s2
    ) external {
        console.log("Verifier:", verifier);
        console.log("Token:", token);
        console.logBytes(data);
        console.log("Value:", value);
        console.logBytes(salt);
        console.log("S2 Length:", s2.length);

        // Direct `call`, ensuring Verifier's storage is accessed instead of Alice's
        (bool success, bytes memory returnData) = verifier.call(
            abi.encodeWithSignature("transact(address,bytes,uint256,bytes,uint256[])", token, data, value, salt, s2)
        );
        require(success, "Call to Verifier failed");
    }
}

contract SignDelegationTest is BaseScript {
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

    ZKNOX_ethfalcon public falcon;
    ZKNOX_Verifier Verifier;

    // ERC-20 token contract for minting test tokens.
    ERC20 public token;

    function setUp() public {
        // Deploy the delegation contract (Alice will delegate calls to this contract).

        vm.broadcast(ALICE_PK);

        falcon = new ZKNOX_ethfalcon();
        // public key in ntt form
        // forgefmt: disable-next-line
        uint256[32] memory tmp_pkc = [20377218425118340445148364134355217251962993606936992273331839780054216280849, 20121106827228450321124896615938334719918113760150351437528659189176262990636, 10067497595444039977213793634597611854404700659079271442444950951559432116521, 8117003418140413121709569530562717039471558017795389997976077490386494167285, 19719916617578783495479977733846345663822541355599584111604787561804371332299, 12011255695358364119082992510081379197681548345148896992583517862986064267371, 1413712800155248155901989741415704580119744515670156265477932184210522442954, 20205896941262413308936850117551422118594142119900192427257346204109575433582, 3486279541225130755598501027003998051985801747561740177288468626060198090459, 15477599456049069393051346514952035991054078301113692636739851820730251809819, 21156392022423827010876847021244058034030321298933336763476969617428294271271, 2908341131797448574919302622375649436059983246466303686691800726354050296280, 4014285105619800009931504325676093765338451832744274077688243007139640906463, 17525386234073442601006363277175078033276096227970594283065994928074709206070, 9399682681199319758356271164177409471029167726563817053939019373865509324066, 14497266053893643950060558685941531408969726991430751449270004178102628913394, 20001018922134128765022849593872125843127919031255693298563962888117505231302, 20223399471737868067964408671262891234552388541376818065834177454291358723391, 11076429199706617732593752467897544427206591530047673604493842949459150906661, 10003914827585439734433133640025401879385317162577084551224105445404031001782, 20818841785974240140489196577114322827962289517719106191109136290716168037702, 9930008312479770233251082269305959959461466299666759427058224003186584853639, 13961923764749961571138036653552925829425897028586292322709756121414948556716, 1865847632959804051511238296007895164923970314748517688837335778369740540589, 9619029050213147645610307806665071441731316717663787766260527940528214317525, 14242850992292404983847270889619711734347852346434510691917062411771622728876, 14741088360075140317883502213566092308263093099494020005957065598182206670698, 450741599221347172965973222014483009289616792068532398266398440365899262013, 18781682460599299134542238039348179607304289110944838378016618837639364477280, 9945663145577743462232497392336568635199398547866845488457561121052707133988, 4434915596203863112439022225522412087141907977885194617923870370615952742502, 9078099396363096043342272050200561246179429816170715912419583083116430298211];
        uint256[] memory pkc = ZKNOX_memcpy32(tmp_pkc);
        uint256 iAlgoID = FALCONSHAKE_ID;

        address a_psirev;
        address a_psiInvrev;
        bytes32 salty = keccak256(abi.encodePacked("ZKNOX_v0.14"));

        address iVerifier_algo = address(falcon);
        address iPublicKey = DeployPolynomial(salty, pkc);

        Verifier = new ZKNOX_Verifier(iAlgoID, iVerifier_algo, iPublicKey);
        console.log("param Verifier:", Verifier.algoID(), Verifier.CoreAddress(), Verifier.authorizedPublicKey());

        // Deploy an ERC-20 token contract where Alice is the minter.
        token = new ERC20(ALICE_ADDRESS);
    }

    function run() public {
        vm.broadcast(ALICE_PK);

        // Construct a single transaction call: Mint 100 tokens to Bob.
        //SimpleDelegateContract.Call[] memory calls = new SimpleDelegateContract.Call[](1);
        bytes memory data = abi.encodeCall(ERC20.mint, (100, BOB_ADDRESS));
        //0x94bf804d00000000000000000000000000000000000000000000000000000000000000640000000000000000000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc
        console.log("payload");
        console.logBytes(data);
        // forgefmt: disable-next-line
        uint256[32] memory TMPS2  =  [21686606549281905815515514191405715115503627890644145003266679262707215642567, 296837262649050065082235723308953139986720476376742581565765319869905633281, 699674915585812202458584990677468674571329331948918721341381283027979731019, 21501091139275485229683714448456762785794250332001033206895748441456979095390, 88671857784014195898161286832236500616594531984891892267306862244313170092, 21702183391290603982727105219391817219888919505654099311403925125853109497548, 21152693792423851251313048196127973842598027512161510612740554533232534892457, 21348815784745969278513305533838322354479473723656317986010190694999941185768, 191144566140012136941148251534717718538485457074702543678283247517654253615, 333943099949708982002975732801063020770834497464905777245782904670588895446, 381968578377497989856826708671235314546960006046982294746140762059672322169, 204954264439288858484119257854458574842975278774279312361872193767282966574, 95740081821630823674403848041084997950322696287856897187849980510773575701, 187291185886637771019106822468655760559634008615104577967713589752435179626, 21636811258212483462319516588522334027449483123950038542988288448629436776673, 21481329821844705381538927849362684771641564435957599293876244593975133732870, 296832895153657740837491502033034437584530278402687560381472984309407547589, 273862054934319655273629611277996015247839932469275878823566702034070274508, 21642437718144483387442525296443705033166513065268971588157796681829752045604, 21400380506100520062556073407609528850535233848246141809180433988923278765988, 21597941894890244789464074890178566323030519463645242150083598174792662777956, 21619469627987651586059766232500554863816678212409986541215065213926050365552, 176685169788570760509601583603387445880852361944673025805716894006958567372, 548050455022204403847393298370808573230958516285345238251608479165076942756, 21628300601137427347799939648337965132929650153953287522712677323025964269608, 21451617857728912045563981969311218255508773410257161323440129998274531635169, 21490488039839670064384939584614741403931101658720464841811999928970149179280, 233554449347444526206103659460841098498992611725419861496833026132633977138, 399308061698062014615371471710586411384619334903430954442140390413233619141, 21651273894629788760476675608321329953517042036277643800184351583500635013169, 168181431561741498485386747624117491147478734995101176294319434378600054855, 267122904050485330079696066999222396535525149593676430159069847637086252681];
        bytes memory SALT = hex"8e1e962c9e111ed82f09179a622f86d72db8c597a8e7bbbf15f80aea93b13e3b127ad56ed8c88ea7";
        uint256[] memory S2 = ZKNOX_memcpy32(TMPS2);
        uint256 nonce = 0;
        //./sign_cli.py sign_tx --data=94bf804d00000000000000000000000000000000000000000000000000000000000000640000000000000000000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc --privkey=private_key.pem --version='falcon' --nonce=0 --to=0xa0Cb889707d426A7A386870A03bc70d1b0697598 --value=0 --pubkey=public_key.pem

        console.log("address ERC20:", address(token));

        bytes32 digest = keccak256(abi.encode(nonce, 0xa0Cb889707d426A7A386870A03bc70d1b0697598, data, 0));

        uint256 TX_HASH_expected = 0xbfcdaa8d33d719d5232c4ec31ae95f5208c14510118a9039475595950f17baeb;

        if (TX_HASH_expected != uint256(digest)) {
            revert();
        }

        //calls[0] = SimpleDelegateContract.Call({to: address(token), data: data, value: 0});

        // Alice signs a delegation allowing `implementation` to execute transactions on her behalf.
        Vm.SignedDelegation memory signedDelegation = vm.signDelegation(address(Verifier), ALICE_PK);

        // Set Alice's storage before calling Verifier
        /*vm.store(ALICE_ADDRESS, bytes32(uint256(0)), bytes32(uint256(uint160(Verifier.authorizedPublicKey()))));
        vm.store(ALICE_ADDRESS, bytes32(uint256(1)), bytes32(uint256(uint160(Verifier.CoreAddress()))));
        vm.store(ALICE_ADDRESS, bytes32(uint256(2)), bytes32(Verifier.algoID()));
        vm.store(ALICE_ADDRESS, bytes32(uint256(3)), bytes32(Verifier.nonce()));*/

        // Debug: Print stored values to verify correct setup
        console.log(
            "Stored authorizedPublicKey at Alice:",
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
        vm.attachDelegation(signedDelegation);
        bytes memory code = address(ALICE_ADDRESS).code; //this shall be ef0100, followed by adress

        console.log("Verifier address:%x", uint256(uint160(address(Verifier))));

        console.log("code written at eoa Alice:");
        console.logBytes(code);

        // Verify that Alice's account now temporarily behaves as a smart contract.
        require(code.length > 0, "no code written to Alice");

        // As Bob, execute the transaction via Alice's temporarily assigned contract.
        ZKNOX_Verifier(ALICE_ADDRESS).transact(address(token), data, 0, SALT, S2); //this is the delegation we want, failing now

        // Verify Bob successfully received 100 tokens.
        vm.assertEq(token.balanceOf(BOB_ADDRESS), 100);
    }
}
