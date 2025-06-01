import Button from "./Button.tsx";
import {wcGetPairings, web3wallet} from "./WalletConnect";
import {execHaloCmdWeb} from "@arx-research/libhalo/api/web";
import {buildApprovedNamespaces, getSdkError} from "@walletconnect/utils";
import {computeAddress} from "ethers";
import {EIP155_MAINNET_CHAINS, EIP155_TEST_CHAINS} from "../logic/EIP155Chains";

function ListPairings({haloAddress, onStartPairing, onSwitchHalo, onResetWallet}) {
    let pairings = wcGetPairings();

    function renderPairing(topic, o) {
        console.log(o);
        return <span>{o.peer.metadata.name} ({o.peer.metadata.url})</span>
    }

    function btnPair() {
        onStartPairing();
    }

    async function btnSwitchHalo() {
        let activeSess = web3wallet.getActiveSessions();

        let pkeys;

        try {
            pkeys = await execHaloCmdWeb({
                "name": "get_pkeys"
            });
        } catch (e) {
            alert(e.toString());
            return;
        }

        let addr = computeAddress('0x' + pkeys.publicKeys[1]);
        onSwitchHalo(addr);

        for (let topic of Object.keys(activeSess)) {
            console.log('active session', activeSess[topic]);

            let chains = Object.keys(EIP155_MAINNET_CHAINS).concat(Object.keys(EIP155_TEST_CHAINS));
            let accounts = chains.map((chain) => chain + ':' + addr);

            const approvedNamespaces = buildApprovedNamespaces({
                proposal: activeSess[topic],
                supportedNamespaces: {
                    eip155: {
                        chains: chains,
                        methods: ["eth_sendTransaction", "eth_sign", "personal_sign", "eth_signTypedData", "eth_signTypedData_v3", "eth_signTypedData_v4"],
                        events: ["accountsChanged", "chainChanged"],
                        accounts: accounts
                    },
                },
            });

            console.log(approvedNamespaces);

            await web3wallet.updateSession({
                topic: topic,
                namespaces: approvedNamespaces
            });

            for (let chainId of activeSess[topic].namespaces.eip155.chains) {
                await web3wallet.emitSessionEvent({
                    topic: topic,
                    event: {
                        name: 'accountsChanged',
                        data: [addr]
                    },
                    chainId: chainId
                });
            }
        }
    }

    async function btnResetWallet() {
        let activeSess = web3wallet.getActiveSessions();

        for (let topic of Object.keys(activeSess)) {
            await web3wallet.disconnectSession({
                topic,
                reason: getSdkError('USER_DISCONNECTED')
            });
        }

        for (let pairing of web3wallet.core.pairing.getPairings()) {
            await web3wallet.core.pairing.disconnect({topic: pairing.topic});
        }

        onResetWallet();
    }

    return (
        <div>
            <div style={{marginBottom: '40px'}}>
                <p className={"label-text"}>
                    Active HaLo tag:
                </p>
                <p style={{textTransform: 'none', color: 'white', fontFamily: 'monospace', fontSize: 12}}>
                    {haloAddress}
                </p>
                <p className={"label-text"} style={{marginTop: 20}}>
                    Paired with the following dApps:
                </p>
                <ul>
                    {Object.keys(pairings).map(
                        (x) => <li key={x} className={"app-item"}>
                            {renderPairing(x, pairings[x])}
                        </li>)}
                </ul>
            </div>
            <Button onClick={() => btnPair()} fullWidth={true} className={"btn-pad"}>Scan QR code</Button>
            <Button onClick={() => btnSwitchHalo()} fullWidth={true} className={"btn-pad"}>Switch HaLo tag</Button>
            <Button onClick={() => btnResetWallet()} fullWidth={true} className={"btn-pad"}>Reset wallet</Button>
        </div>
    );
}

export default ListPairings;
