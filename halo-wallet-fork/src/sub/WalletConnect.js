import { Core } from '@walletconnect/core';
import { Web3Wallet } from '@walletconnect/web3wallet';

import {WALLET_CONNECT_APP_METADATA, WALLET_CONNECT_CLOUD_PROJECT_ID} from "../Config";
import {getSdkError} from "@walletconnect/utils";

let web3wallet = null;
let wcSession = null;

async function wcCreate({onSessionProposal, onSessionRequest, onSessionDelete}) {
    if (!web3wallet) {
        const core = new Core({
            projectId: WALLET_CONNECT_CLOUD_PROJECT_ID
        });

        let tmpWallet = await Web3Wallet.init({
            core,
            metadata: WALLET_CONNECT_APP_METADATA
        });

        tmpWallet.on('session_proposal', async sessionProposal => {
            onSessionProposal(sessionProposal);
        });

        tmpWallet.on('session_request', async sessionRequest => {
            onSessionRequest(sessionRequest);
        });

        tmpWallet.on('session_event', async sessionEvent => {
            console.log('session_event', sessionEvent);
        });

        tmpWallet.on('session_delete', async ev => {
            onSessionDelete(ev);
        });

        web3wallet = tmpWallet;
    }

    return {web3wallet};
}

async function wcPair({uri}) {
    await web3wallet.core.pairing.pair({uri});
}

async function wcApproveSession({id, namespaces}) {
    wcSession = await web3wallet.approveSession({id, namespaces});
    return wcSession;
}

async function wcDenySession({id, pairingTopic}) {
    await web3wallet.rejectSession({
        id: id,
        reason: getSdkError('USER_REJECTED_METHODS')
    });

    await web3wallet.core.pairing.disconnect({
        topic: pairingTopic
    });
}

function wcGetPairings() {
    return web3wallet.getActiveSessions();
}

export {wcCreate, wcPair, wcApproveSession, wcDenySession, wcGetPairings, web3wallet};
