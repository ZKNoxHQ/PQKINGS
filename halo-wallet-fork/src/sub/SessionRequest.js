import {web3wallet} from "./WalletConnect";
import {HaloWallet} from "../logic/HaloWallet.ts";
import {formatJsonRpcError, formatJsonRpcResult} from '@json-rpc-tools/utils'
import {EIP155_CHAINS, EIP155_MAINNET_CHAINS, EIP155_SIGNING_METHODS} from "../logic/EIP155Chains.js";
import {getBytes, JsonRpcProvider} from "ethers";
import JSONPretty from 'react-json-pretty';
import Button from "./Button.tsx";

function SessionRequest({haloAddress, sessionRequest, onRequestProcessed}) {
  async function processCall(req) {
    const { topic, params, id } = req;
    const { chainId, request } = params;
    const requestParamsMessage = request.params[0];

    const wallet = new HaloWallet(haloAddress, null);

    switch (request.method) {
      case EIP155_SIGNING_METHODS.PERSONAL_SIGN:
        try {
          const signedMessage = await wallet.signMessage(getBytes(requestParamsMessage));
          return formatJsonRpcResult(id, signedMessage);
        } catch (error) {
          return formatJsonRpcError(id, error.message);
        }

      case EIP155_SIGNING_METHODS.ETH_SIGN_TYPED_DATA_V4:
        try {
          const {domain, types, message: data} = JSON.parse(request.params[1]);
          delete types.EIP712Domain;
          const signedData = await wallet._signTypedData(domain, types, data);
          return formatJsonRpcResult(id, signedData);
        } catch (error) {
          return formatJsonRpcError(id, error.message);
        }

      case EIP155_SIGNING_METHODS.ETH_SEND_TRANSACTION:
        try {
          console.log(chainId);
          console.log(EIP155_CHAINS[chainId]);
          console.log(EIP155_CHAINS[chainId].rpc);
          const provider = new JsonRpcProvider(EIP155_CHAINS[chainId].rpc);
          const sendTransaction = request.params[0];
          const connectedWallet = wallet.connect(provider);

          if (typeof sendTransaction.gas !== "undefined") {
            sendTransaction.gasLimit = sendTransaction.gas;
            delete sendTransaction.gas;
          }

          const { hash } = await connectedWallet.sendTransaction(sendTransaction);
          return formatJsonRpcResult(id, hash);
        } catch (error) {
          console.error('sendTransaction error', error);
          return formatJsonRpcError(id, error.message);
        }

      default:
        throw new Error("Internal error, session request had an unsupported method: " + request.method);
    }
  }

  async function btnSignTransaction() {
    const { topic } = sessionRequest
    const response = await processCall(sessionRequest);
    await web3wallet.respondSessionRequest({ topic, response });
    onRequestProcessed();
  }

  async function btnReject() {
    const { topic, params, id } = sessionRequest
    let response = formatJsonRpcError(id, 'Operation rejected by the user.');
    await web3wallet.respondSessionRequest({ topic, response });
    onRequestProcessed();
  }

  const { topic, params, id } = sessionRequest;
  const { chainId, request } = params;
  const requestParamsMessage = request.params[0];

  let activeSess = web3wallet.getActiveSessions();
  let peerMeta = activeSess[topic].peer.metadata;

  let reqType = "(unknown)";
  let vizComponent = <div>Unable to visualize the request.</div>;

  let chainName = chainId;

  if (EIP155_MAINNET_CHAINS.hasOwnProperty(chainId)) {
    chainName = EIP155_MAINNET_CHAINS[chainId].name;
  }

  switch (request.method) {
    case EIP155_SIGNING_METHODS.PERSONAL_SIGN:
      reqType = <span>sign personal message</span>;
      vizComponent = <code style={{wordBreak: 'break-all'}}>{requestParamsMessage}</code>;
      break;

    case EIP155_SIGNING_METHODS.ETH_SIGN_TYPED_DATA_V4:
      reqType = <span>sign typed data</span>;
      vizComponent = <JSONPretty id="json-pretty" data={request.params[1]}></JSONPretty>;
      break;

    case EIP155_SIGNING_METHODS.ETH_SEND_TRANSACTION:
      reqType = <span>sign and send transaction</span>;
      vizComponent = <JSONPretty id="json-pretty" data={request.params[0]}></JSONPretty>;
      break;
  }

  return (
      <div>
        <p className={"label-text"}>
          Request from the dApp:<br /><span style={{color: 'white'}}>{peerMeta.name} ({chainName})</span>
          <br />to:<br /><span style={{color: 'white'}}>{reqType}</span>:
        </p>
        <div style={{fontSize: 10, height: '300px', overflow: 'scroll', margin: '20px 0'}}>{vizComponent}</div>
        <p className={"label-text"} style={{margin: '20px 0'}}>
          You will need to scan your HaLo after clicking the "Sign request" button.
        </p>
        <Button onClick={() => btnSignTransaction()}>Sign request</Button>
        <Button onClick={() => btnReject()}>Deny</Button>
      </div>
  );
}

export default SessionRequest;
