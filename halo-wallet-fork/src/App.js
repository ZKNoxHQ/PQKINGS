import './style.scss';
import 'react-json-pretty/themes/monikai.css';

import {useCallback, useEffect, useState} from "react";
import ScanWeb3ModalQR from "./sub/ScanWeb3ModalQR";
import {wcCreate, wcGetPairings, wcPair, web3wallet} from "./sub/WalletConnect";
import SessionProposal from "./sub/SessionProposal";
import SessionRequest from "./sub/SessionRequest";
import Header from "./sub/Header.tsx";
import Wrapper from "./sub/Wrapper.tsx";
import ListPairings from "./sub/ListPairings";

function App() {
  let [appState, setAppState] = useState({name: "init"});
  let [haloAddress, setHaloAddress] = useState(null);

  console.log('appState', appState);

  function updateHaloAddress(addr) {
    window.localStorage.setItem('haloAddress', addr);
    setHaloAddress(addr);
  }

  function postResetWallet() {
    window.localStorage.removeItem('haloAddress');
    setHaloAddress(null);
    setAppState({"name": "pairing"});
  }

  function switchToMainScreen() {
    let pendingProposals = web3wallet.getPendingSessionProposals();
    let pendingReqs = web3wallet.getPendingSessionRequests();
    let hasAnyPairings = Object.keys(wcGetPairings()).length > 0;

    if (pendingProposals.length > 0) {
      setAppState({"name": "session_proposal", "proposal": pendingProposals[0]});
    } else if (pendingReqs.length > 0) {
      setAppState({"name": "session_request", "request": pendingReqs[0]});
    } else if (hasAnyPairings) {
      setAppState({"name": "paired"});
    } else {
      setAppState({"name": "pairing"});
    }
  }

  const onSessionProposal = useCallback((proposal) => {
    setAppState({
      name: "session_proposal",
      proposal
    });
  }, []);

  const onSessionRequest = useCallback((request) => {
    console.log('session_request', request);

    setAppState(prevAppState => {
      if (prevAppState.name === "session_request") {
        console.log('session_request already pending');
        return prevAppState;
      } else {
        return {name: "session_request", request};
      }
    });
  }, []);

  const onSessionDelete = useCallback((request) => {
    console.log('session_delete', request);
    let hasAnyPairings = Object.keys(wcGetPairings()).length > 0;

    setAppState(prevAppState => {
      if (!hasAnyPairings) {
        return {"name": "pairing"};
      } else if (prevAppState.name === "paired") {
        // force re-render
        return {"name": "paired"};
      }
    });
  }, []);

  useEffect(() => {
    async function initializeWalletConnect() {
      try {
        await wcCreate({
          onSessionProposal,
          onSessionRequest,
          onSessionDelete
        });
      } catch (e) {
        alert(e.toString());
        return;
      }

      switchToMainScreen();
    }

    let addr = window.localStorage.getItem('haloAddress');

    if (addr) {
      setHaloAddress(addr);
    }

    initializeWalletConnect();
  }, [onSessionDelete, onSessionProposal, onSessionRequest]);

  useEffect(() => {
    async function pairWalletConnect() {
      try {
        await wcPair({
          uri: appState.pairURI
        });
      } catch (e) {
        alert(e.toString());
        setAppState({name: "pairing"});
      }
    }

    if (appState.name === "do_pair") {
      pairWalletConnect();
    }
  }, [appState]);

  function getMainComponent() {
    switch (appState.name) {
      case "init":
        return <p>Initializing...</p>;
      case "pairing":
        return <ScanWeb3ModalQR
            onScan={(pairURI) => setAppState({name: "do_pair", pairURI})}
            onError={(err) => alert(err)}
            onCancel={() => setAppState({"name": "paired"})}
        />;
      case "paired":
        return <ListPairings
            haloAddress={haloAddress}
            onStartPairing={() => setAppState({"name": "pairing"})}
            onSwitchHalo={(addr) => updateHaloAddress(addr)}
            onResetWallet={() => postResetWallet()}
        />;
      case "do_pair":
        return <p className={"label-text"}>Pairing...</p>;
      case "session_proposal":
        return <SessionProposal
            proposal={appState.proposal}
            haloAddress={haloAddress}
            onProposalProcessed={(addr) => {
              updateHaloAddress(addr);
              switchToMainScreen();
            }}
            onProposalDenied={() => {
              switchToMainScreen();
            }}
        />;
      case "session_request":
        return <SessionRequest
            sessionRequest={appState.request}
            haloAddress={haloAddress}
            onRequestProcessed={() => switchToMainScreen()}
        />;
      default:
        return <p className={"label-text"}>Unknown app state.</p>;
    }
  }

  return (
      <Wrapper>
        <Header />
        {getMainComponent()}
      </Wrapper>
  );
}

export default App;
