import QrReader from "react-qr-reader-es6";
import {useState} from "react";
import Button from "./Button.tsx";
import {wcGetPairings} from "./WalletConnect";

function ScanWeb3ModalQR({onScan, onError, onCancel}) {
  let [manualURIValue, setManualURIValue] = useState('');

    let pairings = wcGetPairings();
    let hasPairings = Object.keys(pairings).length > 0;

    function evButtonDown(ev) {
        if (ev.keyCode === 13) {
            onScan(manualURIValue);
        }
    }

  return (
      <div>
        <p className={"label-text"}>Scan the WalletConnect's QR code</p>
        <QrReader
            delay={300}
            onScan={(val) => {
                if (val) {
                    onScan(val);
                }
            }}
            onError={onError}
            style={{ width: '100%' }}
        />
        <div style={{marginTop: '20px', marginBottom: '10px'}}>
            <p className={"label-text"}>Manually enter pairing URI:</p>
        </div>
          <input
              type="text"
              value={manualURIValue}
              className={"text-field"}
              onKeyDown={(ev) => evButtonDown(ev)}
              onChange={(ev) => setManualURIValue(ev.target.value)}
          />
        <div style={{margin: '10px 0'}}>
            <Button type="button" onClick={() => onScan(manualURIValue)} fullWidth={true} className={"btn-pad"}>Pair manually</Button>
            {hasPairings && <Button type="button" onClick={() => onCancel()} fullWidth={true} className={"btn-pad"}>Cancel</Button>}
        </div>
      </div>
  );
}

export default ScanWeb3ModalQR;
