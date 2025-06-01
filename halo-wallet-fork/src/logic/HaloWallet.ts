import {getAddress} from "@ethersproject/address";
import {Provider, TransactionRequest, TransactionResponse} from "@ethersproject/abstract-provider";
import {Signer, TypedDataDomain, TypedDataField, TypedDataSigner} from "@ethersproject/abstract-signer";
import {Bytes, hexlify, joinSignature} from "@ethersproject/bytes";
import {_TypedDataEncoder, hashMessage} from "@ethersproject/hash";
import {keccak256} from "@ethersproject/keccak256";
import {Deferrable, defineReadOnly, resolveProperties} from "@ethersproject/properties";
import {serialize, UnsignedTransaction} from "@ethersproject/transactions";
import {BytesLike, computeAddress, isAddress} from "ethers";
import {execHaloCmdWeb} from '@arx-research/libhalo/api/web.js';

export class HaloWallet extends Signer implements TypedDataSigner {
    readonly address: string;
    readonly provider: Provider;

    constructor(address: string, provider?: Provider) {
        super();

        defineReadOnly(this, "address", address);

        //if (provider && !Provider.isProvider(provider)) {
        //    throw new Error("invalid provider");
        //}

        defineReadOnly(this, "provider", provider || null);
    }

    getAddress(): Promise<string> {
        return Promise.resolve(this.address);
    }

    connect(provider: Provider): HaloWallet {
        return new HaloWallet(this.address, provider);
    }

    async resolveName(name: string): Promise<string> {
        if (isAddress(name)) {
            return Promise.resolve(name);
        }

        this._checkProvider("resolveName");
        return await this.provider.resolveName(name);
    }

    async sendTransaction(transaction: Deferrable<TransactionRequest>): Promise<TransactionResponse> {
        this._checkProvider("sendTransaction");
        const tx = await this.populateTransaction(transaction);
        const signedTx = await this.signTransaction(tx);
        return await this.provider.broadcastTransaction(signedTx);
    }

    async signDigest(digest: BytesLike): Promise<string> {
        let res;

        try {
            res = await execHaloCmdWeb({
                "name": "sign",
                "keyNo": 1,
                "digest": hexlify(digest).substring(2)
            });
        } catch (e) {
            throw e;
        }

        let signAddr = computeAddress('0x' + res.publicKey);

        if (signAddr !== this.address) {
            throw new Error("This HaLo card is not currently active. Switch HaLo first.");
        }

        return res.signature.ether;
    }

    async signTransaction(transaction: TransactionRequest): Promise<string> {
        let tx = await resolveProperties(transaction);

        if (tx.from != null) {
            if (getAddress(tx.from) !== this.address) {
                throw new Error("transaction from address mismatch");
            }
            delete tx.from;
        }

        const signature = await this.signDigest(keccak256(serialize(<UnsignedTransaction>tx)));
        return serialize(<UnsignedTransaction>tx, signature);
    }

    async signMessage(message: Bytes | string): Promise<string> {
        return joinSignature(await this.signDigest(hashMessage(message)));
    }

    async _signTypedData(domain: TypedDataDomain, types: Record<string, Array<TypedDataField>>, value: Record<string, any>): Promise<string> {
        // Populate any ENS names
        const populated = await _TypedDataEncoder.resolveNames(domain, types, value, (name: string) => {
            if (this.provider == null) {
                throw new Error("cannot resolve ENS names without a provider");
            }
            return this.provider.resolveName(name);
        });

        return joinSignature(await this.signDigest(_TypedDataEncoder.hash(populated.domain, types, populated.value)));
    }
}
