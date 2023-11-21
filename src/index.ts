import type { HexString } from '@zcloak/crypto/types';
import type { DidUrl } from '@zcloak/did-resolver/types';
import type { Proof } from '@zcloak/vc/types';
import type { VerifiableCredentialVersion } from '@zcloak/vc/types';
import dayjs from 'dayjs';
import {
    initCrypto
} from '@zcloak/crypto';
import { eip712_sign_kyc, sui_sign_kyc } from './signatureHandler';
import { Keyring } from '@zcloak/keyring';
import { u8aToHex, hexToU8a } from '@polkadot/util'
import { fromMnemonic } from '@zcloak/did/keys';

// ======================== phase 0: The PublicVC Field ====================================
// The following metadata should be passed from web to server
let userDid: DidUrl = 'did:zk:0x11f8b77F34FCF14B7095BF5228Ac0606324E82D1';
let ctype: HexString =
    '0xd31523b3ce506cceffa8e987e4c7a21299e93c4f28614d5da7d1026e6cf3490b';
let vcVersion: VerifiableCredentialVersion = '2';
let issuanceDate: number = 1698305373148;
let expirationDate: number = 0;
let digest: HexString = '0xdc89fd99ed289caf9bc69fba4f9d64f12969b25ccdaa9eeada03e8eda21694b0';
let attesterDid: DidUrl = 'did:zk:0xFeDE01Ff4402e35c6f6d20De9821d64bDF4Ba563';
let attesterProof: Proof = {
    type: 'EcdsaSecp256k1SignatureEip191',
    created: 1698305373157,
    verificationMethod: 'did:zk:0xFeDE01Ff4402e35c6f6d20De9821d64bDF4Ba563#key-0',
    proofPurpose: 'assertionMethod',
    proofValue: 'z8SNPwL1a8Km1Xni3u5R4kmWyeeKm1wPyNU3qy4Ar3uMAFcYJNL5sqaLsR2DcU5SbUWQ2r8upbHBAKkT7sQQvwUyUC'
};

// VC Claim Info
let on_chain_address: string = '0x05476EE9235335ADd2e50c09B2D16a3A2cC4ebEC';

// the client send the following 4 params
let network: string = 'bfc';
let chainID: number = 420;
let contractAddr: string = '0x16DD27b59cAa6C2D67cB328EDad7E3Df19a59c60';

// let timestamp: number =  dayjs().toDate().getTime();
let timestamp: number = 1697708475764;

initCrypto().then(async () => {
    // ============= phase 1: fetch VC, check VC validity ================================
    // isVC? || computeRoothash, computeDigest, checkSignature || notCheck

    // the digest is from PublicVC, no need client to send

    // ============= phase 2: Server Sign Signature ================================

    const result = await kyc_signer(
        digest,
        false,
        network
        // chainID,
        // contractAddr
    );
    console.log(result);
}
);


// ================================== Main Function ========================================
async function kyc_signer(
    digest: HexString,
    isKYA: boolean,
    network: string,
    chainID?: number,
    contractAddress?: string,
): Promise<[Uint8Array, number, number?]> {
    // ========== phase 0 : Create & Run a Verifier DID in server ============
    // should be replaced with the true verifier, here is a `demo` verifier

    let mnemonic =
        'health correct setup usage father decorate curious copper sorry recycle skin equal';
    const testKeyring = new Keyring();

    const did = fromMnemonic(testKeyring, mnemonic);
    const controllerPath = `/m/44'/60'/0'/0/0`;
    const controller = testKeyring.addFromMnemonic(mnemonic, controllerPath, 'ecdsa');
    
    const controllerEd25519 = testKeyring.addFromMnemonic(mnemonic, controllerPath, 'ed25519');


    let verifier_signature: Uint8Array = new Uint8Array();

    // ========== phase 0 : Verifier should make a signature for the whole process(text) ====
    let riskScore;
    if (isKYA) {
        riskScore = fetch_kya_result(network, on_chain_address);

        if (network === `eth` && chainID !== undefined && contractAddress !== undefined){
            verifier_signature = eip712_sign_kyc(
                controller,
                digest,
                chainID,
                contractAddress,
                timestamp,
                riskScore
            );
        } else if (network === `bfc` || `sui`){
            verifier_signature = sui_sign_kyc(
                controllerEd25519,
                digest,
                network,
                timestamp,
                riskScore
            );
        } else throw new Error(`Not support ${network} yet...`);
    } else {
        if (network === `eth` && chainID !== undefined && contractAddress !== undefined){
            verifier_signature = eip712_sign_kyc(
                controller,
                digest,
                chainID,
                contractAddress,
                timestamp
            );
        } else if (network === `bfc` || `sui`){
            verifier_signature = sui_sign_kyc(
                controllerEd25519,
                digest,
                network,
                timestamp
            );
        } else throw new Error(`Not support ${network} yet...`);
    }
    console.log(u8aToHex(verifier_signature))
    return [verifier_signature, timestamp, isKYA? riskScore : undefined];
}


function fetch_kya_result(network: string, address: string): number {
    //  curl --location --request POST 'https://api.chaintool.ai/kya/v2/risk_score?network=Ethereum&address=0x3d2a23ead4a6e2b8ff973250e56d70cc78353c50' \
    //--header 'Content-Type: application/json' \
    // --header 'TOKEN: {your token}

    // parse curl result to get the Risk Score

    // return the KYA Risk Score * 10; suggest the curl result is 33
    return 33;
}