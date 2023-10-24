import type { HexString } from "@zcloak/crypto/types";
import type { DidUrl } from "@zcloak/did-resolver/types";
import type { Proof } from "@zcloak/vc/types";
import type { VerifiableCredentialVersion } from "@zcloak/vc/types";
import dayjs from 'dayjs';
import {
    initCrypto
} from "@zcloak/crypto";
import { caclculateDigest } from "./digestHandler";
import { verify_digest_signature } from "./didHandler";
import { eip712_sign } from "./signatureHandler";
import { Keyring } from "@zcloak/keyring";
import { u8aToHex, hexToU8a } from "@polkadot/util"
import { fromMnemonic } from "@zcloak/did/keys";

// == phase 0: ZKP Generated (Generated in zkID Wallet, send to Server To Verify)  =====
// The following metadata should be passed from web to server
let user_did: DidUrl = "did:zk:0x11f8b77F34FCF14B7095BF5228Ac0606324E82D1";
let ctype: HexString =
    "0x8a841a46b6e683a2b63c995f23a5590c946731007b451209711a239f2030a387";
let vc_version: VerifiableCredentialVersion = "1";
let issuance_date: number = 1697527231422;
let expiration_date: number = 0;

let attester_did: DidUrl = "did:zk:0xFeDE01Ff4402e35c6f6d20De9821d64bDF4Ba563";
let attester_proof: Proof = {
    type: 'EcdsaSecp256k1SignatureEip191',
    created: 1697527231429,
    verificationMethod: 'did:zk:0xFeDE01Ff4402e35c6f6d20De9821d64bDF4Ba563#key-0',
    proofPurpose: 'assertionMethod',
    proofValue: 'z8j93B63TCHAXSrAHDyydGXDCkTAg28XZHFXov3MJ7iMstihNFhRvYCTUBxaQD4qfFrmpGjAqjHcSkXJXuauYSoVwv'
};

let claimUserEthAddr: string = '05476EE9235335ADd2e50c09B2D16a3A2cC4ebEC';
let claimStatus: number = 1;
let chainID: number = 420;
let contractAddr: string = '0xe7366703cE41FfEfd0f6890ec484280Dc88B543b';

// let timestamp: number =  dayjs().toDate().getTime();
let timestamp: number = 1697708475764;

initCrypto().then(async () => {
    const result = await kyc_verifier(
        user_did,
        ctype,
        vc_version,
        issuance_date,
        expiration_date,
        attester_did,
        attester_proof
    );
    console.log(result);
}
);

// ================================== Main Function ========================================
async function kyc_verifier(
    user_did: DidUrl,
    ctype: HexString,
    vc_version: VerifiableCredentialVersion,
    issuanceDate: number,
    expirationDate: number,
    attester_did: DidUrl,
    attester_proof: Proof,
): Promise<[Uint8Array]> {
    // ============= phase 1: check VC validity ================================
    // isVC? || computeRoothash, computeDigest, checkSignature || notCheck
    let roothash: HexString =
        "0xca2cf029af6532f7683dee845f22dd0263d2abd3e5ea188245681e33274bd4f9";

    const digest: HexString = caclculateDigest(
        roothash,
        user_did,
        issuanceDate,
        expirationDate,
        ctype,
        vc_version
    );

    const signature_verify_result: boolean = await verify_digest_signature(
        attester_did,
        attester_proof,
        digest,
        vc_version
    );

    // ========== phase 2: Verifier should make a signature for the whole process(text) ====

    // should be replaced with the true verifier, here is a `demo` verifier
    let mnemonic =
        "health correct setup usage father decorate curious copper sorry recycle skin equal";
    const testKeyring = new Keyring();

    const did = fromMnemonic(testKeyring, mnemonic);
    const controllerPath = `/m/44'/60'/0'/0/0`;
    const controller = testKeyring.addFromMnemonic(mnemonic, controllerPath, 'ecdsa');
    console.log(did.identifier)
    let verifier_signature: Uint8Array = eip712_sign(
        user_did,
        ctype,
        controller,
        issuance_date,
        expiration_date,
        claimUserEthAddr,
        claimStatus,
        chainID,
        contractAddr,
        timestamp
    );
    console.log(u8aToHex(verifier_signature))
    return [verifier_signature];
}


