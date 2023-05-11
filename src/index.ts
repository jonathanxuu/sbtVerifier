import type { HexString } from "@zcloak/crypto/types";
import type { DidUrl } from "@zcloak/did-resolver/types";
import type { Proof } from "@zcloak/vc/types";
import type { VerifiableCredentialVersion } from "@zcloak/vc/types";
import {
    ethereumEncode,
    initCrypto,
    keccak256AsU8a,
    secp256k1PairFromSeed,
} from "@zcloak/crypto";
import { caclculateDigest } from "./digestHandler";
import { verify_digest_signature } from "./didHandler";
import { eip712_sign } from "./signatureHandler";
import { keys } from "@zcloak/did";
import { Keyring } from "@zcloak/keyring";
import { mnemonicToMiniSecret } from "@zcloak/crypto";
import { u8aToHex, hexToU8a } from "@polkadot/util"
import { fromMnemonic } from "@zcloak/did/keys";
const hdkey = require("hdkey"); // wallet lib
const bip39 = require("bip39"); // mnemonic generator
const ethUtil = require('ethereumjs-util');

// == phase 0: ZKP Generated (Generated in zkID Wallet, send to Server To Verify)  =====
// The following metadata should be passed from web to server
let user_did: DidUrl = "did:zk:0x57E7b664aaa7C895878DdCa5790526B9659350Ec";
let ctype: HexString =
    "0x824c9cd9f7fe36c33a2ded2c4b17be4b0d8a159f57baa193213e7365be1118bd";
let vc_version: VerifiableCredentialVersion = "1";
let issuance_date: number = 1682562340054;
let expiration_date: number = 0;

let attester_did: DidUrl = "did:zk:0x11f8b77F34FCF14B7095BF5228Ac0606324E82D1";
let attester_proof: Proof = {
    type: "EcdsaSecp256k1SignatureEip191",
    created: 1682562340059,
    verificationMethod: "did:zk:0x11f8b77F34FCF14B7095BF5228Ac0606324E82D1#key-0",
    proofPurpose: "assertionMethod",
    proofValue:
        "zHAuGCo9NCbqXXAzZtDXaAskCmmzbqETcH73M1noU3LNAQAAfgUDtcc4CQSLv4kd1fdvSPb8kFupPTbz6kPDcSpz6K",
};
let zkp_result: string = `{"outputs":{"stack":[8,12,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"overflow_addrs":[0,1]},"starkproof":{"proof":{"context":{"trace_layout":{"main_segment_width":72,"aux_segment_widths":[9],"aux_segment_rands":[16],"num_aux_segments":1},"trace_length":1024,"trace_meta":[],"field_modulus_bytes":[1,0,0,0,255,255,255,255],"options":{"num_queries":27,"blowup_factor":8}}}}}`;
let program_hash: string =
    "415a479f191532b76f464c2f0368acf528ff4d1c525c3bc88f63a6ecf3d71872";
let stack_input: string = "655660800";

initCrypto().then(async () => {
    const result = await sbt_verifier(
        user_did,
        ctype,
        vc_version,
        issuance_date,
        expiration_date,
        attester_did,
        attester_proof,
        zkp_result,
        program_hash,
        stack_input
    );
    console.log(result);
}
);

// ================================== Main Function ========================================
async function sbt_verifier(
    user_did: DidUrl,
    ctype: HexString,
    vc_version: VerifiableCredentialVersion,
    issuanceDate: number,
    expirationDate: number,
    attester_did: DidUrl,
    attester_proof: Proof,
    zkp_result: string,
    program_hash: string,
    stack_input: string
): Promise<[Uint8Array, string]> {
    // ============= phase 1: ZKP send to the Rust Verifier ================================
    // The Rust Verifier should verify whether the ZKP is valid, and return the roothash and security_level(u32)

    let [roothash, is_valid]: [HexString, boolean] =
        verify_zk_program_in_server(program_hash, stack_input, zkp_result);

    if (!is_valid) {
        throw new Error("The ZKP Proof is invalid");
    }

    let current_time = new Date();
    let compare_time = current_time.setFullYear(current_time.getFullYear() - 18);

    if (
        (program_hash == "415a479f191532b76f464c2f0368acf528ff4d1c525c3bc88f63a6ecf3d71872" || program_hash == "3bfa5c8dd5c05a80b53218367d743dd9afc80ce947b96742328cec28a8228b38")
        &&
        Number(stack_input) >= new Date(compare_time).getTime() / 1000
    ) {
        throw new Error("The public input used in the program is invalid");
    }
    // ========== phase 2: Restore the digest and check the attester's signature ===========

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

    // ========== phase 3: Generate the SBT Picture and upload that on Arweave =============

    let sbt_link: string = upload_sbt_to_arweave(
        user_did,
        expirationDate,
        attester_did,
        program_hash,
        zkp_result
    );

    // ========== phase 4: Verifier should make a signature for the whole process(text) ====

    // should be replaced with the true verifier, here is a `demo` verifier
    let mnemonic =
        "health correct setup usage father decorate curious copper sorry recycle skin equal";
    const testKeyring = new Keyring();

    const did = fromMnemonic(testKeyring, mnemonic);
    const controllerPath = `/m/44'/60'/0'/0/0`;
    const controller = testKeyring.addFromMnemonic(mnemonic, controllerPath, 'ecdsa');

    let verifier_signature: Uint8Array = eip712_sign(
        user_did,
        ctype,
        program_hash,
        digest,
        did.identifier,
        controller,
        attester_did,
        zkp_result,
        issuance_date,
        expiration_date,
        vc_version,
        sbt_link
    );
    return [verifier_signature, sbt_link];
}

// ================================= Helper ============================================
function verify_zk_program_in_server(
    program_hash: string,
    stack_input: string,
    zkp_result: string
): [HexString, boolean] {
    // ZKP Verifier inputs: program_hash, stack_inputs, zkp_result
    // ZKP Verifier outputs: roothash, is_valid
    let roothash: HexString =
        "0x3f209f25b1594a778f0f65522e5d53c7bc7ae78923418b45472e02bb361629e4";
    let is_valid = true;
    return [roothash, is_valid];
}

function upload_sbt_to_arweave(
    user_did: DidUrl,
    expirationDate: number,
    attester_did: DidUrl,
    program_hash: string,
    zkp_result: string
): string {
    // return the Arweave link of the SBT picture
    return "ar:///MzXyO8ZH3dyyp9wdXAVuUT57vGLFifs3TnskClOoFSQ";
}


