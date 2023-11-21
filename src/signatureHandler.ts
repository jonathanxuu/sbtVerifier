import { encodeData, getMessage, structHash } from '@zcloak/crypto/eip712/eip712';
import type { DidUrl } from '@zcloak/did-resolver/types';
import type { HexString } from '@zcloak/crypto/types';
import { parseDid } from '@zcloak/did-resolver/parseDid'
import { KeyringPair } from "@zcloak/keyring/types"
import { hexToU8a, isU8a, u8aConcat, u8aToBuffer, u8aToU8a, u8aToHex } from '@polkadot/util';
import { stringToU8a, numberToU8a } from '@polkadot/util';
import { keccak256AsHex, keccak256AsU8a } from '@zcloak/crypto';
import { sha256 } from '@noble/hashes/sha256';

const EIP_191_PREFIX = hexToU8a('0x1901');

function paddingU8a(inputArray: Uint8Array): Uint8Array{
    if (inputArray.length == 32) {
        return inputArray;
      }
    
      const paddedArray = new Uint8Array(32);
      paddedArray.set(inputArray, 32 - inputArray.length);
    
      return paddedArray;
}

function concatAll(
    digest: HexString,
    network: String,
    timestamp: number,
    riskScore?: number
): Uint8Array {
    let digestU8a = hexToU8a(digest);
    let networkU8a = stringToU8a(network);
    let timestampU8a = paddingU8a(numberToU8a(timestamp));
    let concatU8a: Uint8Array = new Uint8Array();

    if( riskScore === undefined ){
        concatU8a = u8aConcat(digestU8a, networkU8a, timestampU8a);
    } else {
        let riskScoreU8a = paddingU8a(numberToU8a(riskScore));
        concatU8a = u8aConcat(digestU8a, networkU8a, timestampU8a, riskScoreU8a);
    }
    return concatU8a;
}


export function sui_sign_kyc(
    keypair: KeyringPair,
    digest: HexString,
    network: String,
    timestamp: number,
    riskScore?: number
): Uint8Array {
    const concatData = concatAll(
        digest,
        network,
        timestamp,
        riskScore
    );
    let a = u8aToHex(sha256(concatData));
    const signature = keypair.sign(sha256(concatData));
    return signature;

}

export function eip712_sign_kyc(
    keypair: KeyringPair,
    digest: HexString,
    chainID: number,
    contractAddr: string,
    timestamp: number,
    riskScore?: number
): Uint8Array {
    let typedData = construct_typedData(
        digest,
        chainID,
        contractAddr,
        timestamp,
        riskScore
    );

    const message = getMessage(typedData, true);
    const signature = keypair.sign(message);
    return signature;
}

function construct_typedData(
    digest: HexString,
    chainID: number,
    contractAddr: string,
    timestamp: number,
    riskScore?: number
) {
    if (riskScore === undefined) {
        const typedData = {
            types: {
                EIP712Domain: [
                    { name: 'name', type: 'string' },
                    { name: 'version', type: 'string' },
                    { name: 'chainId', type: 'uint256' },
                    { name: 'verifyingContract', type: 'address' }
                ],
                signature: [
                    { name: 'digest', type: 'bytes32' },
                    { name: 'chainId', type: 'uint256' },
                    { name: 'contractAddr', type: 'address' },
                    { name: 'timestamp', type: 'uint256' },
                ]
            },
            primaryType: 'signature',
            // change when the final contract is deployed
            domain: {
                name: 'SigVerify',
                version: '0',
                // chainId: 4,
                chainId: 420, // on which chainID to use
                verifyingContract: "0x16DD27b59cAa6C2D67cB328EDad7E3Df19a59c60" // zClock Verification 
            },
            message: {
                digest: digest,
                chainId: chainID,
                contractAddr: contractAddr,
                timestamp: timestamp
            }
        }
        console.log(typedData.message)
        return typedData;
    } else {
        const typedData = {
            types: {
                EIP712Domain: [
                    { name: 'name', type: 'string' },
                    { name: 'version', type: 'string' },
                    { name: 'chainId', type: 'uint256' },
                    { name: 'verifyingContract', type: 'address' }
                ],
                signature: [
                    { name: 'digest', type: 'bytes32' },
                    { name: 'chainId', type: 'uint256' },
                    { name: 'contractAddr', type: 'address' },
                    { name: 'timestamp', type: 'uint256' },
                    { name: 'riskScore', type: 'uint256' },

                ]
            },
            primaryType: 'signature',
            // change when the final contract is deployed
            domain: {
                name: 'SigVerify',
                version: '0',
                // chainId: 4,
                chainId: 420, // on which chainID to use
                verifyingContract: "0x16DD27b59cAa6C2D67cB328EDad7E3Df19a59c60" // zClock Verification 
            },
            message: {
                digest: digest,
                chainId: chainID,
                contractAddr: contractAddr,
                timestamp: timestamp,
                riskScore: riskScore
            }
        }
        console.log(typedData.message)
        return typedData;
    }

};