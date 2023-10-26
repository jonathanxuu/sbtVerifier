import { getMessage, structHash } from '@zcloak/crypto/eip712/eip712';
import type { DidUrl } from '@zcloak/did-resolver/types';
import type { HexString } from '@zcloak/crypto/types';
import { parseDid } from '@zcloak/did-resolver/parseDid'
import { KeyringPair } from "@zcloak/keyring/types"
import { hexToU8a, isU8a, u8aConcat, u8aToBuffer, u8aToU8a } from '@polkadot/util';
const EIP_191_PREFIX = hexToU8a('0x1901');

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
                chainId: chainID, // on which chainID to use
                verifyingContract: "0x00351b372FB793D6Fa1902E6b2db2E6A7d8824E7" // zClock Verification Contract
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
                chainId: chainID, // on which chainID to use
                verifyingContract: "0x00351b372FB793D6Fa1902E6b2db2E6A7d8824E7" // zClock Verification 
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