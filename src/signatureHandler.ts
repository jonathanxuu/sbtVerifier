import { getMessage, structHash } from '@zcloak/crypto/eip712/eip712';
import type { DidUrl } from '@zcloak/did-resolver/types';
import type { HexString } from '@zcloak/crypto/types';
import { parseDid } from '@zcloak/did-resolver/parseDid'
import { KeyringPair } from "@zcloak/keyring/types"
import { hexToU8a, isU8a, u8aConcat, u8aToBuffer, u8aToU8a } from '@polkadot/util';
const EIP_191_PREFIX = hexToU8a('0x1901');

export function eip712_sign(
    recipient: DidUrl,
    ctype: HexString,
    keypair: KeyringPair,
    issuance_date: number,
    expiration_date: number,
    claimUserEthAddr: string,
    claimStatus: number,
    chainID: number,
    contractAddr: string,
    timestamp: number
): Uint8Array {
    let typedData = constrcut_typedData(
        recipient,
        ctype,
        issuance_date,
        expiration_date,
        claimUserEthAddr,
        claimStatus,
        chainID,
        contractAddr,
        timestamp
    );

    // const message0 = u8aConcat(EIP_191_PREFIX, structHash(typedData, 'EIP712Domain', typedData.domain), structHash(typedData, typedData.primaryType, typedData.message));
    // console.log("u8a is", u8aToHex(encodeData(typedData, typedData.primaryType, typedData.message)));
    // console.log(u8aToHex(u8aConcat(EIP_191_PREFIX, structHash(typedData, 'EIP712Domain', typedData.domain), structHash(typedData, typedData.primaryType, typedData.message))));

    const message = getMessage(typedData, true);
    const signature = keypair.sign(message);
    return signature;
}


function constrcut_typedData(
    recipient: DidUrl,
    ctype: HexString,
    issuance_date: number,
    expiration_date: number,
    claimUserEthAddr: string,
    claimStatus: number,
    chainID: number,
    contractAddr: string,
    timestamp: number
) {
    const recipient_address: string = parseDid(recipient).identifier;

    const typedData = {
        types: {
            EIP712Domain: [
                { name: 'name', type: 'string' },
                { name: 'version', type: 'string' },
                { name: 'chainId', type: 'uint256' },
                { name: 'verifyingContract', type: 'address' }
            ],
            signature: [
                { name: 'userDID', type: 'address' },
                { name: 'ctype', type: 'bytes32' },
                { name: 'issuanceDate', type: 'bytes' },
                { name: 'expirationDate', type: 'bytes' },
                { name: 'claimUserEthAddr', type: 'string' },
                { name: 'claimStatus', type: 'uint256' },
                { name: 'chainID', type: 'uint256' },
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
            chainId: chainID, // hardhat test chainId
            verifyingContract: contractAddr // hardhat test contract
        },
        message: {
            userDID: recipient_address,
            ctype: ctype,
            issuanceDate: pad(issuance_date.toString(16)),
            expirationDate: pad(expiration_date.toString(16)),
            claimUserEthAddr: claimUserEthAddr,
            claimStatus: claimStatus,
            chainID: chainID,
            contractAddr: contractAddr,
            timestamp: timestamp
        }
    }
    console.log(typedData.message)
    return typedData;
};

function pad(input: string): string {
    let padding;
    if (input.length % 2 == 0) {
        padding = input;
    } else {
        padding = '0' + input;
    }
    return '0x' + padding;
}