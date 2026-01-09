import { CryptoProvider } from '../types';
export declare class ECC {
    private provider;
    constructor(provider: CryptoProvider);
    generateKeyPair(type: 'signing' | 'encryption'): Promise<{
        publicKey: Uint8Array;
        privateKey: Uint8Array;
    }>;
    deriveSharedSecret(privateKeyRaw: Uint8Array, publicKeyRaw: Uint8Array): Promise<Uint8Array>;
    sign(privateKeyRaw: Uint8Array, data: Uint8Array): Promise<Uint8Array>;
    verify(publicKeyRaw: Uint8Array, data: Uint8Array, signature: Uint8Array): Promise<boolean>;
}
