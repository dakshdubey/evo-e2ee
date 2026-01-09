import { CryptoProvider } from '../types';
export declare class AES {
    private provider;
    constructor(provider: CryptoProvider);
    encrypt(data: Uint8Array, key: Uint8Array): Promise<{
        ciphertext: Uint8Array;
        iv: Uint8Array;
        tag: Uint8Array;
    }>;
    decrypt(ciphertext: Uint8Array, key: Uint8Array, iv: Uint8Array, tag: Uint8Array): Promise<Uint8Array>;
}
