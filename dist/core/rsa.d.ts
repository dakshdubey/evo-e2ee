import { CryptoProvider } from '../types';
export declare class RSA {
    private provider;
    constructor(provider: CryptoProvider);
    generateKeyPair(): Promise<any>;
    encryptKey(keyData: Uint8Array, publicKey: any): Promise<Uint8Array>;
    decryptKey(encryptedKey: Uint8Array, privateKey: any): Promise<Uint8Array>;
}
