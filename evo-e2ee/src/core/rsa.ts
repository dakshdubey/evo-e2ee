// src/core/rsa.ts
import { CryptoProvider } from '../types';

export class RSA {
    constructor(private provider: CryptoProvider) { }

    async generateKeyPair() {
        return this.provider.generateKeyPair();
    }

    /* 
     * Encrypts a symmetric key (usually) with the recipient's public key.
     * keyData: The raw bytes of the key to encrypt.
     * publicKey: The recipient's public key (Platform specific object or generic handle).
     */
    async encryptKey(keyData: Uint8Array, publicKey: any): Promise<Uint8Array> {
        return this.provider.encryptRSA(publicKey, keyData);
    }

    /*
     * Decrypts an encrypted key with the user's private key.
     */
    async decryptKey(encryptedKey: Uint8Array, privateKey: any): Promise<Uint8Array> {
        return this.provider.decryptRSA(privateKey, encryptedKey);
    }
}
