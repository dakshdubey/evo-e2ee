// src/core/aes.ts
import { CryptoProvider } from '../types';

export class AES {
    constructor(private provider: CryptoProvider) { }

    async encrypt(data: Uint8Array, key: Uint8Array): Promise<{ ciphertext: Uint8Array; iv: Uint8Array; tag: Uint8Array }> {
        const iv = this.provider.randomBytes(12); // Standard GCM IV size
        const { ciphertext, tag } = await this.provider.aesEncrypt(key, iv, data);
        return { ciphertext, iv, tag };
    }

    async decrypt(ciphertext: Uint8Array, key: Uint8Array, iv: Uint8Array, tag: Uint8Array): Promise<Uint8Array> {
        // Validate IV length
        if (iv.length !== 12) {
            throw new Error('Invalid IV length. Must be 12 bytes.');
        }
        return this.provider.aesDecrypt(key, iv, ciphertext, tag);
    }
}
