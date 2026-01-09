// src/core/hkdf.ts
import { CryptoProvider } from '../types';

export class HKDF {
    constructor(private provider: CryptoProvider) { }

    async deriveKey(
        masterKey: Uint8Array,
        salt: Uint8Array = new Uint8Array(0),
        info: Uint8Array = new Uint8Array(0),
        length: number = 32 // Default for AES-256
    ): Promise<Uint8Array> {
        return this.provider.deriveKey(masterKey, salt, info, length);
    }
}
