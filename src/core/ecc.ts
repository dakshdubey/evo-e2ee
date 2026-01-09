// src/core/ecc.ts
import { CryptoProvider } from '../types';

export class ECC {
    constructor(private provider: CryptoProvider) { }

    async generateKeyPair(type: 'signing' | 'encryption') {
        return this.provider.generateEcKeyPair(type);
    }

    async deriveSharedSecret(privateKeyRaw: Uint8Array, publicKeyRaw: Uint8Array): Promise<Uint8Array> {
        const priv = await this.provider.importKey(privateKeyRaw, 'private', 'ECDH');
        const pub = await this.provider.importKey(publicKeyRaw, 'public', 'ECDH');
        return this.provider.deriveSharedSecret(priv, pub);
    }

    async sign(privateKeyRaw: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
        const priv = await this.provider.importKey(privateKeyRaw, 'private', 'ECDSA');
        return this.provider.sign(priv, data);
    }

    async verify(publicKeyRaw: Uint8Array, data: Uint8Array, signature: Uint8Array): Promise<boolean> {
        const pub = await this.provider.importKey(publicKeyRaw, 'public', 'ECDSA');
        return this.provider.verify(pub, data, signature);
    }
}
