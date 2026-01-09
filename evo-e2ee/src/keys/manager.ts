// src/keys/manager.ts
import { RSA } from '../core/rsa';
import { IKeyStorage, KeyPair } from './storage';

export class KeyManager {
    private currentKeyPair: KeyPair | null = null;

    constructor(
        private rsa: RSA,
        private storage: IKeyStorage
    ) { }

    async init(): Promise<KeyPair> {
        const existing = await this.storage.loadKeyPair();
        if (existing) {
            this.currentKeyPair = existing;
            return existing;
        }

        // Generate new if missing
        const { publicKey, privateKey } = await this.rsa.generateKeyPair();
        const newKey: KeyPair = {
            publicKey,
            privateKey,
            version: 1 // Simple versioning start
        };

        await this.storage.saveKeyPair(newKey);
        this.currentKeyPair = newKey;
        return newKey;
    }

    getKeyPair(): KeyPair {
        if (!this.currentKeyPair) {
            throw new Error('EvoE2EE not initialized. Call init() first.');
        }
        return this.currentKeyPair;
    }
}
