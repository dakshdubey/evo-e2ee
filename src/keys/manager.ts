// src/keys/manager.ts
import { ECC } from '../core/ecc';
import { IKeyStorage, KeySchema } from './storage';

export class KeyManager {
    private currentKeys: KeySchema | null = null;

    constructor(
        private ecc: ECC,
        private storage: IKeyStorage
    ) { }

    async init(): Promise<KeySchema> {
        const existing = await this.storage.loadKeys();
        if (existing) {
            this.currentKeys = existing;
            return existing;
        }

        // Generate Identity Key (ECDSA)
        const identityKey = await this.ecc.generateKeyPair('signing');

        // Generate Encryption Key (ECDH)
        const encryptionKey = await this.ecc.generateKeyPair('encryption');

        const newKeys: KeySchema = {
            identityKey,
            encryptionKey,
            version: 2 // ECC Version
        };

        await this.storage.saveKeys(newKeys);
        this.currentKeys = newKeys;
        return newKeys;
    }

    getKeys(): KeySchema {
        if (!this.currentKeys) {
            throw new Error('EvoE2EE not initialized. Call init() first.');
        }
        return this.currentKeys;
    }
}
