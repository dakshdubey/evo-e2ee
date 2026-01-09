"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.KeyManager = void 0;
class KeyManager {
    constructor(ecc, storage) {
        this.ecc = ecc;
        this.storage = storage;
        this.currentKeys = null;
    }
    async init() {
        const existing = await this.storage.loadKeys();
        if (existing) {
            this.currentKeys = existing;
            return existing;
        }
        const identityKey = await this.ecc.generateKeyPair('signing');
        const encryptionKey = await this.ecc.generateKeyPair('encryption');
        const newKeys = {
            identityKey,
            encryptionKey,
            version: 2
        };
        await this.storage.saveKeys(newKeys);
        this.currentKeys = newKeys;
        return newKeys;
    }
    getKeys() {
        if (!this.currentKeys) {
            throw new Error('EvoE2EE not initialized. Call init() first.');
        }
        return this.currentKeys;
    }
}
exports.KeyManager = KeyManager;
