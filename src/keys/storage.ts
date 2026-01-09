// src/keys/storage.ts

export interface KeySchema {
    identityKey: {
        publicKey: Uint8Array;
        privateKey: Uint8Array;
    };
    encryptionKey: {
        publicKey: Uint8Array;
        privateKey: Uint8Array;
    };
    version: number;
}

export interface IKeyStorage {
    saveKeys(keys: KeySchema): Promise<void>;
    loadKeys(): Promise<KeySchema | null>;
}

export class InMemoryKeyStorage implements IKeyStorage {
    private keys: KeySchema | null = null;

    async saveKeys(keys: KeySchema): Promise<void> {
        this.keys = keys;
    }

    async loadKeys(): Promise<KeySchema | null> {
        return this.keys;
    }
}
