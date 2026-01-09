// src/keys/storage.ts
export interface KeyPair {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
    version: number;
}

export interface IKeyStorage {
    saveKeyPair(keyPair: KeyPair): Promise<void>;
    loadKeyPair(): Promise<KeyPair | null>;
}

export class InMemoryKeyStorage implements IKeyStorage {
    private keyPair: KeyPair | null = null;

    async saveKeyPair(keyPair: KeyPair): Promise<void> {
        this.keyPair = keyPair;
    }

    async loadKeyPair(): Promise<KeyPair | null> {
        return this.keyPair;
    }
}
