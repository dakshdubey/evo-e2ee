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
export declare class InMemoryKeyStorage implements IKeyStorage {
    private keys;
    saveKeys(keys: KeySchema): Promise<void>;
    loadKeys(): Promise<KeySchema | null>;
}
