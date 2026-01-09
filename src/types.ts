export type Platform = 'node' | 'browser';

export interface CryptoProvider {
    randomBytes(size: number): Uint8Array;

    // AES-GCM
    aesEncrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Promise<{ ciphertext: Uint8Array; tag: Uint8Array }>;
    aesDecrypt(key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array): Promise<Uint8Array>;

    // ECC (P-256)
    // type: 'signing' (ECDSA) | 'encryption' (ECDH)
    generateEcKeyPair(type: 'signing' | 'encryption'): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }>;

    // ECDH
    deriveSharedSecret(privateKey: any, publicKey: any): Promise<Uint8Array>;

    // ECDSA
    sign(privateKey: any, data: Uint8Array): Promise<Uint8Array>;
    verify(publicKey: any, data: Uint8Array, signature: Uint8Array): Promise<boolean>;

    // Key Import/Export
    importKey(
        keyData: Uint8Array,
        type: 'public' | 'private',
        algorithm: 'ECDH' | 'ECDSA' | 'AES-GCM' | 'HKDF'
    ): Promise<any>;

    // HKDF - Keep existing
    deriveKey(masterKey: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array>;
}

export interface EncryptedMessage {
    cipherText: string; // Base64
    encryptedKey?: string; // Legacy RSA support (Optional now)
    ephemeralPublicKey?: string; // Base64 (For ECDH)
    signature?: string; // Base64 (ECDSA)
    iv: string; // Base64
    version: number;
}
