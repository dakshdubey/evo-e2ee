export type Platform = 'node' | 'browser';

export interface CryptoProvider {
    randomBytes(size: number): Uint8Array;

    // AES-GCM
    aesEncrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Promise<{ ciphertext: Uint8Array; tag: Uint8Array }>;
    aesDecrypt(key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array): Promise<Uint8Array>;

    // RSA-OAEP
    generateKeyPair(): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }>; // Exported format (SPKI/PKCS8) usually, or CryptoKey handles
    importKey(keyData: Uint8Array, type: 'public' | 'private'): Promise<any>; // abstract CryptoKey
    encryptRSA(publicKey: any, data: Uint8Array): Promise<Uint8Array>;
    decryptRSA(privateKey: any, data: Uint8Array): Promise<Uint8Array>;

    // HKDF
    deriveKey(masterKey: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array>;
}

export interface EncryptedMessage {
    cipherText: string; // Base64
    encryptedKey: string; // Base64 (RSA encrypted AES key)
    iv: string; // Base64
    version: number;
}
