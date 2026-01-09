import { CryptoProvider } from '../types';
export declare class BrowserCryptoProvider implements CryptoProvider {
    private get subtle();
    private get crypto();
    randomBytes(size: number): Uint8Array;
    aesEncrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Promise<{
        ciphertext: Uint8Array;
        tag: Uint8Array;
    }>;
    aesDecrypt(key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array): Promise<Uint8Array>;
    generateEcKeyPair(type: 'signing' | 'encryption'): Promise<{
        publicKey: Uint8Array;
        privateKey: Uint8Array;
    }>;
    importKey(keyData: Uint8Array, type: 'public' | 'private', algorithm: 'ECDH' | 'ECDSA' | 'AES-GCM' | 'HKDF'): Promise<any>;
    deriveSharedSecret(privateKey: any, publicKey: any): Promise<Uint8Array>;
    sign(privateKey: any, data: Uint8Array): Promise<Uint8Array>;
    verify(publicKey: any, data: Uint8Array, signature: Uint8Array): Promise<boolean>;
    deriveKey(masterKey: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array>;
}
