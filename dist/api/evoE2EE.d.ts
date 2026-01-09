import { EncryptedMessage } from '../types';
export interface InitOptions {
    appId: string;
    platform: 'node' | 'react' | 'browser';
    storage?: any;
}
export declare class EvoE2EE {
    private provider;
    private aes;
    private ecc;
    private hkdf;
    private keyManager;
    private initialized;
    init(options: InitOptions): Promise<void>;
    encrypt(data: string, recipientPublicKeyBase64?: string): Promise<EncryptedMessage>;
    decrypt(message: EncryptedMessage, senderIdentityKeyBase64?: string): Promise<string>;
    getPublicKeys(): {
        identityKey: string;
        encryptionKey: string;
    };
    private checkInit;
}
export declare const evoE2EE: EvoE2EE;
