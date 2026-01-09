// src/index.ts
import { CryptoProvider, EncryptedMessage } from './types';
import { NodeCryptoProvider } from './adapters/node';
import { BrowserCryptoProvider } from './adapters/browser';
import { AES } from './core/aes';
import { RSA } from './core/rsa';
import { HKDF } from './core/hkdf';
import { KeyManager } from './keys/manager';
import { InMemoryKeyStorage } from './keys/storage';
import { toBase64, fromBase64, concatBuffers } from './utils';

export interface InitOptions {
    appId: string;
    platform: 'node' | 'react' | 'browser';
    storage?: any; // Allow custom storage injection
}

export class EvoE2EE {
    private provider!: CryptoProvider;
    private aes!: AES;
    private rsa!: RSA;
    private hkdf!: HKDF;
    private keyManager!: KeyManager;
    private initialized = false;

    async init(options: InitOptions) {
        if (this.initialized) return;

        // Platform selection
        if (options.platform === 'node') {
            this.provider = new NodeCryptoProvider();
        } else {
            this.provider = new BrowserCryptoProvider();
        }

        this.aes = new AES(this.provider);
        this.rsa = new RSA(this.provider);
        this.hkdf = new HKDF(this.provider);

        // Key Storage selection - Default to Memory for now to satisfy safety (no disk leak by default)
        // In a real app, user might pass a custom storage adapter or we implement IndexedDB default for browser.
        const storage = options.storage || new InMemoryKeyStorage(); // Default to memory safe

        this.keyManager = new KeyManager(this.rsa, storage);
        await this.keyManager.init();

        this.initialized = true;
    }

    /*
     * Encrypts data for the current user (storage scenario).
     * Generates a random session key, encrypts data, then encrypts session key with user's Public Key.
     */
    async encrypt(data: string): Promise<EncryptedMessage> {
        this.checkInit();

        const dataBytes = new TextEncoder().encode(data);
        const keyPair = this.keyManager.getKeyPair();

        // 1. Generate Session Key (32 bytes for AES-256)
        const sessionKeyRaw = this.provider.randomBytes(32);

        // 2. Encrypt Data
        const { ciphertext, iv, tag } = await this.aes.encrypt(dataBytes, sessionKeyRaw);

        // combine ciphertext + tag for storage if platform doesn't do it, 
        // BUT our AES adapter returns standard { ciphertext, tag }.
        // Common standard for AES-GCM output is IV + Ciphertext + Tag.
        // The prompt asks for IV separately in the object. 
        // So we store Ciphertext + Tag in 'cipherText' field?
        // "cipherText: string" usually implies the payload.
        // Let's stick tag to ciphertext to keep it simple and safe (binding).
        const fullCiphertext = concatBuffers(ciphertext, tag);

        // 3. Encrypt Session Key with RSA
        const encryptedKey = await this.rsa.encryptKey(sessionKeyRaw, keyPair.publicKey);

        // 4. Return formatted object
        return {
            cipherText: toBase64(fullCiphertext),
            encryptedKey: toBase64(encryptedKey),
            iv: toBase64(iv),
            version: 1
        };
    }

    async decrypt(message: EncryptedMessage): Promise<string> {
        this.checkInit();

        const keyPair = this.keyManager.getKeyPair();

        // 1. Decode inputs
        const encryptedKeyBytes = fromBase64(message.encryptedKey);
        const ivBytes = fromBase64(message.iv);
        const fullCiphertextBytes = fromBase64(message.cipherText);

        // 2. Decrypt Session Key
        const sessionKey = await this.rsa.decryptKey(encryptedKeyBytes, keyPair.privateKey);

        // 3. Split Ciphertext and Tag
        // Tag is last 16 bytes
        const tagLength = 16;
        if (fullCiphertextBytes.length < tagLength) {
            throw new Error('Invalid ciphertext length');
        }
        const ciphertext = fullCiphertextBytes.slice(0, fullCiphertextBytes.length - tagLength);
        const tag = fullCiphertextBytes.slice(fullCiphertextBytes.length - tagLength);

        // 4. Decrypt Data
        const decryptedBytes = await this.aes.decrypt(ciphertext, sessionKey, ivBytes, tag);

        return new TextDecoder().decode(decryptedBytes);
    }

    private checkInit() {
        if (!this.initialized) {
            throw new Error('EvoE2EE not initialized. Call init() first.');
        }
    }
}

// Export singleton instance for easy usage
export const evoE2EE = new EvoE2EE();
