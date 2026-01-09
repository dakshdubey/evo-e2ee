import { CryptoProvider, EncryptedMessage } from '../types';
import { NodeCryptoProvider } from '../adapters/node';
import { BrowserCryptoProvider } from '../adapters/browser';
import { AES } from '../core/aes';
import { ECC } from '../core/ecc';
import { HKDF } from '../core/hkdf';
import { KeyManager } from '../keys/manager';
import { InMemoryKeyStorage } from '../keys/storage';
import { toBase64, fromBase64, concatBuffers } from '../utils';

export interface InitOptions {
    appId: string;
    platform: 'node' | 'react' | 'browser';
    storage?: any;
}

export class EvoE2EE {
    private provider!: CryptoProvider;
    private aes!: AES;
    private ecc!: ECC;
    private hkdf!: HKDF;
    private keyManager!: KeyManager;
    private initialized = false;

    async init(options: InitOptions) {
        if (this.initialized) return;

        if (options.platform === 'node') {
            this.provider = new NodeCryptoProvider();
        } else {
            this.provider = new BrowserCryptoProvider();
        }

        this.aes = new AES(this.provider);
        this.ecc = new ECC(this.provider);
        this.hkdf = new HKDF(this.provider);

        const storage = options.storage || new InMemoryKeyStorage();
        this.keyManager = new KeyManager(this.ecc, storage);
        await this.keyManager.init();

        this.initialized = true;
    }

    /*
       * HIGH SECURITY ENCRYPTION FLOW (WhatsApp Class)
       * 
       * 1. Generates Ephemeral ECDH Key Pair (E_pub, E_priv)
       * 2. Performs ECDH with:
       *      - Recipient's Public Key (For self-storage: Our Own Encryption Public Key)
       *      - Ephemeral Private Key
       *    -> SharedSecret
       * 3. Derives Session Key using HKDF(SharedSecret)
       * 4. Encrypts Data with AES-GCM (SessionKey)
       * 5. Signs (Ciphertext + E_pub) using Identity Private Key (Authentication)
       */
    async encrypt(data: string, recipientPublicKeyBase64?: string): Promise<EncryptedMessage> {
        this.checkInit();
        const myKeys = this.keyManager.getKeys();

        // Determine Recipient (Default to Self for storage)
        let recipientPubRaw: Uint8Array;
        if (recipientPublicKeyBase64) {
            recipientPubRaw = fromBase64(recipientPublicKeyBase64);
        } else {
            recipientPubRaw = myKeys.encryptionKey.publicKey;
        }

        // 1. Ephemeral Key
        const ephemeral = await this.ecc.generateKeyPair('encryption');

        // 2. ECDH
        const sharedSecret = await this.ecc.deriveSharedSecret(ephemeral.privateKey, recipientPubRaw);

        // 3. HKDF for AES Session Key
        // Salt can be empty or specific context. Info can be 'EvoE2EE V2'.
        const sessionKey = await this.hkdf.deriveKey(
            sharedSecret,
            new Uint8Array(0),
            new TextEncoder().encode('EvoE2EE V2-AES'),
            32 // AES-256
        );

        // 4. Encrypt Data
        const dataBytes = new TextEncoder().encode(data);
        const { ciphertext, iv, tag } = await this.aes.encrypt(dataBytes, sessionKey);
        const fullCiphertext = concatBuffers(ciphertext, tag);

        // 5. Sign (Ciphertext + Ephemeral Public Key) to prove origin and bind key
        // We bind the key to the payload to prevent key substitution attacks
        const payloadToSign = concatBuffers(fullCiphertext, ephemeral.publicKey);
        const signature = await this.ecc.sign(myKeys.identityKey.privateKey, payloadToSign);

        return {
            cipherText: toBase64(fullCiphertext),
            ephemeralPublicKey: toBase64(ephemeral.publicKey),
            signature: toBase64(signature),
            iv: toBase64(iv),
            version: 2
        };
    }

    async decrypt(message: EncryptedMessage, senderIdentityKeyBase64?: string): Promise<string> {
        this.checkInit();
        const myKeys = this.keyManager.getKeys();

        if (message.version !== 2) {
            throw new Error('Unsupported version: ' + message.version);
        }
        if (!message.ephemeralPublicKey || !message.signature) {
            throw new Error('Invalid V2 Payload: Missing ECC fields');
        }

        // Inputs
        const ephemeralPub = fromBase64(message.ephemeralPublicKey);
        const fullCiphertext = fromBase64(message.cipherText);
        const signature = fromBase64(message.signature);
        const iv = fromBase64(message.iv);

        // 1. Verify Signature (Authenticity)
        // If sender is NOT provided (Self-Decryption), verify against MY Identity Key
        let verifyKeyRaw = myKeys.identityKey.publicKey;
        if (senderIdentityKeyBase64) {
            verifyKeyRaw = fromBase64(senderIdentityKeyBase64);
        }

        const signedPayload = concatBuffers(fullCiphertext, ephemeralPub);
        const isValid = await this.ecc.verify(verifyKeyRaw, signedPayload, signature);

        if (!isValid) {
            throw new Error('Security Violation: Message Signature Invalid! (Potential Tampering or Spoofing)');
        }

        // 2. ECDH
        const sharedSecret = await this.ecc.deriveSharedSecret(myKeys.encryptionKey.privateKey, ephemeralPub);

        // 3. HKDF
        const sessionKey = await this.hkdf.deriveKey(
            sharedSecret,
            new Uint8Array(0),
            new TextEncoder().encode('EvoE2EE V2-AES'),
            32
        );

        // 4. Decrypt
        const tagLength = 16;
        if (fullCiphertext.length < tagLength) throw new Error('Invalid ciphertext');

        const ciphertext = fullCiphertext.slice(0, fullCiphertext.length - tagLength);
        const tag = fullCiphertext.slice(fullCiphertext.length - tagLength);

        const decryptedBytes = await this.aes.decrypt(ciphertext, sessionKey, iv, tag);
        return new TextDecoder().decode(decryptedBytes);
    }

    getPublicKeys() {
        this.checkInit();
        const keys = this.keyManager.getKeys();
        return {
            identityKey: toBase64(keys.identityKey.publicKey),
            encryptionKey: toBase64(keys.encryptionKey.publicKey)
        };
    }

    private checkInit() {
        if (!this.initialized) {
            throw new Error('EvoE2EE not initialized. Call init() first.');
        }
    }
}

export const evoE2EE = new EvoE2EE();
