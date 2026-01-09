// src/adapters/browser.ts
import { CryptoProvider } from '../types';

export class BrowserCryptoProvider implements CryptoProvider {
    private get subtle() {
        if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
            return window.crypto.subtle;
        }
        throw new Error('WebCrypto API not available. This environment is not supported.');
    }

    private get crypto() {
        return window.crypto;
    }

    randomBytes(size: number): Uint8Array {
        return this.crypto.getRandomValues(new Uint8Array(size));
    }

    async aesEncrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Promise<{ ciphertext: Uint8Array; tag: Uint8Array }> {
        const cryptoKey = await this.subtle.importKey(
            'raw', key, { name: 'AES-GCM' }, false, ['encrypt']
        );

        const encryptedBuffer = await this.subtle.encrypt(
            { name: 'AES-GCM', iv },
            cryptoKey,
            data
        );

        const encrypted = new Uint8Array(encryptedBuffer);
        const tagLength = 16;
        const ciphertext = encrypted.slice(0, encrypted.length - tagLength);
        const tag = encrypted.slice(encrypted.length - tagLength);

        return { ciphertext, tag };
    }

    async aesDecrypt(key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array): Promise<Uint8Array> {
        const cryptoKey = await this.subtle.importKey(
            'raw', key, { name: 'AES-GCM' }, false, ['decrypt']
        );

        const encrypted = new Uint8Array(ciphertext.length + tag.length);
        encrypted.set(ciphertext);
        encrypted.set(tag, ciphertext.length);

        try {
            const decryptedBuffer = await this.subtle.decrypt(
                { name: 'AES-GCM', iv },
                cryptoKey,
                encrypted
            );
            return new Uint8Array(decryptedBuffer);
        } catch (e) {
            throw new Error('Decryption failed');
        }
    }

    async generateKeyPair(): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
        const pair = await this.subtle.generateKey(
            {
                name: 'RSA-OAEP',
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256',
            },
            true,
            ['encrypt', 'decrypt']
        );

        const pubBuf = await this.subtle.exportKey('spki', pair.publicKey as CryptoKey);
        const privBuf = await this.subtle.exportKey('pkcs8', pair.privateKey as CryptoKey);

        return {
            publicKey: new Uint8Array(pubBuf),
            privateKey: new Uint8Array(privBuf)
        };
    }

    async importKey(keyData: Uint8Array, type: 'public' | 'private'): Promise<any> {
        const format = type === 'public' ? 'spki' : 'pkcs8';
        const usages = type === 'public' ? ['encrypt'] : ['decrypt'];
        return this.subtle.importKey(
            format,
            keyData,
            { name: 'RSA-OAEP', hash: 'SHA-256' },
            true,
            usages
        );
    }

    async encryptRSA(publicKey: any, data: Uint8Array): Promise<Uint8Array> {
        const encrypted = await this.subtle.encrypt(
            { name: 'RSA-OAEP' },
            publicKey,
            data
        );
        return new Uint8Array(encrypted);
    }

    async decryptRSA(privateKey: any, data: Uint8Array): Promise<Uint8Array> {
        const decrypted = await this.subtle.decrypt(
            { name: 'RSA-OAEP' },
            privateKey,
            data
        );
        return new Uint8Array(decrypted);
    }

    async deriveKey(masterKey: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array> {
        const key = await this.subtle.importKey(
            'raw', masterKey, { name: 'HKDF' }, false, ['deriveBits']
        );

        const bits = await this.subtle.deriveBits(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: salt,
                info: info,
            },
            key,
            length * 8
        );

        return new Uint8Array(bits);
    }
}
