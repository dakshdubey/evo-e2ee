// src/adapters/node.ts
import { CryptoProvider } from '../types';
import * as crypto from 'crypto';

// Use Node's webcrypto implementation where possible for consistency
const subtle = crypto.webcrypto.subtle as any; // Cast to any to avoid strict type mismatch if types are old

export class NodeCryptoProvider implements CryptoProvider {
    randomBytes(size: number): Uint8Array {
        return new Uint8Array(crypto.randomBytes(size));
    }

    async aesEncrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Promise<{ ciphertext: Uint8Array; tag: Uint8Array }> {
        // Using Node's native crypto for AES-GCM might be more robust/familiar than webcrypto shim, but webcrypto is fine.
        // Let's use native createCipheriv for explicit control over Auth Tag if needed, 
        // BUT WebCrypto returns ciphertext + tag concatenated usually.

        // WebCrypto AES-GCM Encrypt:
        const cryptoKey = await subtle.importKey(
            'raw', key, { name: 'AES-GCM' }, false, ['encrypt']
        );

        const encryptedBuffer = await subtle.encrypt(
            { name: 'AES-GCM', iv },
            cryptoKey,
            data
        );

        const encrypted = new Uint8Array(encryptedBuffer);
        // WebCrypto AES-GCM appends the tag at the end (usually 16 bytes)
        const tagLength = 16;
        const ciphertext = encrypted.slice(0, encrypted.length - tagLength);
        const tag = encrypted.slice(encrypted.length - tagLength);

        return { ciphertext, tag };
    }

    async aesDecrypt(key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array): Promise<Uint8Array> {
        const cryptoKey = await subtle.importKey(
            'raw', key, { name: 'AES-GCM' }, false, ['decrypt']
        );

        // Concatenate ciphertext + tag for WebCrypto
        const encrypted = new Uint8Array(ciphertext.length + tag.length);
        encrypted.set(ciphertext);
        encrypted.set(tag, ciphertext.length);

        try {
            const decryptedBuffer = await subtle.decrypt(
                { name: 'AES-GCM', iv },
                cryptoKey,
                encrypted
            );
            return new Uint8Array(decryptedBuffer);
        } catch (e) {
            throw new Error('Decryption failed: Integrity check failed or invalid key.');
        }
    }

    async generateKeyPair(): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
        // Generate RSA-OAEP keys
        const pair = await subtle.generateKey(
            {
                name: 'RSA-OAEP',
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256',
            },
            true,
            ['encrypt', 'decrypt']
        );

        const pubBuf = await subtle.exportKey('spki', pair.publicKey);
        const privBuf = await subtle.exportKey('pkcs8', pair.privateKey);

        return {
            publicKey: new Uint8Array(pubBuf),
            privateKey: new Uint8Array(privBuf)
        };
    }

    async importKey(keyData: Uint8Array, type: 'public' | 'private'): Promise<any> {
        const format = type === 'public' ? 'spki' : 'pkcs8';
        const usages = type === 'public' ? ['encrypt'] : ['decrypt'];
        return subtle.importKey(
            format,
            keyData,
            { name: 'RSA-OAEP', hash: 'SHA-256' },
            true,
            usages
        );
    }

    async encryptRSA(publicKey: any, data: Uint8Array): Promise<Uint8Array> {
        const encrypted = await subtle.encrypt(
            { name: 'RSA-OAEP' },
            publicKey,
            data
        );
        return new Uint8Array(encrypted);
    }

    async decryptRSA(privateKey: any, data: Uint8Array): Promise<Uint8Array> {
        const decrypted = await subtle.decrypt(
            { name: 'RSA-OAEP' },
            privateKey,
            data
        );
        return new Uint8Array(decrypted);
    }

    async deriveKey(masterKey: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array> {
        // Import master key for HKDF
        const key = await subtle.importKey(
            'raw', masterKey, { name: 'HKDF' }, false, ['deriveBits']
        );

        const bits = await subtle.deriveBits(
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
