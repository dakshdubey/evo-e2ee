// src/adapters/browser.ts
import { CryptoProvider } from '../types';

export class BrowserCryptoProvider implements CryptoProvider {
    private get subtle() {
        if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
            return window.crypto.subtle;
        }
        throw new Error('WebCrypto API not available.');
    }

    private get crypto() {
        return window.crypto;
    }

    randomBytes(size: number): Uint8Array {
        return this.crypto.getRandomValues(new Uint8Array(size));
    }

    async aesEncrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Promise<{ ciphertext: Uint8Array; tag: Uint8Array }> {
        const cryptoKey = await this.subtle.importKey(
            'raw', key as unknown as BufferSource, { name: 'AES-GCM' }, false, ['encrypt'] as KeyUsage[]
        );

        const encryptedBuffer = await this.subtle.encrypt(
            { name: 'AES-GCM', iv: iv as unknown as BufferSource },
            cryptoKey,
            data as unknown as BufferSource
        );

        const encrypted = new Uint8Array(encryptedBuffer);
        const tagLength = 16;
        const ciphertext = encrypted.slice(0, encrypted.length - tagLength);
        const tag = encrypted.slice(encrypted.length - tagLength);

        return { ciphertext, tag };
    }

    async aesDecrypt(key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array): Promise<Uint8Array> {
        const cryptoKey = await this.subtle.importKey(
            'raw', key as unknown as BufferSource, { name: 'AES-GCM' }, false, ['decrypt'] as KeyUsage[]
        );

        const encrypted = new Uint8Array(ciphertext.length + tag.length);
        encrypted.set(ciphertext);
        encrypted.set(tag, ciphertext.length);

        try {
            const decryptedBuffer = await this.subtle.decrypt(
                { name: 'AES-GCM', iv: iv as unknown as BufferSource },
                cryptoKey,
                encrypted as unknown as BufferSource
            );
            return new Uint8Array(decryptedBuffer);
        } catch (e) {
            throw new Error('Decryption failed');
        }
    }

    // --- ECC IMPLEMENTATION ---

    async generateEcKeyPair(type: 'signing' | 'encryption'): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
        const usage: KeyUsage[] = type === 'signing' ? ['sign', 'verify'] : ['deriveKey', 'deriveBits'];
        const keyOps = type === 'signing'
            ? { name: 'ECDSA', namedCurve: 'P-256' }
            : { name: 'ECDH', namedCurve: 'P-256' };

        const pair = await this.subtle.generateKey(keyOps, true, usage);

        const pubBuf = await this.subtle.exportKey('spki', pair.publicKey as CryptoKey);
        const privBuf = await this.subtle.exportKey('pkcs8', pair.privateKey as CryptoKey);

        return {
            publicKey: new Uint8Array(pubBuf),
            privateKey: new Uint8Array(privBuf)
        };
    }

    async importKey(keyData: Uint8Array, type: 'public' | 'private', algorithm: 'ECDH' | 'ECDSA' | 'AES-GCM' | 'HKDF'): Promise<any> {
        if (algorithm === 'AES-GCM' || algorithm === 'HKDF') {
            const keyUsage: KeyUsage[] = algorithm === 'AES-GCM' ? ['encrypt', 'decrypt'] : ['deriveBits'];
            return this.subtle.importKey('raw', keyData as unknown as BufferSource, { name: algorithm }, false, keyUsage);
        }

        const format = type === 'public' ? 'spki' : 'pkcs8';
        const keyOps = algorithm === 'ECDSA'
            ? { name: 'ECDSA', namedCurve: 'P-256' }
            : { name: 'ECDH', namedCurve: 'P-256' };

        let usage: KeyUsage[] = [];
        if (algorithm === 'ECDSA') {
            usage = type === 'public' ? ['verify'] : ['sign'];
        } else { // ECDH
            usage = type === 'public' ? [] : ['deriveBits'];
        }

        return this.subtle.importKey(format, keyData as unknown as BufferSource, keyOps, true, usage);
    }

    async deriveSharedSecret(privateKey: any, publicKey: any): Promise<Uint8Array> {
        const bits = await this.subtle.deriveBits(
            {
                name: 'ECDH',
                public: publicKey
            },
            privateKey,
            256
        );
        return new Uint8Array(bits);
    }

    async sign(privateKey: any, data: Uint8Array): Promise<Uint8Array> {
        const signature = await this.subtle.sign(
            {
                name: 'ECDSA',
                hash: { name: 'SHA-256' },
            },
            privateKey,
            data as unknown as BufferSource
        );
        return new Uint8Array(signature);
    }

    async verify(publicKey: any, data: Uint8Array, signature: Uint8Array): Promise<boolean> {
        return this.subtle.verify(
            {
                name: 'ECDSA',
                hash: { name: 'SHA-256' },
            },
            publicKey,
            signature as unknown as BufferSource,
            data as unknown as BufferSource
        );
    }

    async deriveKey(masterKey: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array> {
        const key = await this.subtle.importKey(
            'raw', masterKey as unknown as BufferSource, { name: 'HKDF' }, false, ['deriveBits'] as KeyUsage[]
        );

        const bits = await this.subtle.deriveBits(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: salt as unknown as BufferSource,
                info: info as unknown as BufferSource,
            },
            key,
            length * 8
        );

        return new Uint8Array(bits);
    }
}
