// src/adapters/node.ts
import { CryptoProvider } from '../types';
import crypto from 'crypto';

const subtle = crypto.webcrypto.subtle as any;

export class NodeCryptoProvider implements CryptoProvider {
    randomBytes(size: number): Uint8Array {
        return new Uint8Array(crypto.randomBytes(size));
    }

    async aesEncrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Promise<{ ciphertext: Uint8Array; tag: Uint8Array }> {
        const cryptoKey = await subtle.importKey(
            'raw', key, { name: 'AES-GCM' }, false, ['encrypt']
        );

        const encryptedBuffer = await subtle.encrypt(
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
        const cryptoKey = await subtle.importKey(
            'raw', key, { name: 'AES-GCM' }, false, ['decrypt']
        );

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

    // --- ECC IMPLEMENTATION ---

    async generateEcKeyPair(type: 'signing' | 'encryption'): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
        const usage = type === 'signing' ? ['sign', 'verify'] : ['deriveKey', 'deriveBits'];
        const keyOps = type === 'signing'
            ? { name: 'ECDSA', namedCurve: 'P-256' }
            : { name: 'ECDH', namedCurve: 'P-256' };

        const pair = await subtle.generateKey(keyOps, true, usage);

        const pubBuf = await subtle.exportKey('spki', pair.publicKey);
        const privBuf = await subtle.exportKey('pkcs8', pair.privateKey);

        return {
            publicKey: new Uint8Array(pubBuf),
            privateKey: new Uint8Array(privBuf)
        };
    }

    async importKey(keyData: Uint8Array, type: 'public' | 'private', algorithm: 'ECDH' | 'ECDSA' | 'AES-GCM' | 'HKDF'): Promise<any> {
        // For AES and HKDF, format is 'raw'
        if (algorithm === 'AES-GCM' || algorithm === 'HKDF') {
            const keyUsage = algorithm === 'AES-GCM' ? ['encrypt', 'decrypt'] : ['deriveBits'];
            return subtle.importKey('raw', keyData, { name: algorithm }, false, keyUsage);
        }

        // For ECC
        const format = type === 'public' ? 'spki' : 'pkcs8';
        const keyOps = algorithm === 'ECDSA'
            ? { name: 'ECDSA', namedCurve: 'P-256' }
            : { name: 'ECDH', namedCurve: 'P-256' };

        // Usage depends on key type + Algo
        let usage: string[] = [];
        if (algorithm === 'ECDSA') {
            usage = type === 'public' ? ['verify'] : ['sign'];
        } else { // ECDH
            usage = type === 'public' ? [] : ['deriveBits']; // Public key in ECDH doesn't have usage in deriveBits usually
        }

        // Fix: WebCrypto importKey usage for ECDH public key is actually empty or [] usually? 
        // Actually for ECDH deriveKey, we need the private key to have 'deriveBits'/'deriveKey'.
        // The public key simply participates. 
        // Spec says: "If keyData is a SPKI... usages must be empty". Let's check.
        // Actually, usually we don't 'import' the peer public key with a usage for 'deriveKey' unless we are just storing it.
        // But calculateSharedSecret needs the public key object.

        if (algorithm === 'ECDH' && type === 'public') {
            usage = []; // Public keys for ECDH agreement don't "do" anything themselves
        }

        return subtle.importKey(format, keyData, keyOps, true, usage);
    }

    async deriveSharedSecret(privateKey: any, publicKey: any): Promise<Uint8Array> {
        // ECDH derivation
        const bits = await subtle.deriveBits(
            {
                name: 'ECDH',
                public: publicKey
            },
            privateKey,
            256 // P-256 -> 256 bits
        );
        return new Uint8Array(bits);
    }

    async sign(privateKey: any, data: Uint8Array): Promise<Uint8Array> {
        const signature = await subtle.sign(
            {
                name: 'ECDSA',
                hash: { name: 'SHA-256' },
            },
            privateKey,
            data
        );
        return new Uint8Array(signature);
    }

    async verify(publicKey: any, data: Uint8Array, signature: Uint8Array): Promise<boolean> {
        return subtle.verify(
            {
                name: 'ECDSA',
                hash: { name: 'SHA-256' },
            },
            publicKey,
            signature,
            data
        );
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
