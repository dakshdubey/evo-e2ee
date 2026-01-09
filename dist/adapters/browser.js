"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BrowserCryptoProvider = void 0;
class BrowserCryptoProvider {
    get subtle() {
        if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
            return window.crypto.subtle;
        }
        throw new Error('WebCrypto API not available.');
    }
    get crypto() {
        return window.crypto;
    }
    randomBytes(size) {
        return this.crypto.getRandomValues(new Uint8Array(size));
    }
    async aesEncrypt(key, iv, data) {
        const cryptoKey = await this.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt']);
        const encryptedBuffer = await this.subtle.encrypt({ name: 'AES-GCM', iv: iv }, cryptoKey, data);
        const encrypted = new Uint8Array(encryptedBuffer);
        const tagLength = 16;
        const ciphertext = encrypted.slice(0, encrypted.length - tagLength);
        const tag = encrypted.slice(encrypted.length - tagLength);
        return { ciphertext, tag };
    }
    async aesDecrypt(key, iv, ciphertext, tag) {
        const cryptoKey = await this.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt']);
        const encrypted = new Uint8Array(ciphertext.length + tag.length);
        encrypted.set(ciphertext);
        encrypted.set(tag, ciphertext.length);
        try {
            const decryptedBuffer = await this.subtle.decrypt({ name: 'AES-GCM', iv: iv }, cryptoKey, encrypted);
            return new Uint8Array(decryptedBuffer);
        }
        catch (e) {
            throw new Error('Decryption failed');
        }
    }
    async generateEcKeyPair(type) {
        const usage = type === 'signing' ? ['sign', 'verify'] : ['deriveKey', 'deriveBits'];
        const keyOps = type === 'signing'
            ? { name: 'ECDSA', namedCurve: 'P-256' }
            : { name: 'ECDH', namedCurve: 'P-256' };
        const pair = await this.subtle.generateKey(keyOps, true, usage);
        const pubBuf = await this.subtle.exportKey('spki', pair.publicKey);
        const privBuf = await this.subtle.exportKey('pkcs8', pair.privateKey);
        return {
            publicKey: new Uint8Array(pubBuf),
            privateKey: new Uint8Array(privBuf)
        };
    }
    async importKey(keyData, type, algorithm) {
        if (algorithm === 'AES-GCM' || algorithm === 'HKDF') {
            const keyUsage = algorithm === 'AES-GCM' ? ['encrypt', 'decrypt'] : ['deriveBits'];
            return this.subtle.importKey('raw', keyData, { name: algorithm }, false, keyUsage);
        }
        const format = type === 'public' ? 'spki' : 'pkcs8';
        const keyOps = algorithm === 'ECDSA'
            ? { name: 'ECDSA', namedCurve: 'P-256' }
            : { name: 'ECDH', namedCurve: 'P-256' };
        let usage = [];
        if (algorithm === 'ECDSA') {
            usage = type === 'public' ? ['verify'] : ['sign'];
        }
        else {
            usage = type === 'public' ? [] : ['deriveBits'];
        }
        return this.subtle.importKey(format, keyData, keyOps, true, usage);
    }
    async deriveSharedSecret(privateKey, publicKey) {
        const bits = await this.subtle.deriveBits({
            name: 'ECDH',
            public: publicKey
        }, privateKey, 256);
        return new Uint8Array(bits);
    }
    async sign(privateKey, data) {
        const signature = await this.subtle.sign({
            name: 'ECDSA',
            hash: { name: 'SHA-256' },
        }, privateKey, data);
        return new Uint8Array(signature);
    }
    async verify(publicKey, data, signature) {
        return this.subtle.verify({
            name: 'ECDSA',
            hash: { name: 'SHA-256' },
        }, publicKey, signature, data);
    }
    async deriveKey(masterKey, salt, info, length) {
        const key = await this.subtle.importKey('raw', masterKey, { name: 'HKDF' }, false, ['deriveBits']);
        const bits = await this.subtle.deriveBits({
            name: 'HKDF',
            hash: 'SHA-256',
            salt: salt,
            info: info,
        }, key, length * 8);
        return new Uint8Array(bits);
    }
}
exports.BrowserCryptoProvider = BrowserCryptoProvider;
