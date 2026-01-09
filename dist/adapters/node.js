"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.NodeCryptoProvider = void 0;
const crypto_1 = __importDefault(require("crypto"));
const subtle = crypto_1.default.webcrypto.subtle;
class NodeCryptoProvider {
    randomBytes(size) {
        return new Uint8Array(crypto_1.default.randomBytes(size));
    }
    async aesEncrypt(key, iv, data) {
        const cryptoKey = await subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt']);
        const encryptedBuffer = await subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, data);
        const encrypted = new Uint8Array(encryptedBuffer);
        const tagLength = 16;
        const ciphertext = encrypted.slice(0, encrypted.length - tagLength);
        const tag = encrypted.slice(encrypted.length - tagLength);
        return { ciphertext, tag };
    }
    async aesDecrypt(key, iv, ciphertext, tag) {
        const cryptoKey = await subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt']);
        const encrypted = new Uint8Array(ciphertext.length + tag.length);
        encrypted.set(ciphertext);
        encrypted.set(tag, ciphertext.length);
        try {
            const decryptedBuffer = await subtle.decrypt({ name: 'AES-GCM', iv }, cryptoKey, encrypted);
            return new Uint8Array(decryptedBuffer);
        }
        catch (e) {
            throw new Error('Decryption failed: Integrity check failed or invalid key.');
        }
    }
    async generateEcKeyPair(type) {
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
    async importKey(keyData, type, algorithm) {
        if (algorithm === 'AES-GCM' || algorithm === 'HKDF') {
            const keyUsage = algorithm === 'AES-GCM' ? ['encrypt', 'decrypt'] : ['deriveBits'];
            return subtle.importKey('raw', keyData, { name: algorithm }, false, keyUsage);
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
        if (algorithm === 'ECDH' && type === 'public') {
            usage = [];
        }
        return subtle.importKey(format, keyData, keyOps, true, usage);
    }
    async deriveSharedSecret(privateKey, publicKey) {
        const bits = await subtle.deriveBits({
            name: 'ECDH',
            public: publicKey
        }, privateKey, 256);
        return new Uint8Array(bits);
    }
    async sign(privateKey, data) {
        const signature = await subtle.sign({
            name: 'ECDSA',
            hash: { name: 'SHA-256' },
        }, privateKey, data);
        return new Uint8Array(signature);
    }
    async verify(publicKey, data, signature) {
        return subtle.verify({
            name: 'ECDSA',
            hash: { name: 'SHA-256' },
        }, publicKey, signature, data);
    }
    async deriveKey(masterKey, salt, info, length) {
        const key = await subtle.importKey('raw', masterKey, { name: 'HKDF' }, false, ['deriveBits']);
        const bits = await subtle.deriveBits({
            name: 'HKDF',
            hash: 'SHA-256',
            salt: salt,
            info: info,
        }, key, length * 8);
        return new Uint8Array(bits);
    }
}
exports.NodeCryptoProvider = NodeCryptoProvider;
