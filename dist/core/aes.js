"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AES = void 0;
class AES {
    constructor(provider) {
        this.provider = provider;
    }
    async encrypt(data, key) {
        const iv = this.provider.randomBytes(12);
        const { ciphertext, tag } = await this.provider.aesEncrypt(key, iv, data);
        return { ciphertext, iv, tag };
    }
    async decrypt(ciphertext, key, iv, tag) {
        if (iv.length !== 12) {
            throw new Error('Invalid IV length. Must be 12 bytes.');
        }
        return this.provider.aesDecrypt(key, iv, ciphertext, tag);
    }
}
exports.AES = AES;
