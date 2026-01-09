"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RSA = void 0;
class RSA {
    constructor(provider) {
        this.provider = provider;
    }
    async generateKeyPair() {
        return this.provider.generateKeyPair();
    }
    async encryptKey(keyData, publicKey) {
        return this.provider.encryptRSA(publicKey, keyData);
    }
    async decryptKey(encryptedKey, privateKey) {
        return this.provider.decryptRSA(privateKey, encryptedKey);
    }
}
exports.RSA = RSA;
