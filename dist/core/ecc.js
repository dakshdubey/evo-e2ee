"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ECC = void 0;
class ECC {
    constructor(provider) {
        this.provider = provider;
    }
    async generateKeyPair(type) {
        return this.provider.generateEcKeyPair(type);
    }
    async deriveSharedSecret(privateKeyRaw, publicKeyRaw) {
        const priv = await this.provider.importKey(privateKeyRaw, 'private', 'ECDH');
        const pub = await this.provider.importKey(publicKeyRaw, 'public', 'ECDH');
        return this.provider.deriveSharedSecret(priv, pub);
    }
    async sign(privateKeyRaw, data) {
        const priv = await this.provider.importKey(privateKeyRaw, 'private', 'ECDSA');
        return this.provider.sign(priv, data);
    }
    async verify(publicKeyRaw, data, signature) {
        const pub = await this.provider.importKey(publicKeyRaw, 'public', 'ECDSA');
        return this.provider.verify(pub, data, signature);
    }
}
exports.ECC = ECC;
