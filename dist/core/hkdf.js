"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.HKDF = void 0;
class HKDF {
    constructor(provider) {
        this.provider = provider;
    }
    async deriveKey(masterKey, salt = new Uint8Array(0), info = new Uint8Array(0), length = 32) {
        return this.provider.deriveKey(masterKey, salt, info, length);
    }
}
exports.HKDF = HKDF;
