"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.evoE2EE = exports.EvoE2EE = void 0;
const node_1 = require("../adapters/node");
const browser_1 = require("../adapters/browser");
const aes_1 = require("../core/aes");
const ecc_1 = require("../core/ecc");
const hkdf_1 = require("../core/hkdf");
const manager_1 = require("../keys/manager");
const storage_1 = require("../keys/storage");
const utils_1 = require("../utils");
class EvoE2EE {
    constructor() {
        this.initialized = false;
    }
    async init(options) {
        if (this.initialized)
            return;
        if (options.platform === 'node') {
            this.provider = new node_1.NodeCryptoProvider();
        }
        else {
            this.provider = new browser_1.BrowserCryptoProvider();
        }
        this.aes = new aes_1.AES(this.provider);
        this.ecc = new ecc_1.ECC(this.provider);
        this.hkdf = new hkdf_1.HKDF(this.provider);
        const storage = options.storage || new storage_1.InMemoryKeyStorage();
        this.keyManager = new manager_1.KeyManager(this.ecc, storage);
        await this.keyManager.init();
        this.initialized = true;
    }
    async encrypt(data, recipientPublicKeyBase64) {
        this.checkInit();
        const myKeys = this.keyManager.getKeys();
        let recipientPubRaw;
        if (recipientPublicKeyBase64) {
            recipientPubRaw = (0, utils_1.fromBase64)(recipientPublicKeyBase64);
        }
        else {
            recipientPubRaw = myKeys.encryptionKey.publicKey;
        }
        const ephemeral = await this.ecc.generateKeyPair('encryption');
        const sharedSecret = await this.ecc.deriveSharedSecret(ephemeral.privateKey, recipientPubRaw);
        const sessionKey = await this.hkdf.deriveKey(sharedSecret, new Uint8Array(0), new TextEncoder().encode('EvoE2EE V2-AES'), 32);
        const dataBytes = new TextEncoder().encode(data);
        const { ciphertext, iv, tag } = await this.aes.encrypt(dataBytes, sessionKey);
        const fullCiphertext = (0, utils_1.concatBuffers)(ciphertext, tag);
        const payloadToSign = (0, utils_1.concatBuffers)(fullCiphertext, ephemeral.publicKey);
        const signature = await this.ecc.sign(myKeys.identityKey.privateKey, payloadToSign);
        return {
            cipherText: (0, utils_1.toBase64)(fullCiphertext),
            ephemeralPublicKey: (0, utils_1.toBase64)(ephemeral.publicKey),
            signature: (0, utils_1.toBase64)(signature),
            iv: (0, utils_1.toBase64)(iv),
            version: 2
        };
    }
    async decrypt(message, senderIdentityKeyBase64) {
        this.checkInit();
        const myKeys = this.keyManager.getKeys();
        if (message.version !== 2) {
            throw new Error('Unsupported version: ' + message.version);
        }
        if (!message.ephemeralPublicKey || !message.signature) {
            throw new Error('Invalid V2 Payload: Missing ECC fields');
        }
        const ephemeralPub = (0, utils_1.fromBase64)(message.ephemeralPublicKey);
        const fullCiphertext = (0, utils_1.fromBase64)(message.cipherText);
        const signature = (0, utils_1.fromBase64)(message.signature);
        const iv = (0, utils_1.fromBase64)(message.iv);
        let verifyKeyRaw = myKeys.identityKey.publicKey;
        if (senderIdentityKeyBase64) {
            verifyKeyRaw = (0, utils_1.fromBase64)(senderIdentityKeyBase64);
        }
        const signedPayload = (0, utils_1.concatBuffers)(fullCiphertext, ephemeralPub);
        const isValid = await this.ecc.verify(verifyKeyRaw, signedPayload, signature);
        if (!isValid) {
            throw new Error('Security Violation: Message Signature Invalid! (Potential Tampering or Spoofing)');
        }
        const sharedSecret = await this.ecc.deriveSharedSecret(myKeys.encryptionKey.privateKey, ephemeralPub);
        const sessionKey = await this.hkdf.deriveKey(sharedSecret, new Uint8Array(0), new TextEncoder().encode('EvoE2EE V2-AES'), 32);
        const tagLength = 16;
        if (fullCiphertext.length < tagLength)
            throw new Error('Invalid ciphertext');
        const ciphertext = fullCiphertext.slice(0, fullCiphertext.length - tagLength);
        const tag = fullCiphertext.slice(fullCiphertext.length - tagLength);
        const decryptedBytes = await this.aes.decrypt(ciphertext, sessionKey, iv, tag);
        return new TextDecoder().decode(decryptedBytes);
    }
    getPublicKeys() {
        this.checkInit();
        const keys = this.keyManager.getKeys();
        return {
            identityKey: (0, utils_1.toBase64)(keys.identityKey.publicKey),
            encryptionKey: (0, utils_1.toBase64)(keys.encryptionKey.publicKey)
        };
    }
    checkInit() {
        if (!this.initialized) {
            throw new Error('EvoE2EE not initialized. Call init() first.');
        }
    }
}
exports.EvoE2EE = EvoE2EE;
exports.evoE2EE = new EvoE2EE();
