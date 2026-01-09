import { evoE2EE } from '../src/index';

describe('EvoE2EE Integration Tests', () => {
    beforeAll(async () => {
        await evoE2EE.init({ appId: 'test-app', platform: 'node' });
    });

    test('should encrypt and decrypt a message correctly', async () => {
        const original = 'Hello World! This is secret.';
        const encrypted = await evoE2EE.encrypt(original);

        expect(encrypted).toBeDefined();
        expect(encrypted.cipherText).toBeDefined();
        expect(encrypted.encryptedKey).toBeDefined();
        expect(encrypted.iv).toBeDefined();
        expect(encrypted.version).toBe(1);

        const decrypted = await evoE2EE.decrypt(encrypted);
        expect(decrypted).toBe(original);
    });

    test('should fail to decrypt if ciphertext is tampered', async () => {
        const original = 'Tamper Check';
        const encrypted = await evoE2EE.encrypt(original);

        // Tamper with ciphertext (Base64)
        // We decode, flip a bit, and encode back
        const invalidCipher = encrypted.cipherText.substring(0, encrypted.cipherText.length - 4) + 'AAAA';

        const tamperedMessage = { ...encrypted, cipherText: invalidCipher };

        await expect(evoE2EE.decrypt(tamperedMessage)).rejects.toThrow();
    });

    test('should fail to decrypt if auth tag is invalid (integrity check)', async () => {
        // This is covered by general ciphertext tampering since tag is appended, 
        // but let's try to specifically mess with the tag (last chars of base64).
        const original = 'Integrity Check';
        const encrypted = await evoE2EE.encrypt(original);

        // Flip last char
        const lastChar = encrypted.cipherText.slice(-1);
        const newLastChar = lastChar === 'A' ? 'B' : 'A';
        const tampered = encrypted.cipherText.slice(0, -1) + newLastChar;

        await expect(evoE2EE.decrypt({ ...encrypted, cipherText: tampered })).rejects.toThrow();
    });
});
