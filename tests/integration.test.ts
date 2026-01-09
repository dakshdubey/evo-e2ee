import { evoE2EE } from '../src/index';

describe('EvoE2EE V2 (ECC) Integration Tests', () => {
    beforeAll(async () => {
        await evoE2EE.init({ appId: 'test-ecc-app', platform: 'node' });
    });

    test('should encrypt and decrypt using ECC flow (Self-Decryption)', async () => {
        const original = 'High Security Secret';
        const encrypted = await evoE2EE.encrypt(original);

        expect(encrypted.version).toBe(2);
        expect(encrypted.ephemeralPublicKey).toBeDefined();
        expect(encrypted.signature).toBeDefined();

        const decrypted = await evoE2EE.decrypt(encrypted);
        expect(decrypted).toBe(original);
    });

    test('should fail if signature is tampered', async () => {
        const original = 'Trust No One';
        const encrypted = await evoE2EE.encrypt(original);

        // Tamper Signature
        let sigBytes = Buffer.from(encrypted.signature!, 'base64');
        sigBytes[0] = sigBytes[0] ^ 0xFF; // Flip bits
        const tamperedSig = sigBytes.toString('base64');

        const tamperedMsg = { ...encrypted, signature: tamperedSig };

        await expect(evoE2EE.decrypt(tamperedMsg)).rejects.toThrow(/Security Violation/);
    });

    test('should fail if ephemeral key is tampered (ECDH Fail)', async () => {
        const original = 'Forward Secrecy';
        const encrypted = await evoE2EE.encrypt(original);

        // Tamper Ephemeral Key (Man in the Middle check)
        // Even if signature wasn't checked (which it is), decrypt would fail at MAC or Derive.
        // But Signature covers Ephemeral Key, so Signature Check should fail first!

        let keyBytes = Buffer.from(encrypted.ephemeralPublicKey!, 'base64');
        keyBytes[5] = keyBytes[5] ^ 0xFF;
        const tamperedKey = keyBytes.toString('base64');

        const tamperedMsg = { ...encrypted, ephemeralPublicKey: tamperedKey };

        // Should fail signature verification because we signed (Ciphertext + EphemeralKey)
        await expect(evoE2EE.decrypt(tamperedMsg)).rejects.toThrow(/Security Violation/);
    });
});
