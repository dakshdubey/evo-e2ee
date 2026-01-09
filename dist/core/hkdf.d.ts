import { CryptoProvider } from '../types';
export declare class HKDF {
    private provider;
    constructor(provider: CryptoProvider);
    deriveKey(masterKey: Uint8Array, salt?: Uint8Array, info?: Uint8Array, length?: number): Promise<Uint8Array>;
}
