import { ECC } from '../core/ecc';
import { IKeyStorage, KeySchema } from './storage';
export declare class KeyManager {
    private ecc;
    private storage;
    private currentKeys;
    constructor(ecc: ECC, storage: IKeyStorage);
    init(): Promise<KeySchema>;
    getKeys(): KeySchema;
}
