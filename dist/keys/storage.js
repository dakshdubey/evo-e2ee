"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.InMemoryKeyStorage = void 0;
class InMemoryKeyStorage {
    constructor() {
        this.keys = null;
    }
    async saveKeys(keys) {
        this.keys = keys;
    }
    async loadKeys() {
        return this.keys;
    }
}
exports.InMemoryKeyStorage = InMemoryKeyStorage;
