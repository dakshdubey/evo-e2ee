"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.toBase64 = toBase64;
exports.fromBase64 = fromBase64;
exports.concatBuffers = concatBuffers;
function toBase64(bytes) {
    if (typeof window === 'undefined') {
        return Buffer.from(bytes).toString('base64');
    }
    return btoa(String.fromCharCode(...bytes));
}
function fromBase64(base64) {
    if (typeof window === 'undefined') {
        return new Uint8Array(Buffer.from(base64, 'base64'));
    }
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}
function concatBuffers(res, item) {
    const merged = new Uint8Array(res.length + item.length);
    merged.set(res);
    merged.set(item, res.length);
    return merged;
}
