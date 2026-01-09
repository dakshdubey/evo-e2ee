export function toBase64(bytes: Uint8Array): string {
    if (typeof window === 'undefined') {
        // Node.js
        return Buffer.from(bytes).toString('base64');
    }
    // Browser
    return btoa(String.fromCharCode(...bytes));
}

export function fromBase64(base64: string): Uint8Array {
    if (typeof window === 'undefined') {
        // Node.js
        return new Uint8Array(Buffer.from(base64, 'base64'));
    }
    // Browser
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

export function concatBuffers(res: Uint8Array, item: Uint8Array): Uint8Array {
    const merged = new Uint8Array(res.length + item.length);
    merged.set(res);
    merged.set(item, res.length);
    return merged;
}
