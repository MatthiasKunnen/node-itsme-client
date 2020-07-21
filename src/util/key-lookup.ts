import {JWKKey, KeyStore} from 'node-jose';

export interface BaseKeyLookupOptions {
    kid?: string;
    kty?: string;
    use?: 'sig' | 'enc';

    [k: string]: any;
}

interface PlainKeyLookupOptions extends BaseKeyLookupOptions {
    alg?: string;
    enc?: string;
}

export interface KeyLookupOptions extends BaseKeyLookupOptions {
    alg?: Array<string> | string;
    enc?: Array<string> | string;
}

function normalizeToArray(input?: Array<string> | string) {
    if (input === undefined) {
        return [undefined];
    } else if (typeof input === 'string') {
        return [input];
    }

    return input;
}

/**
 * As soon as non-null is returned in the callback, looping stops and the
 * returned value from the callback is returned.
 * @param keyLookup
 * @param callback
 */
function find(
    keyLookup: KeyLookupOptions,
    callback: (lookup: PlainKeyLookupOptions) => undefined | JWKKey,
): JWKKey | null {
    const setDefined = (object, input) => {
        Object.keys(input)
            .filter(k => input[k] !== undefined)
            .forEach(k => {
                object[k] = input[k];
            });

        return object;
    };

    for (const alg of normalizeToArray(keyLookup.alg)) {
        for (const enc of normalizeToArray(keyLookup.enc)) {
            const result = callback(setDefined({
                ...keyLookup,
            }, {alg, enc}));

            if (result !== undefined) {
                return result;
            }
        }
    }

    return null;
}

/**
 * Custom getKey option to make searching for matching properties easier.
 * @param keyStore The key store to search in
 * @param keyLookup The lookup options.
 */
export function getKey(keyStore: KeyStore, keyLookup: KeyLookupOptions): JWKKey | null {
    return find(keyLookup, lookup => keyStore.get(lookup));
}
