// Types for node-jose, modified to adhere to tslint. Original from SimonSchick.
// See https://github.com/cisco/node-jose/issues/135.
// These typings are not 100% complete.
/* tslint:disable */

declare module 'node-jose' {
    import { Buffer } from 'buffer';

    export interface JWA {
        digest(): any;
        derive(): any;
        sign(): any;
        verify(): any;
        encrypt(): any;
        decrypt(): any;
    }

    export interface JWEEncryptor {
        update(input: any, encoding?: string): this;

        final(payload?: string | Buffer, encoding?: string): Promise<string | Object>;
    }

    export interface JWEDecryptor {
        decrypt(input: string): Promise<JWEDecryptResult>;
    }

    export interface BaseResult {
        /**
         * the combined 'protected' and 'unprotected' header members
         */
        header: any;
        /**
         * the signed content
         */
        payload: Buffer;
        /**
         * The key used to verify the signature
         */
        key: JWKKey;
    }

    export interface JWEDecryptResult extends BaseResult {
        /**
         * an array of the member names from the "protected" member
         */
        protected: string[];
        /**
         * the decrypted content (alternate)
         */
        plaintext: Buffer;
    }

    export interface JWE {
        createEncrypt(key: JWKKey | JWKKey[]): JWEEncryptor;
        createEncrypt(options: {
            format?: 'compact' | 'flattened';
            zip?: boolean;

        }, key: JWKKey): JWEEncryptor;
        createEncrypt(opts: CreateSignEncryptOpts, signs: CreateSignEncryptSigns): JWEEncryptor;
        createDecrypt(key: JWKKey): JWEDecryptor;
    }

    type KeyUse = 'sig' | 'enc' | 'desc';

    export interface RawKey {
        alg: string;
        kty: string;
        use: KeyUse;

        // e and n make up the public key
        e: string;
        n: string;
    }

    export interface KeyStoreGetFilter {
        kty?: string;
        use?: KeyUse;
        alg: string;
    }

    export interface KeyStoreGetOptions extends KeyStoreGetFilter {
        kid: string;
    }

    export interface KeyStore {
        toJSON(exportPrivateKeys?: boolean): object;

        get(kid: string, filter?: KeyStoreGetFilter): JWKKey;

        get(options: KeyStoreGetOptions): JWKKey;

        all(options: Partial<KeyStoreGetOptions>): JWKKey[];

        add(key: RawKey): Promise<JWKKey>;

        /**
         * @param key
         *  String serialization of a JSON JWK/(base64-encoded) PEM/(binary-encoded) DER
         *  Buffer of a JSON JWK/(base64-encoded) PEM/(binary-encoded) DER
         * @param form
         * is either a:
         * - "json" for a JSON stringified JWK
         * - "private" for a DER encoded 'raw' private key
         * - "pkcs8" for a DER encoded (unencrypted!) PKCS8 private key
         * - "public" for a DER encoded SPKI public key (alternate to 'spki')
         * - "spki" for a DER encoded SPKI public key
         * - "pkix" for a DER encoded PKX X.509 certificate
         * - "x509" for a DER encoded PKX X.509 certificate
         * - "pem" for a PEM encoded of PKCS8 / SPKI / PKX
         */
        add(
            key: string | Buffer,
            form: 'json' | 'private' | 'pkcs8' | 'public' | 'spki' | 'pkix' | 'x509' | 'pem',
        ): Promise<JWKKey>;

        remove(key: JWKKey);
    }

    export interface JWKKey {
        keystore: KeyStore;
        length: number;
        kty: string;
        kid: string;
        use: KeyUse;
        alg: string;

        /**
         * The possible algorithms this Key can be used for. The returned
         * list is not any particular order, but is filtered based on the
         * Key's intended usage.
         */
        algorithms(mode: string): Array<string>;

        /**
         * Determines if the given algorithm is supported.
         * @param {String} alg The algorithm in question
         * @param {String} [mode] The operation mode
         * @returns {Boolean} `true` if {alg} is supported, and `false` otherwise.
         */
        supports(alg: string, mode: string): boolean;

        /**
         * Defaults to false
         */
        toPEM(isPrivate?: boolean);
    }

    export interface JWK {
        MODE_SGN: 'sign';
        MODE_VERFY: 'verify';
        MODE_ENCRYPT: 'encrypt';
        MODE_DECRYPT: 'decrypt';
        MODE_WRAP: 'wrap';
        MODE_UNWRAP: 'wrap';

        isKeyStore(input: any): input is KeyStore;
        isKey(input: any): input is JWKKey;
        createKeyStore(): KeyStore;
        asKeyStore(input: any): Promise<KeyStore>;
        asKey(rawKey: RawKey): Promise<JWKKey>;
        /**
         * @param key
         *  String serialization of a JSON JWK/(base64-encoded) PEM/(binary-encoded) DER
         *  Buffer of a JSON JWK/(base64-encoded) PEM/(binary-encoded) DER
         * @param form
         * is either a:
         * - "json" for a JSON stringified JWK
         * - "private" for a DER encoded 'raw' private key
         * - "pkcs8" for a DER encoded (unencrypted!) PKCS8 private key
         * - "public" for a DER encoded SPKI public key (alternate to 'spki')
         * - "spki" for a DER encoded SPKI public key
         * - "pkix" for a DER encoded PKX X.509 certificate
         * - "x509" for a DER encoded PKX X.509 certificate
         * - "pem" for a PEM encoded of PKCS8 / SPKI / PKX
         */
        asKey(
            key: string | Buffer,
            form: 'json' | 'private' | 'pkcs8' | 'public' | 'spki' | 'pkix' | 'x509' | 'pem',
        ): Promise<JWKKey>;
    }

    export interface VerificationResult extends BaseResult {
        /**
         * the verified signature
         */
        signature: Buffer;
    }

    export interface JWSSigner {

        /**
         * Updates the signing content for this signature content. The content
         * is appended to the end of any other content already applied.
         *
         * If {data} is a Buffer, {encoding} is ignored. Otherwise, {data} is
         * converted to a Buffer internally to {encoding}.
         *
         * @param {Buffer|String} data The data to sign.
         * @param {String} [encoding="binary"] The encoding of {data}.
         * @returns This signature generator.
         * @throws {Error} If a signature has already been generated.
         */
        update(data: string | Buffer, encoding?: string): JWSSigner;

        /**
         * Finishes the signature operation.
         *
         * The returned Promise, when fulfilled, is the JSON Web Signature (JWS)
         * object.
         *
         * @param {Buffer|String} [data] The final content to apply.
         * @param {String} [encoding="binary"] The encoding of the final content
         *        (if any).
         * @returns {Promise} The promise for the signatures
         * @throws {Error} If a signature has already been generated.
         */
        final(data?: string | Buffer, encoding?: string): Promise<any>
    }

    export interface JWSVerifier {
        verify(input: string): Promise<VerificationResult>;
    }

    export interface CreateSignEncryptOpts {
        /**
         * Use compact serialization?
         */
        compact?: boolean,
        format?: string | 'compact' | 'flattened' | 'general',

        /**
         * Additional header fields.
         */
        fields?: {[k: string]: any};
    }

    export interface CreateSignEncryptSigns {
        /**
         * Per-signatory header fields.
         */
        header?: Object,

        /**
         * The key used to sign the content.
         */
        key: JWKKey;

        /**
         * List of fields to integrity protect ("*" to protect all fields).
         */
        protect?: string | Array<string>,

        /**
         * Reference field to identify the key.
         */
        reference?: any,
    }

    export interface JWS {

        /**
         * Creates a new JWS Signer with the given options and signatories.
         *
         * @param [opts] The signing options
         * @param signs Signatories, either as an array of JWK.Key instances; or
         * an array of objects.
         * @returns {JWSSigner} The signature generator.
         * @throws {Error} If Compact serialization is requested but there are
         * multiple signatories.
         */
        createSign(opts: CreateSignEncryptOpts, signs: CreateSignEncryptSigns): JWSSigner;
        createSign(key: JWKKey | JWKKey[]): JWSSigner;
        createSign(opts: CreateSignEncryptOpts, key: JWKKey): JWSSigner;

        /**
         * Using a keystore.
         */
        createVerify(keyStore?: KeyStore | JWKKey): JWSVerifier;
    }

    export type TypedArray =
        Uint8Array |
        Uint8ClampedArray |
        Uint16Array |
        Uint32Array |
        Float32Array |
        Float64Array;

    export interface util {
        base64url: {
            encode(data: Buffer, encoding: string): string;
            decode(str: string): Buffer;
        },
        utf8: {
            encode(str: string): string;
            decode(str: string): string;
        }
        asBuffer(arr: ArrayBuffer | ArrayLike<any> | TypedArray): Buffer;
        randomBytes(size: number): Buffer;
    }


    export class jose {
        JWE: JWE;
        JWK: JWK;
        JWS: JWS;
        parse: {
            (input: string | Buffer | object): object;
            compact(input: string): object;
            json(input: object): object;
        };
        util: util;
    }

    export default jose;
}
