export interface Jwk {
    /**
     * The "alg" (algorithm) parameter identifies the algorithm intended for
     * use with the key.
     * See {@link https://tools.ietf.org/html/rfc7517#section-4.4}
     */
    alg?: string;

    /**
     * RSA public exponent e.
     * See {@link https://www.gnupg.org/documentation/manuals/gcrypt-devel/RSA-key-parameters.html}
     */
    e?: string;

    /**
     * RSA secret exponent d = e^-1 \bmod (p-1)(q-1).
     * See {@link https://www.gnupg.org/documentation/manuals/gcrypt-devel/RSA-key-parameters.html}
     */
    d?: string;

    k?: string;

    /**
     * The "kid" (key ID) parameter is used to match a specific key.  This
     * is used, for instance, to choose among a set of keys within a JWK Set
     * during key rollover.
     * See {@link https://tools.ietf.org/html/rfc7517#section-4.5}
     */
    kid?: string;

    /**
     * The "kty" (key type) parameter identifies the cryptographic algorithm
     * family used with the key, such as "RSA" or "EC".
     * See {@link https://tools.ietf.org/html/rfc7517#section-4.1}
     */
    kty: string;

    /**
     * RSA public modulus n.
     * See {@link https://www.gnupg.org/documentation/manuals/gcrypt-devel/RSA-key-parameters.html}
     */
    n: string;

    /**
     * The "use" (public key use) parameter identifies the intended use of
     * the public key.  The "use" parameter is employed to indicate whether
     * a public key is used for encrypting data or verifying the signature
     * on data.
     * See {@link https://tools.ietf.org/html/rfc7517#section-4.2}
     */
    use?: string;

    [k: string]: any; // We might be missing some specific fields
}
