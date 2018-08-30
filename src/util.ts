import { computePrimes } from 'jwk-rsa-compute-primes';
import * as jose from 'node-jose';

import { JwkSet } from './interfaces/jwk-set.interface';

/**
 * Create a keystore. This method will compute p, q, dp, dq, and qi if these
 * parameters are missing.
 */
export async function createKeyStore(jwkSet: JwkSet): Promise<jose.KeyStore> {
    jwkSet.keys = jwkSet.keys.map(k => {
        if (k.kty.toUpperCase() === 'RSA' && k.d != null) { // Private RSA key, recompute primes
            k = computePrimes(<any>k);
        }

        return k;
    });

    return jose.JWK.asKeyStore(jwkSet);
}
