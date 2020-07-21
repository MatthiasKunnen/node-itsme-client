import {computePrimes} from 'jwk-rsa-compute-primes';
import {JWK} from 'node-jose';

import {JwkSet} from './interfaces/jwk-set.interface';

/**
 * Create a keystore. This method will compute p, q, dp, dq, and qi if these
 * parameters are missing.
 */
export async function createKeyStore(jwkSet: JwkSet): Promise<JWK.KeyStore> {
    jwkSet.keys = jwkSet.keys.map(k => {
        if (k.kty.toUpperCase() === 'RSA' && k.d !== undefined) {
            // Private RSA key, recompute primes
            k = computePrimes(k as any);
        }

        return k;
    });

    return JWK.asKeyStore(jwkSet);
}
