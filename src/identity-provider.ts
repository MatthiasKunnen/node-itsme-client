import Axios from 'axios';
import * as LRU from 'lru-cache';
import * as ms from 'ms';
import { JWK, JWKKey, KeyStore, KeyStoreGetOptions } from 'node-jose';

import { ItsmeDiscoveryConfiguration } from './interfaces/itsme-configuration.interface';

export class IdentityProvider {

    private cache: LRU.Cache<string, boolean>;
    private keyStore: KeyStore;
    private readonly keyPrefix = 'key/';

    /**
     * Using the static discover method is recommended.
     * @param configuration
     */
    constructor(public readonly configuration: ItsmeDiscoveryConfiguration) {
        if (!configuration.token_endpoint_auth_methods_supported.includes('private_key_jwt')) {
            throw Error('Expected private_key_jwt for token endpoint auth methods');
        }

        this.cache = new LRU({
            max: 10,
            maxAge: ms('1d'), // Cache keys for 1 day
        });
    }

    /**
     * Discover an endpoint by its discovery URL.
     * @param url The URL to discover.
     */
    static async discover(url: string): Promise<IdentityProvider> {
        const discoveryResponse = await Axios.get(url);

        return new this(discoveryResponse.data);
    }

    async getKey(keyLookup: KeyStoreGetOptions): Promise<JWKKey | undefined> {
        // Init or key rollover could have occurred.
        if (this.keyStore === undefined || !this.isKeyCached(keyLookup.kid)) {
            await this.refreshKeyStore();
        }

        const key = this.keyStore.get(keyLookup);

        if (key != null) {
            this.cache.set(this.keyPrefix + keyLookup.kid, true);
        }

        return key;
    }

    isKeyCached(kid: string): boolean {
        // Use get to hit cache
        return <any>this.cache.get(this.keyPrefix + kid) === true;
    }

    private async refreshKeyStore() {
        if (this.keyStore !== undefined && this.cache.get('throttle')) {
            return;
        }

        const jwkSetResponse = await Axios.get(this.configuration.jwks_uri);
        this.keyStore = await JWK.asKeyStore(jwkSetResponse.data);
        this.cache.reset();
        this.cache.set('throttle', true, ms('1m')); // Throttle for 1 minute
    }
}
