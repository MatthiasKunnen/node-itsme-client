import * as assert from 'assert';
import Axios, { AxiosInstance } from 'axios';
import * as base64url from 'base64url';
import { JWK, JWS } from 'node-jose';
import * as qs from 'qs';
import * as uuid from 'uuid/v4';

import { IdentityProvider } from './identity-provider';
import { Claims } from './interfaces/claims.interface';
import { ItsmeRdpConfiguration } from './interfaces/itsme-configuration.interface';
import { JwkSet } from './interfaces/jwk-set.interface';
import { Header, IdToken, TokenResponse } from './interfaces/token.interface';

export class ItsmeClient {

    private format = 'compact';
    private http: AxiosInstance;

    constructor(
        public idp: IdentityProvider,
        private rp: ItsmeRdpConfiguration,
        private clockTolerance = 0,
    ) {
        this.http = Axios.create();
        this.http.defaults.headers.post['Content-Type'] = 'application/x-www-form-urlencoded';
        this.http.interceptors.request.use(request => {
            if (request.method === undefined || request.data == null) {
                return request;
            }

            const headers = request.headers[request.method];

            if (headers['Content-Type'] === 'application/x-www-form-urlencoded') {
                request.data = qs.stringify(request.data);
            }

            return request;
        });
    }

    /**
     * Exchange an Authorization code for an Access token and an ID token.
     * @param authorizationCode The Authorization code.
     * @param redirectUri The redirection URI used in the Authorization request.
     */
    async exchangeAuthorizationCode(
        authorizationCode: string,
        redirectUri: string,
    ): Promise<TokenResponse> {
        const exp = new Date();
        exp.setUTCMilliseconds(exp.getUTCMilliseconds() + 5 * 60 * 1000);
        const clientAssertion: Claims = {
            iss: this.rp.clientId,
            sub: this.rp.clientId,
            aud: this.idp.configuration.token_endpoint,
            jti: uuid(),
            exp: Math.ceil(exp.getTime() / 1000),
        };

        const signer = await this.createSign(
            this.idp.configuration.token_endpoint_auth_methods_supported,
            this.idp.configuration.token_endpoint_auth_signing_alg_values_supported,
        );

        const body = {
            grant_type: 'authorization_code',
            code: authorizationCode,
            redirect_uri: redirectUri,
            client_assertion: await signer.update(JSON.stringify(clientAssertion)).final(),
            client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        };

        const tokenResponse = await this.http.post<TokenResponse>(
            this.idp.configuration.token_endpoint,
            body,
        );

        return tokenResponse.data;
    }

    /**
     * Get the public part of your JWK Set. This can be used to expose your
     * JWK Set on a public URI.
     */
    getPublicJwkSet(): JwkSet {
        return this.rp.keyStore.toJSON();
    }

    /**
     * Verifies a token and extracts its contents.
     * @param token The token to verify.
     */
    async verifyIdToken(token: string): Promise<IdToken> {
        return await this.createVerify(
            token,
            this.idp.configuration.id_token_signing_alg_values_supported,
        );
    }

    /**
     * Returns the token payload if the token is valid. Errors if it is not.
     * @param token The token to verify.
     * @param supportedSigningAlgorithms Supported signing algorithms for this
     * IDP.
     */
    private async createVerify(
        token: string,
        supportedSigningAlgorithms: Array<string>,
    ): Promise<IdToken> {
        const timestamp = Math.floor(Date.now() / 1000);
        const parts = token.split('.');
        const header: Header = JSON.parse(base64url.decode(parts[0]));
        const payload: IdToken = JSON.parse(base64url.decode(parts[1]));

        ['iss', 'sub', 'aud', 'exp', 'iat'].forEach(field => {
            if (payload[field] === undefined) {
                throw new Error(`Missing required JWT property ${field}`);
            }
        });

        const alg = supportedSigningAlgorithms.find(a => a === header.alg);
        if (alg === undefined) {
            throw Error('No matching algorithm for verification found.');
        }

        assert.strictEqual(
            payload.iss,
            this.idp.configuration.issuer,
            `Unexpected iss value '${payload.iss}' in token`,
        );

        if (payload.iat !== undefined) {
            assert.strictEqual(typeof payload.iat, 'number', 'iat is not a number');
            assert(payload.iat <= timestamp + this.clockTolerance, 'ID token issued in the future');
        }

        if (payload.nbf !== undefined) {
            assert.strictEqual(typeof payload.nbf, 'number', 'nbf is not a number');
            assert(payload.nbf <= timestamp + this.clockTolerance, 'ID token not active yet');
        }

        assert(timestamp - this.clockTolerance < payload.exp, 'ID token expired');

        if (payload.aud !== undefined) {
            assert(payload.aud.includes(this.rp.clientId), 'aud is missing the client_id');
        }

        const key = await this.idp.getKey(header);
        await JWS.createVerify(key).verify(token);

        return payload;
    }

    private async createSign(
        supportedMethods: Array<string>,
        signingAlgorithms: Array<string>,
    ) {
        if (supportedMethods.includes('private_key_jwt')) {
            const key = this.rp.keyStore.all().find(k => {
                return signingAlgorithms.some(a => k.supports(a, JWK.MODE_SIGN));
            });

            if (key == null) {
                throw Error('No keys found that match the supported algorithms');
            }

            return await JWS.createSign(
                {
                    fields: {
                        alg: key.alg,
                        typ: 'JWT',
                    },
                    format: this.format,
                },
                {
                    key,
                    reference: true,
                },
            );

        }

        throw new Error('No supported methods found.');
    }
}
