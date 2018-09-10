import * as assert from 'assert';
import Axios, { AxiosInstance } from 'axios';
import * as base64url from 'base64url';
import { JWE, JWS } from 'node-jose';
import * as qs from 'qs';
import * as uuid from 'uuid/v4';

import { IdentityProvider } from './identity-provider';
import { Claims, UserInfoClaims } from './interfaces/claims.interface';
import { ItsmeRpConfiguration } from './interfaces/itsme-configuration.interface';
import { JwkSet } from './interfaces/jwk-set.interface';
import { JwtPayload } from './interfaces/jwt.interface';
import { Header, TokenResponse } from './interfaces/token.interface';
import { getKey } from './util/key-lookup';

export class ItsmeClient {

    private format = 'compact';
    private http: AxiosInstance;

    constructor(
        public idp: IdentityProvider,
        private rp: ItsmeRpConfiguration,
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

        const clientAssertionReady = await this.tokenAuth(
            JSON.stringify(clientAssertion),
            this.idp.configuration.token_endpoint_auth_methods_supported,
            this.idp.configuration.token_endpoint_auth_signing_alg_values_supported,
        );

        const body = {
            grant_type: 'authorization_code',
            code: authorizationCode,
            redirect_uri: redirectUri,
            client_assertion: clientAssertionReady,
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
     * Decrypts and verifies an ID Token.
     * @param token
     */
    async decryptAndVerifyIdToken(token: string): Promise<JwtPayload> {
        const decrypted = await this.decryptIdToken(token);

        return await this.verifyIdToken(decrypted);
    }

    /**
     * Decrypts the token and returns the decrypted result.
     * @param token The token to decrypt.
     */
    async decryptIdToken(token: string): Promise<string> {
        return this.decrypt(
            token,
            this.idp.configuration.id_token_encryption_alg_values_supported,
        );
    }

    /**
     * Verifies a token and extracts its contents.
     * @param token The token to verify.
     */
    async verifyIdToken(token: string): Promise<JwtPayload> {
        return await this.verify(
            token,
            this.idp.configuration.id_token_signing_alg_values_supported,
            ['iss', 'sub', 'aud', 'exp', 'iat'],
        );
    }

    /**
     * Combines {@link userInfo}, {@link decryptUserInfo}, and
     * {@link verifyUserInfo}. Takes care of fetching, decrypting, verifying and
     * extracting the claims.
     * @param accessToken The Access Token to leverage for retrieving the user
     * info.
     */
    async userInfoComplete(accessToken: string) {
        const userInfoJwe = await this.userInfo(accessToken);
        const userInfoJws = await this.decryptUserInfo(userInfoJwe);
        return await this.verifyUserInfo(userInfoJws);
    }

    /**
     * Get user info using an access token. Returns an encoded JWE.
     * Use {@link decryptUserInfo} and {@link verifyUserInfo} to extract the
     * claims.
     * {@link userInfoComplete} Combines this method, {@link decryptUserInfo},
     * and {@link verifyUserInfo}. You can use it to skip the intermediary
     * steps.
     * @param accessToken The Access Token to leverage for retrieving the user
     * info.
     */
    async userInfo(accessToken: string): Promise<string> {
        const response = await Axios.get<string>(this.idp.configuration.userinfo_endpoint, {
            headers: {
                Authorization: `Bearer ${accessToken}`,
            },
        });

        return response.data;
    }

    /**
     * Decrypts the user info response and returns an encoded JWS.
     * @param jwe The JWE to decrypt.
     */
    async decryptUserInfo(jwe: string): Promise<string> {
        return this.decrypt(
            jwe,
            this.idp.configuration.userinfo_encryption_alg_values_supported,
        );
    }

    /**
     * Verifies the encoded but decrypted user info JWS. Returns the claims of
     * the user.
     * @param jws The JWS to verify.
     */
    async verifyUserInfo(jws: string): Promise<UserInfoClaims> {
        const userInfo = await this.verify(
            jws,
            this.idp.configuration.userinfo_signing_alg_values_supported,
            ['iss', 'sub', 'aud'],
        );

        // This parses the address since itsme returns the object as a plain string
        if (userInfo.address !== undefined && typeof userInfo.address === 'string') {
            try {
                userInfo.address = JSON.parse(userInfo.address);
            } catch (e) {
                // If the address is a string yet not valid JSON, let the
                // implementer deal with it
            }
        }

        return userInfo;
    }

    /**
     * Returns the JWS payload if the JWS is valid. Errors if it is not.
     * @param jws The encoded JWS to verify.
     * @param supportedSigningAlgorithms Supported signing algorithms for this
     * IDP.
     * @param requiredFields An array of fields that are required for the JWT
     * payload.
     */
    private async verify(
        jws: string,
        supportedSigningAlgorithms: Array<string>,
        requiredFields: Array<string>,
    ): Promise<JwtPayload> {
        const timestamp = Math.floor(Date.now() / 1000);
        const parts = jws.split('.');
        const header: Header = JSON.parse(base64url.decode(parts[0]));
        const payload: JwtPayload = JSON.parse(base64url.decode(parts[1]));

        requiredFields.forEach(field => {
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
            assert(payload.iat <= timestamp + this.clockTolerance, 'JWS issued in the future');
        }

        if (payload.nbf !== undefined) {
            assert.strictEqual(typeof payload.nbf, 'number', 'nbf is not a number');
            assert(payload.nbf <= timestamp + this.clockTolerance, 'JWS not active yet');
        }

        if (payload.exp !== undefined) {
            assert(timestamp - this.clockTolerance < payload.exp, 'JWS expired');
        }

        if (payload.aud !== undefined) {
            const aud: Array<string> = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
            assert(aud.includes(this.rp.clientId), 'aud is missing the client ID');
        }

        const key = await this.idp.getKey(header);
        await JWS.createVerify(key).verify(jws);

        return payload;
    }

    private async tokenAuth(
        data: string,
        supportedMethods: Array<string>,
        signingAlgorithms: Array<string>,
    ): Promise<string> {
        if (supportedMethods.includes('private_key_jwt')) {
            return this.sign(data, signingAlgorithms);
        }

        throw new Error('No supported methods found.');
    }

    /**
     * Signs a piece of data and returns the resulting encoded JWS.
     * @param payload The payload to sign.
     * @param signingAlgorithms The supported signing algorithms.
     */
    private async sign(
        payload: string | Buffer,
        signingAlgorithms: Array<string>,
    ): Promise<string> {
        const key = getKey(this.rp.keyStore, {
            alg: signingAlgorithms,
        });

        if (key == null) {
            throw Error('No keys found that match the supported algorithms');
        }

        return JWS.createSign(
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
        ).final(payload);
    }

    /**
     * Decrypts the JWE and returns the decrypted result.
     * @param jwe The encoded JWE to decrypt.
     * @param supportedAlgorithms An array of supported encryption algorithms.
     */
    private async decrypt(
        jwe: string,
        supportedAlgorithms: Array<string>,
    ): Promise<string> {
        const parts = jwe.split('.');
        const header: Header = JSON.parse(base64url.decode(parts[0]));
        const alg = supportedAlgorithms.find(a => a === header.alg);

        if (alg === undefined) {
            throw Error('No matching algorithm for verification found.');
        }

        const key = this.rp.keyStore.get({alg});

        if (key == null) {
            throw Error(`No key supporting ${alg} found`);
        }

        const decrypted = await JWE.createDecrypt(key).decrypt(jwe);

        return decrypted.plaintext.toString('utf8');
    }
}
