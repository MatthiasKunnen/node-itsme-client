import Axios from 'axios';
import * as jose from 'node-jose';
import * as uuid from 'uuid/v4';

import { IdentityProvider } from './identity-provider';
import { ItsmeRdpConfiguration } from './interfaces/itsme-configuration.interface';

export class ItsmeClient {

    private format = 'compact';

    constructor(
        private idp: IdentityProvider,
        private rp: ItsmeRdpConfiguration,
    ) {
    }

    /**
     * Exchange an Authorization code for an Access token and an ID token.
     * @param authorizationCode The Authorization code.
     * @param redirectUri The redirection URI used in the Authorization request.
     */
    async exchangeAuthorizationCode(
        authorizationCode: string,
        redirectUri: string,
    ) {
        const exp = new Date();
        exp.setUTCMilliseconds(exp.getUTCMilliseconds() + 5 * 60 * 1000);
        const clientAssertion = {
            iss: this.rp.clientId,
            sub: this.rp.clientId,
            aud: this.idp.configuration.token_endpoint,
            jti: uuid(),
            exp: (exp.getTime() / 1000).toFixed(),
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

        const tokenResponse = await this.http.post(this.idp.configuration.token_endpoint, body);

        return tokenResponse.data;
    }

    private async createSign(
        supportedMethods: Array<string>,
        signingAlgorithms: Array<string>,
    ) {
        if (supportedMethods.includes('private_key_jwt')) {
            const key = this.rp.keyStore.all().find(k => {
                return signingAlgorithms.some(a => k.supports(a, jose.JWK.MODE_SIGN));
            });

            if (key == null) {
                throw Error('No keys found that match the supported algorithms');
            }

            return await jose.JWS.createSign(
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
