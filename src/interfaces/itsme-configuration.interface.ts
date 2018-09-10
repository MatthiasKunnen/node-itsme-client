import { KeyStore } from 'node-jose';

/**
 * The input of the configuration of the relying party.
 */
export interface ItsmeRpConfigurationInput {

    /**
     * The client ID provided by itsme.
     */
    clientId: string;

    /**
     * A KeyStore based on your JWK Set. Use createKeyStore() to
     * generate one.  For sandbox environments see
     * {@link https://belgianmobileid.github.io/slate/private_jwks.json} for a
     * default JWK set.
     */
    keyStore: KeyStore;

    /**
     * The base URI for usage of request_uri. Will be appended with a string you
     * provide during requests. See `ApprovalInput.requestUriToken` for an
     * example.
     */
    requestUri?: string;

    /**
     * Used to match service codes to redirect URIs.
     * Keys are the service codes, values are the redirect URIs.
     */
    serviceCodes?: {[k: string]: string};
}

/**
 * The configuration of the relying party.
 */
export interface ItsmeRpConfiguration extends ItsmeRpConfigurationInput {

    /**
     * Used to match service codes to redirect URIs.
     * Keys are the service codes, values are the redirect URIs.
     */
    serviceCodes: {[k: string]: string};
}

export interface ItsmeDiscoveryConfiguration {
    acr_values_supported: Array<string>;
    authorization_endpoint: string;
    claim_types_supported: Array<string>;
    claims_parameter_supported: false;
    claims_supported: Array<string>;
    display_values_supported: Array<string>;
    grant_types_supported: Array<string>;
    id_token_encryption_alg_values_supported: Array<string>;
    id_token_encryption_enc_values_supported: Array<string>;
    id_token_signing_alg_values_supported: Array<string>;
    issuer: string;
    jwks_uri: string;
    registration_endpoint: string;
    request_object_encryption_alg_values_supported: Array<string>;
    request_object_encryption_enc_values_supported: Array<string>;
    request_object_signing_alg_values_supported: Array<string>;
    request_parameter_supported: boolean;
    request_uri_parameter_supported: boolean;
    require_request_uri_registration: boolean;
    response_types_supported: Array<string>;
    scopes_supported: Array<string>;
    subject_types_supported: Array<string>;
    token_endpoint: string;
    token_endpoint_auth_methods_supported: Array<string>;
    token_endpoint_auth_signing_alg_values_supported: Array<string>;
    ui_locales_supported: Array<string>;
    userinfo_encryption_alg_values_supported: Array<string>;
    userinfo_encryption_enc_values_supported: Array<string>;
    userinfo_endpoint: string;
    userinfo_signing_alg_values_supported: Array<string>;

    [k: string]: any;
}
