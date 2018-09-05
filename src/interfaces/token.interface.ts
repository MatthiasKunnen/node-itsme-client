export interface Header {
    alg: string;
    kid: string;
}

export interface IdToken {

    /**
     * Identifier of the issuer of the ID Token.
     */
    iss: string;

    /**
     * An identifier for the User, unique among all itsme® accounts and never
     * reused. Use sub in the application as the unique-identifier key for the
     * User.
     */
    sub: string;

    /**
     * Audience of the ID Token. This will contain the client_id. This is the
     * client identifier (e.g. : Project ID) you received when registering your
     * application in the itsme® B2B portal.
     */
    aud: string;

    /**
     * Expiration time on or after which the ID Token MUST NOT be accepted for
     * processing.
     */
    exp: number;

    /**
     * The time the ID Token was issued, represented in Unix time (integer
     * seconds).
     */
    iat: number;

    /**
     * The time the User authentication occurred, represented in Unix time
     * (integer seconds).
     */
    auth_time: string;

    /**
     * Not Before.
     */
    nbf?: number;

    nonce: string;
}

export interface TokenBase {

    /**
     * The Access Token which may be used to access the userInfo Endpoint.
     */
    access_token: string;
    token_type: 'Bearer';

    /**
     * Time in seconds in which the token expires.
     */
    expires_in: number;
}

export interface TokenResponse extends TokenBase {

    /**
     * The Base64URL encoded token signed with the itsme® private key.
     */
    id_token: string;
}
