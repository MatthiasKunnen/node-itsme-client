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
