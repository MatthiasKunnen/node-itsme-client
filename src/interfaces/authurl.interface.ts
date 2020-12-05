export interface AuthURL {

    /**
     * Scopes to request from itsme auth endpoint
     * Required: "service:YOURSERVICE_TST_LOGIN"
     * Default: ["openid"]
     */
    scopes: Array<string>;
    /**
     * The URL the user should be redirected to once authorized or in the event an error occurs
     */
    redirect_uri: string;
    /**
     * State variable that is passed through the requests and returned to the redirect_uri
     * Recommended to be used to keep track of sessions
     * OPTIONAL
     */
    state?: string;
}
