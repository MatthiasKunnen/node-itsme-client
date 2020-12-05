export interface GenerateAuthUrlInput<ServiceCodes extends string> {

    /**
     * Any additional params you want added to the URL. E.g. nonce, claim, login_hint, ...
     */
    additionalParams?: {[k: string]: string};

    /**
     * Additional scopes to request from itsme auth endpoint. E.g. profile, email.
     * The scope openid and service is already added and as such should not be specified here.
     */
    additionalScopes?: Array<string>;

    /**
     * Service code you received when registering your project in the itsme® B2B portal. This
     * service code will be used to find the matching redirect_uri as supplied in the ItsmeClient
     * constructor.
     */
    service: ServiceCodes;

    /**
     * State variable that is passed through the requests and returned to the redirect_uri.
     * Recommended to be used to keep track of sessions
     */
    state?: string;
}
