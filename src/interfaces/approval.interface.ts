export interface ApprovalTemplate {
    'tag:sixdots.be,2016-08:claim_approval_template_name': {
        value: string;
        essential: true;
    };

    [k: string]: {
        value: any;
        essential?: boolean;
        [k: string]: any;
    };
}

export interface ApprovalInput {

    /**
     * The approval template to use. Generate one using
     * *generatePaymentApprovalTemplate* or *generateFreeTextApprovalTemplate*.
     * Alternatively, provide your own.
     */
    approvalTemplate: ApprovalTemplate;

    /**
     * To circumvent errors on requests with too many characters in the URL, the
     * approval service uses a request_uri field to refer a URI where a request
     * object, in JWT format, can be retrieved. This token will be appended onto
     * the requestUri configuration parameter of the relying party.
     * E.g. requestUri: "https://jwt.store/", requestUriToken: "jijkjfsd8DF4afd"
     * Results in a request_uri of "https://jwt.store/jijkjfsd8DF4afd"
     *
     * The implementers of this library are themselves responsible for hosting
     * the JWT on the supplied URL. Once read, you can discard the JWT since
     * itsme will only read it once.
     */
    requestUriToken: string;

    /**
     * The service code of this approval. This will also be used to use the
     * correct redirect URI.
     */
    serviceCode: string;

    /**
     * Use sub to refer to the previously identified user that you seek
     * approval of. Do NOT use this together with {@link telephoneNumber}.
     * Takes precedence over {@link telephoneNumber}.
     */
    sub?: string;

    /**
     * Use a telephone number to refer to the previously identified user that
     * you seek approval of. {@link sub} takes precedence if specified.
     */
    telephoneNumber?: string;
}

export interface ApprovalRequest {
    /**
     * The endpoint to send the approval request to.
     */
    endpoint: string;

    /**
     * The query params to attach to the approval request.
     */
    params: {[k: string]: string};

    /**
     * A JWE of a JWS of the request data.
     */
    request: string;
}
