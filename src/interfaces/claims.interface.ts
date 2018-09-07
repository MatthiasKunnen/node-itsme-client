export interface Claims {
    iss: string;
    sub: string;
    aud: string;
    jti: string;
    exp: number;
}

export interface UserInfoClaims {

    /**
     * UserCode, unique identifier for the user.
     */
    sub: string;

    /**
     * Audience, clientId of the relying party.
     */
    aud: string;

    /**
     * Itsme endpoint issuing this data.
     */
    iss: string;

    /**
     * Date of birth of the user. YYYY-MM-DD format.
     */
    birthdate?: string;

    /**
     * Will need to be parsed as JSON.
     */
    address?: {
        country: string;
        locality: string;
        postal_code: string;
        street_address: string;
    };

    gender?: 'male' | 'female';

    /**
     * Full name.
     */
    name?: string;

    /**
     * First name.
     */
    given_name?: string;

    locale?: 'de' | 'en' | 'fr' | 'nl';

    family_name?: string;
}
