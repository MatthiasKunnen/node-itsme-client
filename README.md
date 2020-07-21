[![npm version](https://img.shields.io/npm/v/itsme-client.svg?style=for-the-badge)
](https://www.npmjs.com/package/itsme-client)

# Itsme® client
This library's purpose it to make your server's communication with itsme®
more pleasant.

_itsme-client_ discovers the OpenID configuration of itsme and allows you to
easily exchange tokens without worrying about fetching, caching, signing and
encrypting.

# Features

 * Endpoint discovery
 * Exchanging an Authorization Token
 * Extracting claims from an ID Token
 * Getting claims from the User Info endpoint
 * Extracting your public keys as a JWK Set
 * Decrypting and verifying JWTs
 * Encrypting and signing JWTs
 * Key rollover
 * Normalizing returned values

The library is written in TypeScript, so typings are available. Plain Node.js
will also work.
When using TypeScript, add `@node_modules/itsme-client/@types` to your
[typeRoots](https://www.typescriptlang.org/docs/handbook/tsconfig-json.html#types-typeroots-and-types).

# Usage
## Initialize ItsmeClient

```TypeScript
import { createKeyStore, IdentityProvider, ItsmeClient } from 'itsme-client';

async function initItsmeClient() {
    const itsmeDiscoveryUrl = 'https://e2emerchant.itsme.be/oidc/.well-known/openid-configuration';
    const itsmeProvider = await IdentityProvider.discover(itsmeDiscoveryUrl);
    return new ItsmeClient(itsmeProvider, {
        clientId: 'your client id here',
        keyStore: await createKeyStore(yourJwkSet),
    });
}
```

## Obtaining user info with an Authorization token

```TypeScript
import { ItsmeClient } from 'itsme-client';

async function wrapper(itsmeClient: ItsmeClient) {
    const token = await itsmeClient.exchangeAuthorizationCode(
        'Authorization code here',
        'https://your-redirect.url/here', // The callback used to acquire the Authorization code
    );

    // Get the user info via the userInfo endpoint
    const userInfo = await itsmeClient.userInfoComplete(token.access_token);

    // Same thing with intermediary steps
    const userInfoJwt = await itsmeClient.userInfo(accessToken);
    const decryptedUserInfo = await itsmeClient.decryptUserInfo(userInfoJwt);
    const userInfoStepByStep = await itsmeClient.verifyUserInfo(decryptedUserInfo);


    // Or get the claims via the ID Token
    const idTokenPayload = await itsmeClient.decryptAndVerifyIdToken(token.id_token);
}
```

## Extracting your public keys as a JWK Set
This library supports extracting your public keys as a JWK Set for easy exposure
via URL or other means.

```TypeScript
itsmeClient.getPublicJwkSet();
```

# Responses
RESPONSES.md contains examples of responses of certain methods.
