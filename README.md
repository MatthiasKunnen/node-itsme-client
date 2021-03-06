[![npm version](https://img.shields.io/npm/v/itsme-client.svg?logo=npm&style=for-the-badge)
](https://www.npmjs.com/package/itsme-client)
[![Build Status](https://img.shields.io/github/workflow/status/MatthiasKunnen/node-itsme-client/Main?label=Build&logo=github&style=for-the-badge)
](https://github.com/MatthiasKunnen/node-itsme-client/actions)
[![License](https://img.shields.io/npm/l/itsme-client?&style=for-the-badge&color=green)
](https://github.com/MatthiasKunnen/node-itsme-client/blob/master/LICENSE)

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
This is the basic usage, more options and methods are available. Intellisense and jsdoc should
help you find and understand them.

```TypeScript
import { createKeyStore, IdentityProvider, ItsmeClient } from 'itsme-client';

async function initItsmeClient() {
    const itsmeDiscoveryUrl = 'https://e2emerchant.itsme.be/oidc/.well-known/openid-configuration';
    const itsmeProvider = await IdentityProvider.discover(itsmeDiscoveryUrl);
    return new ItsmeClient(itsmeProvider, {
        clientId: 'your client id here',
        keyStore: await createKeyStore(yourJwkSet),
        serviceCodes: {
            YOUR_SERVICE_CODE: 'https://the-redirect-url-matching-this-service-code',
        },
    });
}
```

## Obtaining user info with an Authorization token

```TypeScript
import { ItsmeClient } from 'itsme-client';

async function wrapper(itsmeClient: ItsmeClient) {
    const token = await itsmeClient.exchangeAuthorizationCode(
        'Authorization code here',
        itsmeClient.generateAuthUrl({
            service: 'YOUR_SERVICE_CODE',
            state: 'optional state',
        }),
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
