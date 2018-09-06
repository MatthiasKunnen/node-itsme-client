# Itsme&reg; client
This library's purpose it to make your server's communication with itsme&reg;
more pleasant.

_itsme-client_ discovers the OpenID configuration of itsme and allows you to
easily exchange tokens without worrying about fetching, caching, signing and
encrypting.

# Usage
## Initialize ItsmeClient

```TypeScript
async function initItsmeClient() {
    const itsmeDiscoveryUrl = 'https://e2emerchant.itsme.be/oidc/.well-known/openid-configuration';
    const itsmeProvider = await IdentityProvider.discover(itsmeDiscoveryUrl));
    return new ItsmeClient(itsmeProvider, {
        clientId: 'your client id here',
        keyStore: await createKeyStore(yourJwkSet),
    });
}
```
