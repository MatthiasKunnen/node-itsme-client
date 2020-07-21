import {generateFreeTextApprovalTemplate} from './approval-templates/free-text.approval-template';
import {IdentityProvider} from './identity-provider';
import {JwkSet} from './interfaces/jwk-set.interface';
import {ItsmeClient} from './itsme-client';
import {createKeyStore} from './util';

async function test() {
    const itsmeDiscoveryUrl = 'https://e2emerchant.itsme.be/oidc/.well-known/openid-configuration';
    const idp = await IdentityProvider.discover(itsmeDiscoveryUrl);

    const jwkSet: JwkSet = {
        keys: [
            {
                kty: 'RSA',
                d: `
                    FVSxlyJTtDwWxAkAIxexpZTaDd3EsiCTcjF9h5Ciu0fcZujvX7i-qC1Nhzxk5ScQ36j0vduDymsW
                    4uTehJKmcIZAnw_oMtX9ikn85KiUGGVzoUu4TyaUGmoGmDGUIrqtKhXbhoFXmFrQrtMSjy-1V2J-
                    I0nX7s-fqS3c2MPtmnPEMXkLpxHr2hStRiIQFIf3T7Dv4aX5-2o00JViEM-cXTQZJerkDjSgj7Kh
                    GP7EKnkTfV7sBAiuRnbtOFqrNNMjXpGWJQSPbof1_6oo3_R9Jw7TYTNMzIyXWDmpam_Zf_iPFltF
                    RWTh9nUygCAvpnPXRgFkgJN2JuSY6oLrIG-HsQ`,
                e: 'AQAB',
                use: 'sig',
                kid: 's1',
                alg: 'RS256',
                n: `
                    pJADu0nyhCrh9XIRTO42V6YQqAeNABGGo006hknHw86wYByjHMhpYYwHuxuyx44mO8iQIcJkh5NP
                    lkcaDN90RH0JOxyEE1pES5C3LqntC0mAP6BWoqMhY8g4PT2EJyPjVYZcpaZw0VUp6E5kx847dbvh
                    Me8KWy0geuCwrCgXVhWDRoIyV7r2k948zlmRJjbdjkNosYEFI43nicZ_jckTbs_8nzlxDQo8Gtst
                    dhR_oUbXyyBJM66SUA8KxWV6NG0zubNIYWxHIwlU938gdpTNfUMKm78f78iPyfuoPz2dTb6Z7OP7
                    WZb06eRv41i_dS0Zh-sKKHrpUYXRf6VrOoU96w`,
            },
            {
                kty: 'RSA',
                d: `
                    J7jk1r3-83KZ7zPrrG659kTVwbsYNJxBnwAHH_G4-m89DfyrcYgQqxvZyvRaWfkKnAsSaPJHSJXL
                    vQu0yoXX6Z5weQ5vyDbnbvOoKdDPZ9seclgMQI2LyKnCWvUh0kKLd5Iq4QQ7TfNUbVaM1_41qdm3
                    BoSU1rAmE702B4IiqeBUZNNgVxUnCecBYcBxSJf-C6NKNBGcMVcpGbVE6zF90C87FOze3cE-NwfR
                    mMfzGC22Ybj9vEaqxQo-JFsQTKxUwtfhNO4S_aSQPjbpmEA9mfEKzbJG6NzmzDqxwAJy3Jfi9IdI
                    Fu6mjenjX-rbYpLGWorznocJcdIyxb_kLJ56QQ`,
                e: 'AQAB',
                use: 'enc',
                kid: 'e1',
                alg: 'RSA-OAEP',
                n: `
                    jpEyL3uCZ1Grkg4sFTtAup0TxpZRiNbB2qyyVJQsXE8QZGfEFSKE847KF2o7TtafORyidfGI7bvB
                    rh34zA1EzR0FqCpLk0z9yGnAmG-dMslpViwO7Ob-WT472KAdtpkQPIgxnkxT7LCR0HyjR_3yxCe3
                    UzcsLg35b-xlrln7Hw9B8Zy8p4Q1lBsnKo-TiHY6C4poSCZTOMeEKn3zuWXvYD33F9ZAqlvtXKKv
                    uSbWrt-34e1lN9TqFWr4GUuuVS_iBjntaNt56Kj9w0aoSuhN7MrHAM0O-FfqJc_BBtJwILr1JcaM
                    _mklwyHJ0eXRvqh3G24bBcXhHYa1yvkAoI8Nnw`,
            },
        ],
    };

    const keyStore = await createKeyStore(jwkSet);

    keyStore.all().forEach(k => console.log(k.kid, k.use, k.toPEM(true)));
    keyStore.all().forEach(k => console.log(k.kid, k.use, k.toPEM()));

    const itsmeClient = new ItsmeClient(
        idp,
        {
            clientId: 'eyhPsqyaEf',
            keyStore,
            requestUri: 'https://119c2a3a.ngrok.io/store/',
            serviceCodes: {
                FORCIT_LOGIN: 'https://119c2a3a.ngrok.io/callback/vote',
            },
        },
    );

    console.log(await itsmeClient.getApprovalRequest({
        approvalTemplate: generateFreeTextApprovalTemplate({
            text: 'hello',
        }),
        requestUriToken: '123',
        serviceCode: 'FORCIT_LOGIN',
        sub: '02q815kkuer8pbbgo3i65vaonfivmx82oxb6',
    }));

    /*
    const token = await itsmeClient.exchangeAuthorizationCode(
        'cmzl0ity35vxqkejh6y53wx9502cnpondxs1',
        'https://119c2a3a.ngrok.io/callback/login',
    );
    const decryptedToken = await itsmeClient.decryptIdToken(token.id_token);
    const verifiedToken = await itsmeClient.verifyIdToken(decryptedToken);
    const userInfo = await itsmeClient.userInfoComplete(token.access_token);
    */
}

test().catch(console.error);
