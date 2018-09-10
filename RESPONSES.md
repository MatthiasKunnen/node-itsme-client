# Responses
This file contains examples of responses by certain methods. Objects have been
converted to JSON. JWTs can be pasted into https://jwt.io for easy dissection
and verification.

# Token
##

## `ItsmeClient.exchangeAuthorizationCode()`
```json
{
    "sub": "02q815kkuer8pbbgo3i65vaonfivmx82oxb6",
    "aud": "eyhPsqyaEf",
    "acr": "tag:sixdots.be,2016-06:acr_basic",
    "iss": "https://e2emerchant.itsme.be/oidc",
    "exp": 1536537856,
    "iat": 1536537556
}
```

## `ItsmeClient.decryptIdToken()`
```
eyJraWQiOiJzMSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIwMnE4MTVra3VlcjhwYmJnbzNpNjV2YW9u
Zml2bXg4Mm94YjYiLCJhdWQiOiJleWhQc3F5YUVmIiwiYWNyIjoidGFnOnNpeGRvdHMuYmUsMjAxNi0w
NjphY3JfYmFzaWMiLCJpc3MiOiJodHRwczpcL1wvZTJlbWVyY2hhbnQuaXRzbWUuYmVcL29pZGMiLCJl
eHAiOjE1MzY1Mzc4NTYsImlhdCI6MTUzNjUzNzU1Nn0.NMJ5CrNf9I1nV1tDHfZ4DCGXu1G1K5uwQjMt
OwHBWl6lLRmO7OoySyQbONAWixFGQWjpdMh22yfVjJwI0SFAxQqOcKVJU93dNLfGARZcJFfdvwf6D5ZT
QFeurm7CPodGlGikitBjZl3rvBlU5zzd5LAUyb6OLdJ1Z7W3MKPF1eF_yAT_kQWGxYPK0m97vA7dzW6r
jLSSSWh16atfXHMVAcwu0NF0xSvXIzCF40whbT4KBNEW0E3qnXGbhhDUarXsZ0sKIYL-C3pL3OfJMe2g
nbouXUXKJbhspTqYwdMxos6PL0rOwYm3SqKXfZdUAyd3pq2woff4geoENKMu_r6Mmg
```

## `ItsmeClient.verifyIdToken()`
Same for `ItsmeClient.decryptAndVerifyIdToken()`

```json
{
    "sub": "02q815kkuer8pbbgo3i65vaonfivmx82oxb6",
    "aud": "eyhPsqyaEf",
    "acr": "tag:sixdots.be,2016-06:acr_basic",
    "iss": "https://e2emerchant.itsme.be/oidc",
    "exp": 1536537856,
    "iat": 1536537556
}
```

# User Info
## `ItsmeClient.userInfo()`
```
eyJjdHkiOiJKV1QiLCJ0eXAiOiJKV1QiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9B
RVAifQ.WCrdnd_gifzLMxYbEqjkx0RKWm8UISZAC4I9Hb8NDqk9-5bC_Xe8_RYLYHnka1LPtNuOHzqN6
kHqULEsJZHPwCismADxpf73A_VZF2vzuvKnVHr6wQQB-llm307hsV0RZO35oOcYmX0wSA0o_DZQiat3Y
7-Rmr4OpWCcDOwUYKwyz4662EuFM2sMkw5C8xPGfa5q5mLkZlQHQzTA1u8t9oMIwr_djdhgA2FEfKkkg
C0EWHKv71pcmUnjjfszhP6VK5qg0J9U8kZc1kNGroABUul_Tu0C93YL-3oHENySre6t1KpzHaceuNIdS
b83E-uZDWj1sGwfeTnVR15WcQtz5A.nj4_O25r8XjkmGPpGek1CA.3avpGx5-qsCSmjR3V8zXXrqYuJv
27FuhzYNKK0NauD2HATUVA4RXY8SROKVLHl3MM17IJ48LiS_QyW0hMpla-WFGNsG8CFh284XprjEpgUR
4GM1lUvCZgUhUK0q3xrjiPw5pBQQw6ebzErz27wU_WS9C1fZ2K-TabB5Af8HDO6yiufQi9F1iTShvIGn
yTf8ZIPm1UkKofre_PJFzJodCBUqN1GUn_Swox2F7Gkh6yA0sv4NoWNw8Euk49fBUN5GD0QBTAyHLPb4
4ZrAvRTGdyovYHo7GxZSVjJJY1ZovTv0qTzsmjhi3Zuw-uoGXm673vevDU46EuocWaVUB5N9Dv7CHdCf
SwKYGdkm2UtSUZhc4u6VODy79kuWVRBN0vmuhX1eh3PdH-OI4ttbOimJz0RhreYKWUAqxA3677leCUro
T87ywyo2-Jh_ilEeD-hWJUcDuSCgrBnAecTTnR7lyoUVzGsUrfw9wM-_NOZZZfsmqrHmXlmiOB1tMusA
4JinMnEcFZrxDlE6byL9y0W1VAz9VmjV6yB32bkXrZw_N9ti15jay2qgaBkarziWbWLp0SmnPvm3_sHW
q5eqzxn35bx74sjakcu_ZenJUUzWDC6gm8DRpRSuWDBnXWkowPR9L7_os_wussWtwT9vgSGTGAy9wXxv
UrJ2-e9NCp19we3ve3SA0W18mkyKHOLF29slGISvNgzLj0g35y7iXweCYEICH7jz6BQ8ru5Rp0a7tVM0
fk9WmXV45oPHYQfMwrBQUkMXAC_J6fgJKo_FxS-_wvIXOKsfuR0-NPCgaxo48e76-_P3L_92TRpxuNm0
U0RrMFqCNHE08cilxOXGf3PAgv4x4dcr_2_wLJgRI1iOz4gI8400GYCfswOcmbeecjaAyKysgAHxjCRM
aGOOgZRjDSD0Dsb0imDiM_yDOqgNT9AV70UB1FoqL_nFHGsZiY308PBxFWFkX9d4416zcezIpINkG1Va
17jeo1wV95o1jRBoQP8V1DFEfhbcco14Q4WMfBwKxfEVfss3XRAim3ijwqDwcp1d5Au5wyfmKKUYKoF-
3Mgk_KDGoyfhEZ7kSQrXPpVeaaUsTg_l4veD7fz_bac0OeZfdVaLZIrw1Wm35uBI.FVVRrxjqW5BPVLY
N2dF1yA
```

## `ItsmeClient.decryptUserInfo()`
```
eyJraWQiOiJzMSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIwMnE4MTVra3VlcjhwYmJnbzNpNjV2YW9u
Zml2bXg4Mm94YjYiLCJhdWQiOiJleWhQc3F5YUVmIiwiYmlydGhkYXRlIjoiMTk2OS0wNC0xNiIsImFk
ZHJlc3MiOiJ7XCJjb3VudHJ5XCI6XCJCRVwiLFwic3RyZWV0X2FkZHJlc3NcIjpcInN0cmVldFwiLFwi
bG9jYWxpdHlcIjpcIkJydXhlbGxlc1wiLFwicG9zdGFsX2NvZGVcIjpcIjEwOTRcIn0iLCJnZW5kZXIi
OiJtYWxlIiwibmFtZSI6Ik1hdHRoaWFzIEMiLCJpc3MiOiJodHRwczpcL1wvZTJlbWVyY2hhbnQuaXRz
bWUuYmVcL29pZGMiLCJsb2NhbGUiOiJubCIsImdpdmVuX25hbWUiOiJNYXR0aGlhcyIsImZhbWlseV9u
YW1lIjoiQyJ9.OB41qh6BHuJZgEjr5XBrUzFEuJCeevQa152ZbuZVFRKWKy9DPs766w4jirSfdhvzc6C
tyuqR5LaiWuuMHx92B-QmZAiKZQmDgM-ZNwcPdYdQrYWS4dtuANg1BculUalG_kjKvQwMab6YNOFqdO0
ow4eT115zJvWdxdC5fypM6IRg52wn8dQi9gf0gmYEVDerjwMZ2HGUsrZiM1oGhyLQivK4dWfnl9lxm90
nDXScSMDRX0Nbz9bHryFvGPJX3ryUbbOURt7IDfzuCpat7f1wzDvZ7eIaV1tcWgr10eDizgBjBBPXhH6
ITbet4CqrhZDeH5A5aKKVUAz6HrAnP98HZg
```

## `ItsmeClient.verifyUserinfo()`
Same for `ItsmeClient.userInfoComplete()`
```json
{
    "sub": "02q815kkuer8pbbgo3i65vaonfivmx82oxb6",
    "aud": "eyhPsqyaEf",
    "birthdate": "1969-04-16",
    "address": {
        "country": "BE",
        "street_address": "street",
        "locality": "Bruxelles",
        "postal_code": "1094"
    },
    "gender": "male",
    "name": "Matthias C",
    "iss": "https://e2emerchant.itsme.be/oidc",
    "locale": "nl",
    "given_name": "Matthias",
    "family_name": "C"
}
```

# Other
## `ItsmeClient.getPublicJwkSet()`
```json
{
    "keys": [
        {
            "kty": "RSA",
            "kid": "s1",
            "use": "sig",
            "alg": "RS256",
            "e": "AQAB",
            "n": "pJADu0nyhCrh9XIRTO42V6YQqAeNABGGo006hknHw86wYByjHMhpYYwHuxuyx44mO8iQIcJkh5NPlkcaDN90RH0JOxyEE1pES5C3LqntC0mAP6BWoqMhY8g4PT2EJyPjVYZcpaZw0VUp6E5kx847dbvhMe8KWy0geuCwrCgXVhWDRoIyV7r2k948zlmRJjbdjkNosYEFI43nicZ_jckTbs_8nzlxDQo8GtstdhR_oUbXyyBJM66SUA8KxWV6NG0zubNIYWxHIwlU938gdpTNfUMKm78f78iPyfuoPz2dTb6Z7OP7WZb06eRv41i_dS0Zh-sKKHrpUYXRf6VrOoU96w"
        },
        {
            "kty": "RSA",
            "kid": "e1",
            "use": "enc",
            "alg": "RSA-OAEP",
            "e": "AQAB",
            "n": "jpEyL3uCZ1Grkg4sFTtAup0TxpZRiNbB2qyyVJQsXE8QZGfEFSKE847KF2o7TtafORyidfGI7bvBrh34zA1EzR0FqCpLk0z9yGnAmG-dMslpViwO7Ob-WT472KAdtpkQPIgxnkxT7LCR0HyjR_3yxCe3UzcsLg35b-xlrln7Hw9B8Zy8p4Q1lBsnKo-TiHY6C4poSCZTOMeEKn3zuWXvYD33F9ZAqlvtXKKvuSbWrt-34e1lN9TqFWr4GUuuVS_iBjntaNt56Kj9w0aoSuhN7MrHAM0O-FfqJc_BBtJwILr1JcaM_mklwyHJ0eXRvqh3G24bBcXhHYa1yvkAoI8Nnw"
        }
    ]
}
```
