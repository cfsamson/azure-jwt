use azure_oauth_rs as auth;
use auth::*;
use base64;
use jsonwebtoken as jwt;

    const PUBLIC_KEY_TEST: &str = 
    "MIIBCgKCAQEAyRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4\
    l4sggh5/CYYi/cvI+SXVT9kPWSKXxJXBXd/4LkvcPuUakBoAkfh+eiFVMh2VrUyW\
    yj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG\
    /AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBIMc4l\
    QzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi+yUod+j8MtvIj812dkS4QMiRVN/by2h\
    3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQIDAQAB";

    const PRIVATE_KEY_TEST: &str =
    "MIIEpAIBAAKCAQEAyRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTL\
    UTv4l4sggh5/CYYi/cvI+SXVT9kPWSKXxJXBXd/4LkvcPuUakBoAkfh+eiFVMh2V\
    rUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8H\
    oGfG/AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBI\
    Mc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi+yUod+j8MtvIj812dkS4QMiRVN/\
    by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQIDAQABAoIBAHREk0I0O9DvECKd\
    WUpAmF3mY7oY9PNQiu44Yaf+AoSuyRpRUGTMIgc3u3eivOE8ALX0BmYUO5JtuRNZ\
    Dpvt4SAwqCnVUinIf6C+eH/wSurCpapSM0BAHp4aOA7igptyOMgMPYBHNA1e9A7j\
    E0dCxKWMl3DSWNyjQTk4zeRGEAEfbNjHrq6YCtjHSZSLmWiG80hnfnYos9hOr5Jn\
    LnyS7ZmFE/5P3XVrxLc/tQ5zum0R4cbrgzHiQP5RgfxGJaEi7XcgherCCOgurJSS\
    bYH29Gz8u5fFbS+Yg8s+OiCss3cs1rSgJ9/eHZuzGEdUZVARH6hVMjSuwvqVTFaE\
    8AgtleECgYEA+uLMn4kNqHlJS2A5uAnCkj90ZxEtNm3E8hAxUrhssktY5XSOAPBl\
    xyf5RuRGIImGtUVIr4HuJSa5TX48n3Vdt9MYCprO/iYl6moNRSPt5qowIIOJmIjY\
    2mqPDfDt/zw+fcDD3lmCJrFlzcnh0uea1CohxEbQnL3cypeLt+WbU6kCgYEAzSp1\
    9m1ajieFkqgoB0YTpt/OroDx38vvI5unInJlEeOjQ+oIAQdN2wpxBvTrRorMU6P0\
    7mFUbt1j+Co6CbNiw+X8HcCaqYLR5clbJOOWNR36PuzOpQLkfK8woupBxzW9B8gZ\
    mY8rB1mbJ+/WTPrEJy6YGmIEBkWylQ2VpW8O4O0CgYEApdbvvfFBlwD9YxbrcGz7\
    MeNCFbMz+MucqQntIKoKJ91ImPxvtc0y6e/Rhnv0oyNlaUOwJVu0yNgNG117w0g4\
    t/+Q38mvVC5xV7/cn7x9UMFk6MkqVir3dYGEqIl/OP1grY2Tq9HtB5iyG9L8NIam\
    QOLMyUqqMUILxdthHyFmiGkCgYEAn9+PjpjGMPHxL0gj8Q8VbzsFtou6b1deIRRA\
    2CHmSltltR1gYVTMwXxQeUhPMmgkMqUXzs4/WijgpthY44hK1TaZEKIuoxrS70nJ\
    4WQLf5a9k1065fDsFZD6yGjdGxvwEmlGMZgTwqV7t1I4X0Ilqhav5hcs5apYL7gn\
    PYPeRz0CgYALHCj/Ji8XSsDoF/MhVhnGdIs2P99NNdmo3R2Pv0CuZbDKMU559LJH\
    UvrKS8WkuWRDuKrz1W/EQKApFjDGpdqToZqriUFQzwy7mR3ayIiogzNtHcvbDHx8\
    oFnGY0OFksX/ye0/XGpy2SFxYRwGU98HPYeBvAQQrVjdkzfy7BmXQQ==";

    fn test_token_header() -> String {
        format!(
            r#"{{
                "typ": "JWT",
                "alg": "RS256",
                "kid": "i6lGk3FZzxRcUb2C3nEQ7syHJlY"
            }}"#
        )
    }

    fn test_token_claims() -> String {
        format!(
            r#"{{
                "aud": "6e74172b-be56-4843-9ff4-e66a39bb12e3",
                "iss": "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0",
                "iat": {},
                "nbf": {},
                "exp": {},
                "aio": "AXQAi/8IAAAAtAaZLo3ChMif6KOnttRB7eBq4/DccQzjcJGxPYy/C3jDaNGxXd6wNIIVGRghNRnwJ1lOcAnNZcjvkoyrFxCttv33140RioOFJ4bCCGVuoCag1uOTT22222gHwLPYQ/uf79QX+0KIijdrmp69RctzmQ==",
                "azp": "6e74172b-be56-4843-9ff4-e66a39bb12e3",
                "name": "Abe Lincoln",
                "azpacr": "0",
                "oid": "690222be-ff1a-4d56-abd1-7e4f7d38e474",
                "preferred_username": "abeli@microsoft.com",
                "rh": "I",
                "scp": "access_as_user",
                "sub": "HKZpfaHyWadeOouYlitjrI-KffTm222X5rrV3xDqfKQ",
                "tid": "72f988bf-86f1-41af-91ab-2d7cd011db47",
                "uti": "fqiBqXLPj0eQa82S-IYFAA",
                "ver": "2.0"
            }}"#, 
        chrono::Utc::now().timestamp() - 1000,
        chrono::Utc::now().timestamp() - 2000,
        chrono::Utc::now().timestamp() + 1000)
    }

fn from_base64_to_bytearray(b64_str: &str) -> Result<Vec<u8>, AuthErr> {
    let decoded = base64::decode_config(b64_str, base64::STANDARD)
        .map_err(|e| AuthErr::ParseError(e.to_string()))?;
    Ok(decoded)
}

    // We create a test token from parts here. We use the v2 token used as example
    // in https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens
    fn generate_test_token() -> String {
        // jwt library expects a `*.der` key wich is a byte encoded file so
        // we need to convert the key from base64 to their byte value to use them.
        let private_key: Vec<u8> = from_base64_to_bytearray(PRIVATE_KEY_TEST).expect("priv_key");

        // we need to construct the calims in a function since we need to set
        // the expiration relative to current time
        let test_token_playload = test_token_claims();
        let test_token_header = test_token_header();

        // we base64 (url-safe-base64) the header and claims and arrange
        // as a jwt payload -> header_as_base64.claims_as_base64
        let test_token = [
            base64::encode_config(&test_token_header, base64::URL_SAFE),
            base64::encode_config(&test_token_playload, base64::URL_SAFE),
        ]
        .join(".");

        // we create the signature using our private key
        let signature = jwt::sign(&test_token, &private_key, jwt::Algorithm::RS256).unwrap();

        let public_key = from_base64_to_bytearray(PUBLIC_KEY_TEST).expect("publ_key");

        // we construct a complete token which looks like: header.claims.signature
        let complete_token = format!("{}.{}", test_token, signature);

        complete_token
    }

    //#[test]
    fn decode_token() {
        let token = generate_test_token();

        // we need to construct our own key object that matches on `kid` field
        // just as it should if we used the fetched keys from microsofts servers
        // since our validation methods converts the base64 data to bytes for us
        // we don't need to worry about that here.
        let from_std = base64::decode_config(PUBLIC_KEY_TEST, base64::STANDARD).unwrap();
        let to_url_safe = base64::encode_config(&from_std, base64::URL_SAFE);
        let key = KeyPairs {
            x5t: "i6lGk3FZzxRcUb2C3nEQ7syHJlY".to_string(),
            n: to_url_safe,
            e: String::new(),
        };

        let mut az_auth = AzureAuth::new("6e74172b-be56-4843-9ff4-e66a39bb12e3").unwrap();
        az_auth.set_public_keys(vec![key]);

        az_auth.validate_token(&token).unwrap();
    }