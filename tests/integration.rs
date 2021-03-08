use azure_jwt::*;
use jsonwebtoken as jwt;

const PUBLIC_KEY_N: &str = "AOx0GOQcSt5AZu02nlGWUuXXppxeV9Cu_9LcgpVBg_WQb-5DBHZpqs8AMek5u5iI4hkHCcOyMbQrBsDIVa9xxZxR2kq_8GtERsnd6NClQimspxT1WVgX5_WCAd5rk__Iv0GocP2c_1CcdT8is2OZHeWQySyQNSgyJYg6Up7kFtYabiCyU5q9tTIHQPXiwY53IGsNvSkqbk-OsdWPT3E4dqp3vNraMqXhuSZ-52kLCHqwPgAsbztfFJxSAEBcp-TS3uNuHeSJwNWjvDKTPy2oMacNpbsKb2gZgzubR6hTjvupRjaQ9SHhXyL9lmSZOpCzz2XJSVRopKUUtB-VGA0qVlk";
const PUBLIC_KEY_E: &str = "AQAB";

const PRIVATE_KEY_TEST: &str = "MIIEowIBAAKCAQEA7HQY5BxK3kBm7TaeUZZS5demnF5X0K7/0tyClUGD9ZBv7kME\
                                dmmqzwAx6Tm7mIjiGQcJw7IxtCsGwMhVr3HFnFHaSr/wa0RGyd3o0KVCKaynFPVZ\
                                WBfn9YIB3muT/8i/Qahw/Zz/UJx1PyKzY5kd5ZDJLJA1KDIliDpSnuQW1hpuILJT\
                                mr21MgdA9eLBjncgaw29KSpuT46x1Y9PcTh2qne82toypeG5Jn7naQsIerA+ACxv\
                                O18UnFIAQFyn5NLe424d5InA1aO8MpM/Lagxpw2luwpvaBmDO5tHqFOO+6lGNpD1\
                                IeFfIv2WZJk6kLPPZclJVGikpRS0H5UYDSpWWQIDAQABAoIBAQC982Yrmi7q7IHC\
                                /qWglUpzKhLGe2PAWVVaZ5rfnIoNs8K3fU8QcUKumFGAMsjpeM1pnaXSeExFmGsM\
                                Y+Ox1YwSUA81DYxuH6Ned86YDqpgIDr5M0Ba7JmDOLWXoIR8byB19oMOuhjBAW+P\
                                EKlb0Z2a1f1Gt3J8oAxWq8PDsShHRdjyesVS36QZpIgjZskcNws/zqqqDRrLWuLm\
                                Avk6E+tMD6sqo9xpzEqHF7rmwtt5yAtM1oZdWoEg2O+wZH5DBX2GhLlNZi/8sIiF\
                                Mo+jouQn+l6Qc4G65vnnoZ+yEuf9fTJPnTHBFMViUcmTPsdbD4eLfrRXwAE9GYrv\
                                R/RVusABAoGBAPgsQ4kAChpzU2aP21NQV1XTBW+eoHVbcJoYuOlmwB6x5o8lDUz/\
                                EQVVYZavfNY1AjhEkfltCDjm1GHyWofrtGKTy7DHSZwPw5CxuqDtaiC6PMpFEu+O\
                                xa09s7IZxpgInlrhY5JskOkH495BQ0xIU8UDxuP6sdtVNeQmWGjKG7kBAoGBAPPp\
                                Nid4QEV4XleyAXT/JQGugdpa7TirWOEATNo10YPPqz7GphRhucT0ipNKMi/0XKh3\
                                U0IC7XxjUvtE2LP9TVGAcV/Wzi4EYp1fziFuF9QcUds2tJ60SpfgIQrmVcF1zHxn\
                                4/mSABoIyFxZSb4Tq9f+KXPAO5/l0NjgrVwk6gVZAoGAbMVZxE4UH4u0XhtnEZkA\
                                7kjS9R0dTtKJA8EaKpIyWkG2v76JmdmhaCkH4LeBi5EoK+lB4YR8OhRRuawzKaeR\
                                JDOK7ywpgxEVsfFzzty/yyBVTIIBzqVQ1qFYhRLvC+ubHFH1BlQ3HyuqH9uS13hL\
                                3unM3lceZPdv61MzJJqQlAECgYAWg0MFV5sPDnIexAZQZzBiPFot7lCQ93fHpMBz\
                                L557/RIARFOV9AMyg6O6vpFtTa+zuPfNUvnajkxddthNnKajTCiqwOfc5Xi4r9wV\
                                x9SZNlfz1NPNBjUQWZaTK/lkVtwd63TmVyx9OqxLoc4lpikpUYM/9NFMC+k/61T0\
                                +U9EWQKBgCdZV3yxwkz3pi6/E40EXfUsj8HQG/UtFJGeUNQiysBrxTmtmwLyvJeC\
                                GruG96j1JcehpbcWKV+ObyMQuk65dM94uM7Wa+2NCA/MvorVcU7wdPbq7/eczZU4\
                                xMd+OWT6JsInVM1ASh1mcn+Q0/Z3WqxxetCQLqaMs+FATn059dGf";

// Token taken from microsoft docs: https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens
fn test_token_header() -> String {
    format!(
        r#"{{
                "typ": "JWT",
                "alg": "RS256",
                "kid": "i6lGk3FZzxRcUb2C3nEQ7syHJlY"
            }}"#
    )
}

// Token taken from microsift docs: https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens
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
        chrono::Utc::now().timestamp() + 1000
    )
}

// We create a test token from parts here. We use the v2 token used as example
// in https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens
fn generate_test_token() -> String {
    let private_key = jwt::EncodingKey::from_base64_secret(PRIVATE_KEY_TEST).expect("priv_key");

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
    let signature =
        jwt::crypto::sign(&test_token, &private_key, jwt::Algorithm::RS256).expect("Singed.");

    // we construct a complete token which looks like: header.claims.signature
    let complete_token = format!("{}.{}", test_token, signature);

    complete_token
}

#[test]
fn decode_token() {
    let token = generate_test_token();
    // we need to construct our own key object that matches on `kid` field
    // just as it should if we used the fetched keys from microsofts servers.
    let key = Jwk {
        kid: "i6lGk3FZzxRcUb2C3nEQ7syHJlY".to_string(),
        n: PUBLIC_KEY_N.to_string(),
        e: PUBLIC_KEY_E.to_string(),
    };

    let mut az_auth = AzureAuth::new("6e74172b-be56-4843-9ff4-e66a39bb12e3").unwrap();
    // We manually overwrite the keys so we use the ones we have for testing
    az_auth.set_public_keys(vec![key]);

    az_auth.validate_token(&token).expect("validated");
}
