//use azure_jwt::*;
//use jsonwebtoken as jsw;
//
//const TOKEN: &str =
//    "a_valid_azure_token__Note_that_the_keys_will_expire_so_this_test_needs_fresh_tokens_to_run";

// Thos integration test is supposed to be run when you want to test against a valid azure token.
// TODO: See if we can redirect this test to microsioft demo/test api.
//#[test]
// fn decode_token() {
//     let mut az_auth = AzureAuth::new("an_active_client_id").unwrap();
//     let header: jsw::TokenData<AzureJwtClaims> = jsw::dangerous_unsafe_decode(TOKEN).unwrap();
//     println!("{:?}", header);
//     az_auth.validate_token(TOKEN).unwrap();
// }
