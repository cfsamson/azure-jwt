

# A library that authenticates Azure JWT tokens.
This library will fetch public keys from Microsoft and validate the authenticity of the Tokens and verify that they
are issued by Azure and are not tampered with. See further down for details on what this library validates and
whay you need to take care of yourself.

This library will send requests to the Microsoft api to get updated keys. The default is to expire the stored keys after
24 hours and fetch new ones since that correspond with the normal key rotation scheme. There is also a default retry fallback 
where key that doesn't match wil trigger _one_ refresh of the keys (limited to once an hour), just in case the set default is 
badly synced with the rotation of the Microsoft public keys or Microsoft decides to rotate the keys immideately for some reason. 
Both of these settings can be configured.

## Example

```rust

use azure_auth_rs::*;

let client_id = "my client id from Azure";
let mut az_auth = AzureAuth::new(client_id).unwrap();

let decoded = az_auth.validate_token(TEST_TOKEN)?;

// get user, or perform additional validation here

```

## Security

**This library validates five things:**
1. That the token is issued by Azure and is not tampered with
2. That this token is issued for use in your application
3. That the token is not expired
4. That the token is not used before it's valid
5. That the token is not issued in the future
6. That the algorithm the token tells us to use is the same as we use*

* Note that we do NOT use the token header to set the algorithm for us, look [at this article for more information on why that would be bad](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)

The validation will `Error` on a failed validation providing more granularity for library users to find out why the token
was rejected.

**You'll need:**

You will need a private app_id created by Azure for your application to be able to veriify that
the token is created for your application (and not anyone with a valid Azure token can log in). This is the ID this library
needs from you to authenticate that the token vas issued for your application.

You get a verified token parsed for you in return.

**You still must take care of:**

1. Validating that the user has the right access to your system yourself
2. Validating any other information that is important for your use case
3. If you as for more information about the user than what is standard you will need
to make a struct that maps to all the fields in the token.

For more information, see this artice: https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens