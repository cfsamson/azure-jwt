

# A library that authenticates Azure JWT tokens.

[![Crates.io](https://img.shields.io/crates/v/azure_jwt.svg)](https://crates.io/crates/azure_jwt)
[![Chrono on docs.rs][docsrs-image]][docsrs]

[docsrs-image]: https://docs.rs/azure_jwt/badge.svg
[docsrs]: https://docs.rs/azure_jwt

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

```

## Note

There is another library: [alcoholic_jwt](https://github.com/tazjin/alcoholic_jwt]) that provides
much of the same functionality but on a slightly lower level allowing for using it with other providers
as well. If you need more control then take a look at that library.

## Performance

When you create a new `AzureAuth` instance in its default configuration it will trigger two calls
to microsoft endpoints (one to get the open connect metadata to get the current jwks_uri and one to 
fetch the jwk sets). You should create these objects with care and prefer using a reference to one
instance. If you're using it on a webserver you should avoid creating a new instance on every connection
and rather instanciate one on server start and use a mutex or channels to do validation. Once the keys 
are loaded the operations should be very fast. More benchmarks are however needed to confirm this, but 
the current benchmark indicates around 74 nanoseconds to perform a validation on my 2013 Intel Core 2 
processor once the public keys are retrieved (should only occur every 24h if set up correctly).

## Security

**This library validates five things:**
1. That the token is issued by Azure and is not tampered with
2. That this token is issued for use in your application
3. That the token is not expired
4. That the token is not used before it's valid
5. That the token is not issued in the future
6. That the algorithm the token header specifies the right algorithm*

* Note that we do NOT use the token header to set the algorithm for us, look [at this article for more information on why that would be bad](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)

The validation will `Error` on a failed validation providing more granularity for library users to find out why the token
was rejected.

**You'll need:**

You will need a private client_id created by Azure for your application to be able to verify that
the token is created for your application (and not anyone with a valid Azure token can log in). This is the ID this library
needs from you to authenticate that the token vas issued for your application.

You get a verified token parsed for you in return.

**You still must take care of:**

1. Validating that the user has the right access to your system yourself
2. Validating any other information that is important for your use case
3. If you as for more information about the user than what is standard you will need
to make a struct that maps to all the fields in the token.

For more information, see this artice: https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens

## Todo
- [ ] Use alcoholic_jwk as basis for parsing and validating tokens and keys
- [ ] See if it's possible to refactor the code to avoid needing a mutable reference to do validation