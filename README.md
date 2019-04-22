

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

## Features
- `vendored` feature will compile OpenSSL with the `vendored` feature: https://docs.rs/openssl/0.10.20/openssl/, but needs to
be used with the `default-features = false` flag or an error will occur.

```toml

azure_jwt = {version="0.1", default-features = false,  features = ["vendored"]}

```

## OpenSSL

This library depends on the [openssl crate](https://docs.rs/openssl/0.10.20/openssl/).
There are two options:
1. If you have an installation of OpenSSL installed you can most likely compile this library with
its default settings.
2. If you don't have OpenSSL libraries installed you can use the `vendored` feature that will in turn
compile the OpenSSL with its `vendored` feature enabled. This will compile and statically link 
OpenSSL to the library. You will need a C compiler, Make and Perl installed for it to build.


## Windows
Most Windows system will not have OpenSSL installed by default so the easiest way to get the library working is compiling with
the `vendored` feature. Beware that building OpenSSL the first time will require some time.

On windows, the `vendored` feature requires a small workaround to find the systems root certificates
so we will add an additional dependency to fix that. For more information see: https://github.com/alexcrichton/openssl-probe 

## Alternatives

There is another library: [alcoholic_jwt](https://github.com/tazjin/alcoholic_jwt) that provides
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
processor and 36 nanoseconds on a newer i7 3.7 GHz, once the public keys are retrieved (which should only occur every 24h 
if set up correctly).

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

You will need a [private client_id created by Azure for your application][link2] to be able to verify that
the token is created for your application (and not anyone with a valid Azure token can log in). This is the ID this library
needs from you to authenticate that the token vas issued for your application.

You get a verified token parsed for you in return.

**You still must take care of:**

1. Validating that the user has the right access to your system 
2. Validating any other information that is important for your use case
3. If you ask for more information about the user than what is defined in [Microsoft ID tokens reference][link1] you will need
to make a struct that maps to all the fields in the token and use the `custom_validation` method.

For more information, see this artice: https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens

## Todo
There are no known errors in the library but there are a few things that could be done to make it better:

- [ ] Use alcoholic_jwk as basis for parsing and validating tokens and keys
- [ ] Avoid leaking `jsonwebtoken::Validation` and provide a layer between so we don't depend on it's API.
- [ ] Look for a better solution to conditionally compile openssl with vendored feature. The cargo.toml hack we have works for nowm though.

[link1]: https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens
[link2]: https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal