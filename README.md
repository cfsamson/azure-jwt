

# A library that authenticates Azure JWT tokens.
This library will fetch public keys from Microsoft and validate the authenticity of the Tokens and verify that they
are issued by Azure and are not tampered with. It will also check that this token is issued to the right audience matching the `aud` Claim of the token with
the client_id you got when you registered your app in Azure. If either of these fail, the token is invalid.

This token will send requests to the Microsoft api to get updated keys. The default is to expire the stored keys after
24 hours and fetch new ones. There is also a default Retry fallback where an invalid key match wil trigger _one_ refresh of
the keys (limited to once an hour), just in case the set default is badly synced with the rotation of the Microsoft public
keys. Both of these settings can be configured.


## Example

# Example

```rust

use azure_auth_rs as auth;
use auth::*;

let app_secret = "my app secret";
let mut az_auth = AzureAuth::new(app_secret).unwrap();

let decoded = az_auth.validate_token(TEST_TOKEN)?;

```

## Security

**This library validates two things:**
1. That the token is issued by Azure and is not tampered with
2. That this token is issued for use in your application

The validation will `Error` on a failed validation providing more granularity for library users to find out why the token
was rejected.

**You'll need:**
You will need a private app_id created by Azure for your application to be able to veriify that
the token is created for your application (and not anyone with a valid Azure token can log in). This is the ID this library
needs from you to authenticate that the token vas issued for your application.

You get a verified token parsed for you in return.

**You still must take care of:**

1. That the user has the right access to your system yourself
2. That the token hasn't expired
3. That the tokens `nbf` (Not Before) is valid
4. Any other information that is valid for your use case

For more information, see this artice: https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens