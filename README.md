# jwkrs

[jwkrs](https://hips.hearstapps.com/hmg-prod.s3.amazonaws.com/images/joker-1570104122.png?crop=1.00xw:1.00xh;0,0&resize=980:*)

Early prototype of a JWK authentication library.

## How to use:

```rust
#[tokio::main]
async fn main() {
    let config = JwkConfiguration {
        jwk_url: "{JWK_URL}".to_string(),
        audience: "{AUDIENCE}".to_string(),
        issuer: "{ISSUER}".to_string(),
    };
    let jwk = jwkrs::JwkAuth::new(config);

    ...
}
```

See examples for more ideas of how to use it.

## Thanks to:

This repo is inspired by Lukas May's great blog post https://medium.com/@maylukas/firebase-token-authentication-in-rust-a1885f0982df
