pub mod config;
mod fetch_keys;
mod get_max_age;
mod jwk_auth;
mod validator;
mod verifier;

pub use jwk_auth::JwkAuth;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
