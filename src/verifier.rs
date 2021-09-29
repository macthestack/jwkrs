use crate::config::JwkConfiguration;
use crate::jwk_auth::JwkKey;
use evmap::ReadHandleFactory;
use jsonwebtoken::decode_header;
use jsonwebtoken::TokenData;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::str::FromStr;

#[derive(Debug, Deserialize)]
pub struct Claims {
    // The audience the token was issued for
    pub aud: String,
    // The expiry date -- as epoch seconds
    pub exp: i64,
    // The token issuer
    pub iss: String,
    // The subject the token refers to
    pub sub: String,
    // Issued at -- as epoch seconds
    pub iat: i64,
}

enum VerificationError {
    InvalidSignature,
    UnknownKeyAlgorithm,
}

#[derive(Debug)]
pub struct JwkVerifier<'a> {
    pub keys: &'a ReadHandleFactory<String, JwkKey>,
    pub config: &'a JwkConfiguration,
}

impl<'a> JwkVerifier<'a> {
    pub fn verify(&self, token: &String) -> Option<TokenData<Claims>> {
        let token_kid = decode_header(token).map(|header| header.kid).ok()??;

        let jwk_key = self.get_key(token_kid)?;

        self.decode_token_with_key(&jwk_key, token).ok()
    }

    fn get_key(&self, key_id: String) -> Option<JwkKey> {
        let r = self.keys.handle();
        let a = r.get_one(&key_id)?;
        Some(a.clone())
    }

    fn decode_token_with_key(
        &self,
        key: &JwkKey,
        token: &String,
    ) -> Result<TokenData<Claims>, VerificationError> {
        let algorithm = match Algorithm::from_str(&key.alg) {
            Ok(alg) => alg,
            Err(_error) => return Err(VerificationError::UnknownKeyAlgorithm),
        };

        let mut validation = Validation::new(algorithm);
        validation.set_audience(&[&self.config.audience]);
        validation.iss = Some(self.config.issuer.clone());
        let key = DecodingKey::from_rsa_components(&key.n, &key.e);
        return decode::<Claims>(token, &key, &validation)
            .map_err(|_| VerificationError::InvalidSignature);
    }
}
