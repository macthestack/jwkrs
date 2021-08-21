use crate::fetch_keys::JwkKey;
use crate::jwk_auth::JwkConfiguration;
use jsonwebtoken::decode_header;
use jsonwebtoken::TokenData;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::collections::HashMap;
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
pub struct JwkVerifier {
    keys: Option<HashMap<String, JwkKey>>,
    config: JwkConfiguration,
}

fn keys_to_map(keys: Vec<JwkKey>) -> HashMap<String, JwkKey> {
    let mut keys_as_map = HashMap::new();
    for key in keys {
        keys_as_map.insert(String::clone(&key.kid), key);
    }
    keys_as_map
}

impl JwkVerifier {
    pub fn new(config: JwkConfiguration) -> JwkVerifier {
        JwkVerifier { keys: None, config }
    }

    pub fn verify(&self, token: &String) -> Option<TokenData<Claims>> {
        let token_kid = match decode_header(token).map(|header| header.kid) {
            Ok(Some(kid)) => kid,
            _ => return None,
        };

        let jwk_key = match self.get_key(token_kid) {
            Some(key) => key,
            _ => return None,
        };

        match self.decode_token_with_key(jwk_key, token) {
            Ok(token_data) => Some(token_data),
            _ => None,
        }
    }

    pub fn set_keys(&mut self, keys: Vec<JwkKey>) {
        self.keys = Some(keys_to_map(keys));
    }

    fn get_key(&self, key_id: String) -> Option<&JwkKey> {
        let k = self.keys.as_ref().expect("Keys not initialized.");
        k.get(&key_id)
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
