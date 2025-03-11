use crate::key::Key;
use evmap::ReadHandleFactory;
use jsonwebtoken::decode;
use jsonwebtoken::decode_header;
use jsonwebtoken::TokenData;
use serde::Deserialize;
use serde::Serialize;
use tracing::trace;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub aud: Audience,
    pub exp: i64,
    pub iss: String,
    pub sub: String,
    pub iat: i64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Debug)]
pub enum VerificationError {
    NoKid,
    NoKeyPresent,
    InvalidSignature,
    KeyDecodingFailed,
}

#[derive(Debug)]
pub struct JwkVerifier<'a> {
    pub(crate) validators: &'a ReadHandleFactory<String, Key>,
}

impl<'a> JwkVerifier<'a> {
    pub fn verify(&self, token: &str) -> Result<TokenData<Claims>, VerificationError> {
        let header = decode_header(token).map_err(|_| VerificationError::KeyDecodingFailed)?;

        let key_id = header.kid.ok_or(VerificationError::NoKid)?;

        let validator = self
            .get_validator(key_id)
            .ok_or(VerificationError::NoKeyPresent)?;

        self.decode_token_with_key(&validator, token)
    }

    fn get_validator(&self, key_id: String) -> Option<Key> {
        let validators = self.validators.handle();
        let validator = validators.get_one(&key_id)?;
        Some(validator.clone())
    }
    fn decode_token_with_key(
        &self,
        validator: &Key,
        token: &str,
    ) -> Result<TokenData<Claims>, VerificationError> {
        return decode::<Claims>(token, &validator.key, &validator.validation).map_err(|e| {
            trace!("Failed to decode token: {:?}", e);
            VerificationError::InvalidSignature
        });
    }
}
