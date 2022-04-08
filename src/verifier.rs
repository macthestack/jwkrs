use crate::config::JwkConfiguration;
use crate::validator::Validator;
use evmap::ReadHandleFactory;
use jsonwebtoken::decode;
use jsonwebtoken::decode_header;
use jsonwebtoken::TokenData;
use serde::Deserialize;

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

#[derive(Debug)]
pub enum VerificationError {
    NoKid,
    NoKeyPresent,
    InvalidSignature,
    KeyDecodingFailed,
}

#[derive(Debug)]
pub struct JwkVerifier<'a> {
    pub validators: &'a ReadHandleFactory<String, Validator>,
    pub config: &'a JwkConfiguration,
}

impl<'a> JwkVerifier<'a> {
    pub fn verify(&self, token: &String) -> Result<TokenData<Claims>, VerificationError> {
        let header = decode_header(token).map_err(|_| VerificationError::KeyDecodingFailed)?;

        let key_id = header.kid.ok_or(VerificationError::NoKid)?;

        let validator = self
            .get_validator(key_id)
            .ok_or(VerificationError::NoKeyPresent)?;

        self.decode_token_with_key(&validator, token)
    }

    fn get_validator(&self, key_id: String) -> Option<Validator> {
        let validators = self.validators.handle();
        let validator = validators.get_one(&key_id)?;
        Some(validator.clone())
    }
    fn decode_token_with_key(
        &self,
        validator: &Validator,
        token: &String,
    ) -> Result<TokenData<Claims>, VerificationError> {
        return decode::<Claims>(token, &validator.key, &validator.validation)
            .map_err(|_| VerificationError::InvalidSignature);
    }
}
