use core::fmt;

use crate::config::JwkConfiguration;
use crate::key::Key;
use evmap::ReadHandleFactory;
use jsonwebtoken::decode;
use jsonwebtoken::decode_header;
use jsonwebtoken::TokenData;
use serde::de;
use serde::de::Visitor;
use serde::Deserialize;
use serde::Deserializer;
use tracing::trace;

#[derive(Debug, Deserialize)]
pub struct Claims {
    pub aud: Audience,
    pub exp: i64,
    pub iss: String,
    pub sub: String,
    pub iat: i64,
}

#[derive(Debug)]
pub enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

impl<'de> Deserialize<'de> for Audience {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AudienceVisitor;

        impl<'de> Visitor<'de> for AudienceVisitor {
            type Value = Audience;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string or a list of strings")
            }

            fn visit_str<E>(self, value: &str) -> Result<Audience, E>
            where
                E: de::Error,
            {
                Ok(Audience::Single(value.to_owned()))
            }

            fn visit_seq<A>(self, seq: A) -> Result<Audience, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let values: Vec<String> =
                    Deserialize::deserialize(de::value::SeqAccessDeserializer::new(seq))?;
                Ok(Audience::Multiple(values))
            }
        }

        deserializer.deserialize_any(AudienceVisitor)
    }
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
    pub config: &'a JwkConfiguration,
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
