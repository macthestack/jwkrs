use std::str::FromStr;

use jsonwebtoken::{Algorithm, DecodingKey, Validation};

use crate::{config::JwkConfiguration, jwk_auth::JwkKey};

#[derive(Clone)]
pub(crate) struct Key {
    pub key_id: String,
    pub key: Box<DecodingKey>,
    pub validation: Box<Validation>,
}

impl Eq for Key {
    fn assert_receiver_is_total_eq(&self) {
        self.key_id.assert_receiver_is_total_eq();
    }
}

impl evmap::ShallowCopy for Key {
    unsafe fn shallow_copy(&self) -> std::mem::ManuallyDrop<Self> {
        std::mem::ManuallyDrop::new(Key {
            key_id: self.key_id.clone(),
            key: self.key.clone(),
            validation: self.validation.clone(),
        })
    }
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.key_id == other.key_id
    }
}

impl std::hash::Hash for Key {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.key_id.hash(state);
    }
}

impl Key {
    pub fn from_jwk_key(key: &JwkKey, config: &JwkConfiguration) -> Result<Key, ValidatorError> {
        let algorithm =
            Algorithm::from_str(&key.alg).map_err(|_| ValidatorError::InvalidAlgorithm)?;
        let mut validation = Validation::new(algorithm);
        validation.set_audience(&[&config.audience]);
        validation.iss = Some(config.issuers.clone());
        let decoding_key = DecodingKey::from_rsa_components(&key.n, &key.e)
            .map_err(|_| ValidatorError::KeyDecodingFailed)?;

        // let decoding_key = decoding_key;
        let validator = Key {
            key_id: key.kid.clone(),
            key: Box::new(decoding_key),
            validation: Box::new(validation),
        };

        Ok(validator)
    }
}
#[derive(Debug)]
pub enum ValidatorError {
    KeyDecodingFailed,
    InvalidAlgorithm,
}
