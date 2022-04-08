use crate::config::JwkConfiguration;
use crate::fetch_keys::get_keys;
use crate::key::Key;
use crate::verifier::{Claims, JwkVerifier};
use evmap::{ReadHandleFactory, WriteHandle};
use evmap_derive::ShallowCopy;
use jsonwebtoken::TokenData;
use serde::Deserialize;
use std::time::Duration;
use tokio::time::sleep;
use tracing::trace;

#[derive(Clone)]
pub struct JwkAuth {
    validators: ReadHandleFactory<String, Key>,
    config: JwkConfiguration,
}

#[derive(Clone, Default, Debug, Deserialize, Eq, PartialEq, Hash, ShallowCopy)]
pub struct JwkKey {
    pub e: String,
    pub alg: String,
    pub kty: String,
    pub kid: String,
    pub n: String,
}

impl JwkAuth {
    pub fn new(config: JwkConfiguration) -> JwkAuth {
        let (r, w) = evmap::new();

        let instance = JwkAuth {
            validators: r.factory(),
            config: config.clone(),
        };

        tokio::spawn(key_update(config, w));

        instance
    }

    pub async fn verify(self, token: &String) -> Option<TokenData<Claims>> {
        let verifier = JwkVerifier {
            validators: &self.validators,
            config: &self.config,
        };

        let verification_result = verifier.verify(token);

        match verification_result {
            Ok(token_data) => Some(token_data),
            Err(e) => {
                trace!("Token verification failed: {:?}", e);
                None
            }
        }
    }
}

async fn key_update(config: JwkConfiguration, mut w: WriteHandle<String, Key>) {
    loop {
        let keys = get_keys(&config).await;
        let duration = match keys {
            Ok((keys, duration)) => {
                w.purge();

                for key in keys {
                    let validator = Key::from_jwk_key(&key, &config);

                    match validator {
                        Ok(validator) => {
                            w.update(key.kid.clone(), validator);
                        }
                        Err(e) => {
                            trace!("Failed to create validator: {:?}", e);
                        }
                    }
                }
                w.refresh();
                duration
            }
            Err(_) => Duration::from_secs(10),
        };
        sleep(duration).await;
    }
}
